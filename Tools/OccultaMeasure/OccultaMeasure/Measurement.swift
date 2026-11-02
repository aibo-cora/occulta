//
//  Measurement.swift
//  OccultaMeasure
//
//  The run: PBKDF2, the space-key derivation, then a plain SQLite store at three sizes. Every figure is the median
//  of several passes. Mock data and transient keys only; every file made lives in one temporary directory that is
//  removed when the run ends. Never touches Occulta's container or keychain, which iOS keeps apart.
//
//  Numbers feed `Docs/v2.0.0/PASSPHRASE_ROLLOUT.md` §1.5 and §8 (items 6, 21, 22, 26, 27); see README.md.
//

import CryptoKit
import Foundation
import SQLite3

enum Measurement {
    static let directoryPrefix = "OccultaMeasure-"
    static let contactCounts = [100, 1_000, 5_000]
    static let noiseRows = 1_000
    static let contactPasses = 5

    /// Runs everything and returns the report. Blocks; call it off the main thread.
    static func run(progress: (String) -> Void) -> String {
        Self.removeStaleDirectories()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(Self.directoryPrefix + UUID().uuidString)

        var lines = Self.header()
        func section(_ title: String, _ body: () throws -> [String]) {
            lines.append("")
            lines.append("== \(title) ==")
            do {
                lines += try body()
            } catch {
                lines.append("FAILED: \(error)")
            }
        }
        section("PBKDF2-HMAC-SHA256 (CommonCrypto)") { try Self.pbkdf2(progress: progress) }
        section("Space-key derivation") { try Self.derivation(progress: progress) }
        section("SQLite") { try Self.sqlite(in: directory, progress: progress) }

        try? FileManager.default.removeItem(at: directory)
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path))?
            .filter { $0.hasPrefix(Self.directoryPrefix) } ?? []
        lines.append("")
        lines.append("== Clean-up ==")
        lines.append(leftovers.isEmpty ? "every file made was removed; keys were transient and never stored"
                                       : "LEFT BEHIND: \(leftovers.joined(separator: ", "))")
        return lines.joined(separator: "\n")
    }

    // MARK: - Header

    private static func header() -> [String] {
        #if DEBUG
        let build = "DEBUG - these numbers are not valid, build Release"
        #else
        let build = "Release"
        #endif
        let thermal: String
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: thermal = "nominal"
        case .fair: thermal = "fair"
        case .serious: thermal = "serious"
        case .critical: thermal = "critical"
        @unknown default: thermal = "unknown"
        }
        return [
            "Occulta Measure \(Date.now.formatted(.iso8601))",
            "device: \(Self.deviceModel()), \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "build: \(build)",
            "thermal state: \(thermal); low power mode: \(ProcessInfo.processInfo.isLowPowerModeEnabled ? "ON, numbers are not valid" : "off")"
        ]
    }

    private static func deviceModel() -> String {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] {
            return "\(simulated) (Simulator, the Mac's CPU and Enclave)"
        }
        var system = utsname()
        uname(&system)
        return withUnsafeBytes(of: system.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }

    // MARK: - PBKDF2

    private static let fixedCounts: [UInt32] = [100_000, 300_000, 600_000, 1_000_000, 2_000_000]

    private static func pbkdf2(progress: (String) -> Void) throws -> [String] {
        let password = PBKDF2.randomPassword()
        let salt = [UInt8](Random.bytes(PBKDF2.saltSize))

        func samples(_ iterations: UInt32, passes: Int) throws -> Samples {
            var samples = Samples()
            for _ in 0..<passes {
                samples.add(try timed { _ = try PBKDF2.derive(password: password, salt: salt, iterations: iterations) })
            }
            return samples
        }
        func rounded(_ iterations: Double) -> UInt32 {
            UInt32(max(10_000, (iterations / 10_000).rounded() * 10_000))
        }

        progress("PBKDF2: calibrating")
        _ = try samples(100_000, passes: 1)
        let probe = try samples(100_000, passes: 3)
        var iterations = rounded(1_000 / probe.median * 100_000)
        var target = try samples(iterations, passes: 5)
        if abs(target.median - 1_000) > 100 {
            iterations = rounded(Double(iterations) * 1_000 / target.median)
            target = try samples(iterations, passes: 5)
        }

        var lines = [
            "\(PBKDF2.wordCount) word indices, \(PBKDF2.saltSize)-byte salt, \(PBKDF2.outputSize)-byte output; 5 passes each",
            "about 1 s: \(iterations) iterations, \(target.summary)",
            "CCCalibratePBKDF for 1000 ms, for comparison: \(PBKDF2.systemCalibration(milliseconds: 1_000)) iterations"
        ]
        for count in Self.fixedCounts {
            progress("PBKDF2: \(count) iterations")
            lines.append("\(count) iterations: \(try samples(count, passes: 5).summary)")
        }
        return lines
    }

    // MARK: - Space key

    private static func derivation(progress: (String) -> Void) throws -> [String] {
        progress("Space key: creating transient Enclave keys")
        let derivation = try SpaceKeyDerivation()
        let output = try PBKDF2.derive(password: PBKDF2.randomPassword(), salt: [UInt8](Random.bytes(PBKDF2.saltSize)),
                                       iterations: 100_000)
        let peer = try derivation.point(from: output)

        var total = Samples(), point = Samples(), exchange = Samples(), decapsulation = Samples()
        var key = try derivation.derive(from: output)
        let same = try (0..<5).allSatisfy { _ in
            try derivation.derive(from: output).withUnsafeBytes { first in key.withUnsafeBytes { first.elementsEqual($0) } }
        }
        progress("Space key: 20 passes")
        for _ in 0..<20 {
            total.add(try timed { key = try derivation.derive(from: output) })
            point.add(try timed { _ = try derivation.point(from: output) })
            exchange.add(try timed { _ = try derivation.exchange(with: peer) })
            if derivation.postQuantum {
                decapsulation.add(try timed { _ = try derivation.decapsulation() })
            }
        }

        var lines = [
            "transient Enclave P-256 ECDH against a point derived from the PBKDF2 output, HKDF; 20 passes",
            "ML-KEM in the derivation: \(derivation.postQuantum ? "yes, transient Enclave ML-KEM-1024 decapsulation" : "no (below iOS 26)")",
            "the same key every time: \(same ? "yes" : "NO")",
            "derive the key (point + ECDH\(derivation.postQuantum ? " + ML-KEM" : "") + HKDF): \(total.summary)",
            String(format: "first call, before the Enclave is warm: %.2f ms", total.first),
            "  derive the point (scalar multiplication + key import): \(point.summary)",
            "  Enclave ECDH: \(exchange.summary)"
        ]
        if derivation.postQuantum {
            lines.append("  Enclave ML-KEM-1024 decapsulation: \(decapsulation.summary)")
        }
        return lines
    }

    // MARK: - SQLite

    private static func sqlite(in directory: URL, progress: (String) -> Void) throws -> [String] {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let key = SymmetricKey(size: .bits256)

        var lines = [
            "SQLite \(String(cString: sqlite3_libversion())); compile options naming WAL or SECURE_DELETE: "
                + Self.compileOptions().joined(separator: ", ")
        ]
        let fresh = try SQLiteStore(path: directory.appendingPathComponent("defaults.sqlite").path)
        lines.append("defaults before any PRAGMA: journal_mode = \(try fresh.scalar("PRAGMA journal_mode")), "
                     + "secure_delete = \(try fresh.scalar("PRAGMA secure_delete")), "
                     + "wal persists after the last close = \(try fresh.persistsWAL())")
        try fresh.close()
        lines.append("every store below: PRAGMA secure_delete=ON, journal_mode=WAL")

        for count in Self.contactCounts {
            progress("SQLite: \(count) contacts and \(Self.noiseRows) noise rows")
            lines.append("")
            lines += try Self.contactStore(count: count, key: key, directory: directory)
        }

        progress("SQLite: photos")
        lines.append("")
        lines += try Self.photoStore(key: key, directory: directory)

        progress("SQLite: vault")
        lines.append("")
        lines += try Self.vaultStore(key: key, directory: directory)

        progress("SQLite: the -wal after closing")
        lines.append("")
        lines += try Self.walAfterClose(directory: directory)
        return lines
    }

    private static func compileOptions() -> [String] {
        var options: [String] = []
        var index: Int32 = 0
        while let option = sqlite3_compileoption_get(index) {
            let name = String(cString: option)
            if name.contains("WAL") || name.contains("SECURE_DELETE") {
                options.append(name)
            }
            index += 1
        }
        return options.isEmpty ? ["none"] : options
    }

    private static func configuredStore(_ name: String, in directory: URL) throws -> SQLiteStore {
        let store = try SQLiteStore(path: directory.appendingPathComponent(name).path)
        guard try store.scalar("PRAGMA journal_mode=WAL") == "wal" else { throw MeasureError("journal_mode=WAL did not take") }
        try store.execute("PRAGMA secure_delete=ON")
        guard try store.scalar("PRAGMA secure_delete") == "1" else { throw MeasureError("secure_delete=ON did not take") }
        return store
    }

    private static func contactStore(count: Int, key: SymmetricKey, directory: URL) throws -> [String] {
        let store = try Self.configuredStore("contacts-\(count).sqlite", in: directory)
        try store.createTable("contacts")
        let real = try Sealing.contactRows(count: count, key: key)
        let sealedSize = real[0].sealed.count
        try store.insert(real + Sealing.noiseRows(count: Self.noiseRows, sealedSize: sealedSize), into: "contacts")
        try store.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        var read = Samples(), trial = Samples(), decode = Samples(), total = Samples()
        for _ in 0..<Self.contactPasses {
            var rows: [Row] = []
            var plaintexts: [Data] = []
            var records = 0

            let readTime = try timed { rows = try store.readAll(from: "contacts") }
            let trialTime = timed {
                for row in rows {
                    if let plaintext = try? Sealing.open(row.sealed, id: row.id, key: key) {
                        plaintexts.append(plaintext)
                    }
                }
            }
            let decodeTime = try timed { records = try plaintexts.map(Sealing.decode).count }

            guard rows.count == count + Self.noiseRows, plaintexts.count == count, records == count else {
                throw MeasureError("read \(rows.count) rows, \(plaintexts.count) opened, \(records) decoded; "
                                   + "expected \(count + Self.noiseRows), \(count), \(count)")
            }
            read.add(readTime)
            trial.add(trialTime)
            decode.add(decodeTime)
            total.add(readTime + trialTime + decodeTime)
        }
        let size = (try? FileManager.default.attributesOfItem(atPath: store.path)[.size] as? Int) ?? 0
        try store.close()

        return [
            "\(count) contacts of \(sealedSize) bytes + \(Self.noiseRows) noise rows; file \(size / 1_024) KB; \(Self.contactPasses) passes",
            "  read every row: \(read.summary)",
            "  trial-decrypt every row (noise fails its tag): \(trial.summary)",
            "  decode the \(count) real ones: \(decode.summary)",
            "  read + trial + decode: \(total.summary)",
            String(format: "  first pass, closest to a cold start: %.2f ms", total.first)
        ]
    }

    private static func photoStore(key: SymmetricKey, directory: URL) throws -> [String] {
        let photos = 100
        let store = try Self.configuredStore("photos.sqlite", in: directory)
        try store.createTable("photos")
        let rows = try Sealing.opaqueRows(count: photos, plaintextSize: RowSize.photo, key: key)
        try store.insert(rows, into: "photos")
        try store.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        var fetch = Samples(), fetchAndOpen = Samples()
        for _ in 0..<50 {
            let row = rows.randomElement()!
            var sealed = Data()
            fetch.add(try timed { sealed = try store.fetch(id: row.id, from: "photos") })
            guard sealed == row.sealed else { throw MeasureError("fetched a different photo") }
            fetchAndOpen.add(try timed {
                let sealed = try store.fetch(id: row.id, from: "photos")
                _ = try Sealing.open(sealed, id: row.id, key: key)
            })
        }
        try store.close()

        return [
            "photos: \(photos) rows of \(rows[0].sealed.count) bytes, no noise; 50 fetches of one row by ID",
            "  fetch: \(fetch.summary)",
            "  fetch + decrypt: \(fetchAndOpen.summary)"
        ]
    }

    private static func vaultStore(key: SymmetricKey, directory: URL) throws -> [String] {
        let entries = 20
        let noise = 200
        let store = try Self.configuredStore("vault.sqlite", in: directory)
        try store.createTable("vault")
        let real = try Sealing.opaqueRows(count: entries, plaintextSize: RowSize.vault, key: key)
        try store.insert(real + Sealing.noiseRows(count: noise, sealedSize: real[0].sealed.count), into: "vault")
        try store.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        var read = Samples(), trial = Samples(), total = Samples()
        for _ in 0..<Self.contactPasses {
            var rows: [Row] = []
            var opened = 0
            let readTime = try timed { rows = try store.readAll(from: "vault") }
            let trialTime = timed { opened = rows.filter { (try? Sealing.open($0.sealed, id: $0.id, key: key)) != nil }.count }
            guard rows.count == entries + noise, opened == entries else {
                throw MeasureError("read \(rows.count) vault rows, \(opened) opened")
            }
            read.add(readTime)
            trial.add(trialTime)
            total.add(readTime + trialTime)
        }
        try store.close()

        return [
            "vault: \(entries) entries of \(real[0].sealed.count) bytes + \(noise) noise rows; \(Self.contactPasses) passes",
            "  read every row: \(read.summary)",
            "  trial-decrypt every row: \(trial.summary)",
            "  read + trial: \(total.summary)"
        ]
    }

    /// Decision 26 expects the `-wal` gone once the last connection closes. Apple's build may keep it.
    private static func walAfterClose(directory: URL) throws -> [String] {
        func size(_ path: String) -> Int? {
            (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? nil
        }

        var lines = ["after the last connection closes (10 rows written, WAL mode, nothing else open):"]
        for (name, checkpoint) in [("no checkpoint", false), ("PRAGMA wal_checkpoint(TRUNCATE)", true)] {
            let store = try Self.configuredStore("wal-\(checkpoint).sqlite", in: directory)
            try store.createTable("t")
            try store.insert(Sealing.noiseRows(count: 10, sealedSize: 8_220), into: "t")
            if checkpoint {
                try store.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            }
            let path = store.path
            let before = size(path + "-wal")
            try store.close()

            let wal = size(path + "-wal").map { "STILL THERE, \($0) bytes" } ?? "gone"
            let shm = size(path + "-shm").map { "still there, \($0) bytes" } ?? "gone"
            lines.append("  \(name): -wal was \(before.map { "\($0) bytes" } ?? "absent") while open, after close \(wal); -shm \(shm)")
        }
        return lines
    }

    private static func removeStaleDirectories() {
        let temporary = FileManager.default.temporaryDirectory
        let names = (try? FileManager.default.contentsOfDirectory(atPath: temporary.path)) ?? []
        for name in names where name.hasPrefix(Self.directoryPrefix) {
            try? FileManager.default.removeItem(at: temporary.appendingPathComponent(name))
        }
    }
}
