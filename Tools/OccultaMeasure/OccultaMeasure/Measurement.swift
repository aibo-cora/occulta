//
//  Measurement.swift
//  OccultaMeasure
//
//  The run: PBKDF2, the space-key derivation, then a plain SQLite store at three row sizes and three contact counts,
//  the way `Docs/v2.0.0/PASSPHRASE_ROLLOUT.md` §1.5 decided it on 2026-11-24. Every figure is the median of several
//  passes. Mock data and transient keys only; every file made lives in one temporary directory that is
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
    /// The row size is decided later, bottom-up from the field limits (§8 item 29), and estimated at 48-64 KB.
    static let rowSizes = [32 * 1_024, 48 * 1_024, 64 * 1_024]
    /// Decided 2026-11-24 (§1.5, "Fallback"): everything after PBKDF2 within this many milliseconds, by contact count.
    static let unlockLimits: [Int: Double] = [1_000: 500, 5_000: 2_000]

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
        let estimate = rounded(1_000 / probe.median * 100_000)

        // The smallest multiple of 10,000 whose median is at least 1 s: from the estimate, up while it falls short,
        // then down while the next one below still reaches it. Each count is measured once.
        var measured: [UInt32: Samples] = [:]
        func reaches(_ iterations: UInt32) throws -> Bool {
            if measured[iterations] == nil {
                progress("PBKDF2: searching, \(iterations) iterations")
                measured[iterations] = try samples(iterations, passes: 5)
            }
            return measured[iterations]!.median >= 1_000
        }
        let steps = 40
        var found = estimate
        var searched = 0
        while try !reaches(found), searched < steps {
            found += 10_000
            searched += 1
        }
        while found > 10_000, try reaches(found - 10_000), searched < steps {
            found -= 10_000
            searched += 1
        }

        var lines = [
            "\(PBKDF2.wordCount) word indices, \(PBKDF2.saltSize)-byte salt, \(PBKDF2.outputSize)-byte output; 5 passes each",
            searched < steps
                ? "smallest multiple of 10,000 iterations whose median is at least 1 s: \(found)"
                : "SEARCH STOPPED after \(steps) steps, the result is not the smallest: \(found)",
            "  at \(found): \(measured[found]!.summary)"
        ]
        if let below = measured[found - 10_000] {
            lines.append("  at \(found - 10_000), the next one below: \(below.summary)")
        }
        lines.append(String(format: "  10,000 iterations take about %.1f ms, so one step is %.1f%% of a second; a median of 5 moves by a few"
                            + " percent between runs, so the result is good to a few steps",
                            measured[found]!.median / Double(found) * 10_000, measured[found]!.median / Double(found) * 10_000 / 10))
        lines.append("CCCalibratePBKDF for 1000 ms, for comparison: \(PBKDF2.systemCalibration(milliseconds: 1_000)) iterations")
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

        let derivation = try SpaceKeyDerivation()
        let peer = try derivation.point(from: try PBKDF2.derive(password: PBKDF2.randomPassword(),
                                                                salt: [UInt8](Random.bytes(PBKDF2.saltSize)), iterations: 10_000))
        var results: [UnlockResult] = []
        lines.append("contact table: one table of one row size; per contact one contact row and one photo row of "
                     + "\(RowSize.photo / 1_024) KB, plus \(Self.noiseRows) noise rows. Unlock streams the table: "
                     + "read a row, trial-decrypt it, read its type, decode a contact, drop a photo's plaintext")
        lines.append("the mock contact is \(try Sealing.contactPayloadSize()) bytes of JSON in every row size; decode parses "
                     + "that, not the padding, so a fuller record would decode slower")
        for rowSize in Self.rowSizes {
            for count in Self.contactCounts {
                progress("SQLite: \(rowSize / 1_024) KB rows, \(count) contacts")
                lines.append("")
                let result = try Self.contactStore(count: count, rowSize: rowSize, key: key, directory: directory,
                                                   derivation: derivation, peer: peer)
                lines += result.lines
                results.append(result)
            }
        }

        lines.append("")
        lines += Self.verdict(results)

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

    private struct UnlockResult {
        let rowSize: Int
        let count: Int
        let total: Samples
        let read: Samples
        let trial: Samples
        let decode: Samples
        var lines: [String]
    }

    /// One unlock after PBKDF2, streamed: everything is timed per phase, and the total is the sum of the phases.
    private struct UnlockPass {
        var enclave = 0.0, read = 0.0, trial = 0.0, decode = 0.0
        var rows = 0, opened = 0, contacts = 0, photos = 0

        var total: Double { self.enclave + self.read + self.trial + self.decode }
    }

    private static func milliseconds(_ duration: Duration) -> Double {
        Double(duration.components.seconds) * 1_000 + Double(duration.components.attoseconds) / 1e15
    }

    private static func unlockPass(store: SQLiteStore, table: String, key: SymmetricKey,
                                   derivation: SpaceKeyDerivation, peer: SecKey) throws -> UnlockPass {
        var pass = UnlockPass()
        pass.enclave = try timed { _ = try derivation.derive(point: peer) }

        let clock = ContinuousClock()
        var read = Duration.zero, trial = Duration.zero, decode = Duration.zero
        let cursor = try store.cursor(over: table)
        while true {
            let start = clock.now
            guard let row = cursor.next() else { break }
            let afterRead = clock.now
            let plaintext = try? Sealing.open(row.sealed, id: row.id, key: key)
            let afterTrial = clock.now
            if let plaintext {
                pass.opened += 1
                switch Sealing.kind(of: plaintext) {
                case .contact:
                    _ = try Sealing.decodeContact(plaintext)
                    pass.contacts += 1
                case .photo:
                    pass.photos += 1
                case nil:
                    throw MeasureError("a row opened with an unknown type")
                }
            }
            // The plaintext goes out of scope here, a photo's with nothing else done to it.
            let end = clock.now
            pass.rows += 1
            read += afterRead - start
            trial += afterTrial - afterRead
            decode += end - afterTrial
        }
        pass.read = Self.milliseconds(read)
        pass.trial = Self.milliseconds(trial)
        pass.decode = Self.milliseconds(decode)
        return pass
    }

    private static func contactStore(count: Int, rowSize: Int, key: SymmetricKey, directory: URL,
                                     derivation: SpaceKeyDerivation, peer: SecKey) throws -> UnlockResult {
        let name = "contacts-\(rowSize)-\(count).sqlite"
        let store = try Self.configuredStore(name, in: directory)
        try store.createTable("contacts")

        // Written in chunks: the table is 0.1 to 0.7 GB, which is not built in memory.
        var photoIDs: [Data] = []
        for start in stride(from: 0, to: count, by: 100) {
            var chunk: [Row] = []
            for index in start..<min(start + 100, count) {
                let rows = try Sealing.contactAndPhotoRows(index: index, rowSize: rowSize, key: key)
                chunk += [rows.contact, rows.photo]
                if photoIDs.count < 30 {
                    photoIDs.append(rows.photo.id)
                }
            }
            try store.insert(chunk, into: "contacts")
        }
        let sealedSize = rowSize + Sealing.overhead
        for start in stride(from: 0, to: Self.noiseRows, by: 100) {
            try store.insert(Sealing.noiseRows(count: min(100, Self.noiseRows - start), sealedSize: sealedSize), into: "contacts")
        }
        try store.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        var enclave = Samples(), read = Samples(), trial = Samples(), decode = Samples(), total = Samples()
        for _ in 0..<Self.contactPasses {
            let pass = try Self.unlockPass(store: store, table: "contacts", key: key, derivation: derivation, peer: peer)
            guard pass.rows == 2 * count + Self.noiseRows, pass.opened == 2 * count,
                  pass.contacts == count, pass.photos == count
            else {
                throw MeasureError("read \(pass.rows) rows, \(pass.opened) opened, \(pass.contacts) contacts and "
                                   + "\(pass.photos) photos; expected \(2 * count + Self.noiseRows), \(2 * count), \(count), \(count)")
            }
            enclave.add(pass.enclave)
            read.add(pass.read)
            trial.add(pass.trial)
            decode.add(pass.decode)
            total.add(pass.total)
        }

        var fetch = Samples(), fetchAndOpen = Samples()
        for id in photoIDs {
            fetch.add(try timed { _ = try store.fetch(id: id, from: "contacts") })
            fetchAndOpen.add(try timed {
                _ = try Sealing.open(try store.fetch(id: id, from: "contacts"), id: id, key: key)
            })
        }

        let size = (try? FileManager.default.attributesOfItem(atPath: store.path)[.size] as? Int) ?? 0
        try store.close()
        for suffix in ["", "-wal", "-shm"] {
            try? FileManager.default.removeItem(atPath: directory.appendingPathComponent(name).path + suffix)
        }

        var lines = [
            "\(rowSize / 1_024) KB rows, \(count) contacts: \(count) contact rows + \(count) photo rows + \(Self.noiseRows) noise "
                + "rows = \(2 * count + Self.noiseRows) rows of \(sealedSize) bytes; file \(size / 1_048_576) MB; \(Self.contactPasses) passes",
            "  Enclave derivation, fixed point: \(enclave.summary)",
            "  read every row: \(read.summary)",
            "  trial-decrypt every row (noise fails its tag): \(trial.summary)",
            "  read the type, decode the \(count) contacts, drop the \(count) photos: \(decode.summary)"
        ]
        let after = "  everything after PBKDF2 (Enclave + read + trial + decode): \(total.summary)"
        if let limit = Self.unlockLimits[count] {
            lines.append(after + String(format: "; limit %.0f ms: %@", limit, total.median <= limit ? "WITHIN" : "OVER"))
        } else {
            lines.append(after + "; no limit decided at this count")
        }
        lines.append(String(format: "  first pass, closest to a cold start: %.2f ms", total.first))
        lines.append("  where the time goes: " + Self.split(read: read.median, trial: trial.median, decode: decode.median))
        lines.append("  one photo row by ID, \(photoIDs.count) fetches: fetch \(fetch.summary); fetch + decrypt \(fetchAndOpen.summary)")
        return UnlockResult(rowSize: rowSize, count: count, total: total, read: read, trial: trial, decode: decode, lines: lines)
    }

    private enum Phase: String {
        case read = "reading", trial = "decrypting", decode = "decoding"
    }

    private static func largest(read: Double, trial: Double, decode: Double) -> Phase {
        if read >= trial && read >= decode { return .read }
        return trial >= decode ? .trial : .decode
    }

    /// The share of read + trial-decrypt + decode each phase takes, and which is the largest; "mostly" only above half.
    private static func split(read: Double, trial: Double, decode: Double) -> String {
        let sum = read + trial + decode
        let phase = Self.largest(read: read, trial: trial, decode: decode)
        let largest = [Phase.read: read, .trial: trial, .decode: decode][phase]!
        return String(format: "read %.0f%%, trial-decrypt %.0f%%, decode %.0f%% -> %@ %@",
                      read / sum * 100, trial / sum * 100, decode / sum * 100,
                      largest > sum / 2 ? "mostly" : "largest share:", phase.rawValue)
    }

    /// Every store against the decided limit, one line each, and what the split says to do next.
    private static func verdict(_ results: [UnlockResult]) -> [String] {
        var lines = [
            "== Unlock after PBKDF2, against the limit decided 2026-11-24 ==",
            "limit: at most 500 ms at 1,000 contacts and 2,000 ms at 5,000 (§1.5); the figure is the median of "
                + "Enclave derivation + read + trial-decrypt + decode",
            "this machine, not an iPhone 11, unless the header says so"
        ]
        for result in results {
            let limit = Self.unlockLimits[result.count]
            let mark = limit.map { result.total.median <= $0 ? "WITHIN \(Int($0)) ms" : "OVER \(Int($0)) ms" } ?? "no limit at this count"
            lines.append(String(format: "  %2d KB rows, %5d contacts: %8.1f ms  %@  (%@)", result.rowSize / 1_024, result.count,
                                result.total.median, mark,
                                Self.split(read: result.read.median, trial: result.trial.median, decode: result.decode.median)))
        }

        let limited = results.filter { Self.unlockLimits[$0.count] != nil }
        var counts: [Phase: Int] = [:]
        for result in limited {
            counts[Self.largest(read: result.read.median, trial: result.trial.median, decode: result.decode.median), default: 0] += 1
        }
        lines.append("largest phase at the \(limited.count) rows with a limit: reading in \(counts[.read, default: 0]), "
                     + "decrypting in \(counts[.trial, default: 0]), decoding in \(counts[.decode, default: 0])")
        lines.append("what that decides: decoding is what lazy decoding removes. A locator tag cuts reading and decrypting "
                     + "only by the rows that aren't this space's: the \(Self.noiseRows) noise rows, and other spaces' rows")
        return lines
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
