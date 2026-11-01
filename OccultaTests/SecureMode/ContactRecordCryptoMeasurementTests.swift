//
//  ContactRecordCryptoMeasurementTests.swift
//  OccultaTests
//
//  ⚠️  The second and third tests require a Secure Enclave.
//
//  Supports `Docs/v2.0.0/PASSPHRASE_ROLLOUT.md` §8, 23: what it costs to open 100 sealed contact records,
//  change a few fields in each and seal them again, as stage 4's one-record-per-contact design does.
//
//  Mock data only. Crypto and encoding only: no store is read or written. Two runs:
//    - under an in-memory key, so it runs anywhere;
//    - with the key derived the way stage 3 derives a space key: one Enclave ECDH against P, on iOS 26 one
//      Enclave ML-KEM decapsulation, and HKDF (`Manager.Key.deriveEnclaveBound`). The Enclave keys are transient
//      and leave no keychain item. PBKDF2 is left out: it is tuned to a target time (~1 s on an iPhone 11, spec
//      §4), so its cost is set, not measured. For comparison, it also times one Enclave ECDH per record, which
//      the design doesn't do.
//    - the same at 100, 1,000 and 5,000 records, with 1,000 noise rows (§8, 21's cap) tried and rejected first, as
//      unlock tries every row. Meant for a device: the Simulator's Enclave is the Mac's.
//
//  The mock record is sized from measured values: a P-256 identity and agreement key (65 bytes each), an
//  ML-KEM-1024 public key (1,568 bytes, `bugs.md` Bug 171), and 23 prekey blobs of 143 bytes, the 15/5 peak
//  (`Docs/Features/Prekey Continuity/DESIGN.md`). Records are padded to a multiple of 4 KB, since the sizes are
//  not decided yet.
//
//  Asserted: every record round-trips with its changes, every sealed record has the same size, and the Enclave
//  derivation gives the same key every time.
//  Measured and attached as `contact-record-measurement.txt`, `contact-record-enclave-measurement.txt` and
//  `contact-record-scale-<count>.txt`, not asserted, because the numbers belong to the hardware they ran on.
//
//  ⚠️  Never run this on a phone that holds real Occulta data. The suite is hosted in Occulta.app, so a device run
//  installs a Debug build over the real install. To read the numbers:
//
//    xcodebuild -project Occulta.xcodeproj -scheme OccultaTests \
//      -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
//      -only-testing:OccultaTests/ContactRecordCryptoMeasurementTests test
//    xcrun xcresulttool export attachments --path <the .xcresult it prints> --output-path <dir>
//

import Testing
import CryptoKit
import Foundation
import Security
import OccultaCore

@testable import Occulta

private func transientEnclaveKeyAvailable() -> Bool {
    ContactRecordCryptoMeasurementTests.transientEnclaveKey() != nil
}

// Serialized: run in parallel, the tests queue for the one Enclave and time each other.
@Suite("Contact record — open, change and seal sealed records", .serialized)
struct ContactRecordCryptoMeasurementTests {

    static let contactCount = 100
    static let passes = 20
    static let paddingStep = 4_096
    static let scalePasses = 5
    static let noiseRows = 1_000

    let clock = ContinuousClock()

    @Test("Open, change and seal 100 records, attached")
    func measureOpenChangeSeal() throws {
        var report = ["device: \(Self.deviceModel()), \(ProcessInfo.processInfo.operatingSystemVersionString)"]
        defer { Attachment.record(report.joined(separator: "\n"), named: "contact-record-measurement.txt") }

        let key = SymmetricKey(size: .bits256)
        var rows = try Self.makeRows(key: key)

        let sizes = Set(rows.map(\.sealed.count))
        #expect(sizes.count == 1, "every sealed record must have the same size")
        report.append("sealed record: \(sizes.sorted().map(String.init).joined(separator: ", ")) bytes; " +
                      "JSON before padding: \(try JSONEncoder().encode(MockContactRecord.make(0)).count) bytes")

        var open: [Duration] = []
        var change: [Duration] = []
        var seal: [Duration] = []
        var total: [Duration] = []

        for pass in 0..<Self.passes {
            let times = try self.runPass(pass, rows: &rows, key: key)
            open.append(times.open)
            change.append(times.change)
            seal.append(times.seal)
            total.append(times.open + times.change + times.seal)
        }
        try Self.expectLastPass(rows, key: key)

        report.append("\(Self.contactCount) records, \(Self.passes) passes; each figure is one pass over all of them")
        report.append("open (AES-GCM open + JSON decode): \(Self.stats(open))")
        report.append("change three fields: \(Self.stats(change))")
        report.append("seal (JSON encode + pad + AES-GCM seal): \(Self.stats(seal))")
        report.append("total: \(Self.stats(total))")
    }

    @Test("Derive the key in the Enclave, then open, change and seal 100 records, attached",
          .enabled(if: transientEnclaveKeyAvailable()))
    func measureWithEnclave() throws {
        var report = ["device: \(Self.deviceModel()), \(ProcessInfo.processInfo.operatingSystemVersionString)"]
        defer { Attachment.record(report.joined(separator: "\n"), named: "contact-record-enclave-measurement.txt") }

        let derivation = try Self.enclaveDerivation()
        let enclaveKey = derivation.enclaveKey
        let peer = derivation.peer
        let deriveKey = derivation.derive
        report.append("ML-KEM in the derivation: \(derivation.postQuantum ? "yes, Enclave ML-KEM-1024" : "no (below iOS 26)")")

        var rows = try Self.makeRows(key: try deriveKey())

        var derive: [Duration] = []
        var total: [Duration] = []
        for pass in 0..<Self.passes {
            var key = SymmetricKey(size: .bits256)
            let deriveTime = try self.clock.measure { key = try deriveKey() }
            let times = try self.runPass(pass, rows: &rows, key: key)
            derive.append(deriveTime)
            total.append(deriveTime + times.open + times.change + times.seal)
        }
        try Self.expectLastPass(rows, key: try deriveKey())

        var perRecord: [Duration] = []
        for _ in 0..<5 {
            perRecord.append(try self.clock.measure {
                for _ in 0..<Self.contactCount {
                    var error: Unmanaged<CFError>?
                    _ = try #require(SecKeyCopyKeyExchangeResult(
                        enclaveKey, .ecdhKeyExchangeCofactorX963SHA256, peer,
                        [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
                    ) as Data?)
                }
            })
        }

        report.append("\(Self.contactCount) records, \(Self.passes) passes; each figure is one pass over all of them")
        report.append("derive the key (Enclave ECDH + ML-KEM decapsulation + HKDF), once per pass: \(Self.stats(derive))")
        report.append("total (derive + open + change + seal): \(Self.stats(total))")
        report.append("for comparison, one Enclave ECDH per record (\(Self.contactCount) calls): \(Self.stats(perRecord))")
    }

    /// The same derivation and pass at the sizes a real space reaches, plus item 21's noise cap: unlock tries every
    /// row, and a noise row fails its tag check.
    @Test("Derive the key in the Enclave, then open, change and seal many records among noise rows, attached",
          .enabled(if: transientEnclaveKeyAvailable()),
          arguments: [100, 1_000, 5_000])
    func measureAtScale(contactCount: Int) throws {
        var report = ["device: \(Self.deviceModel()), \(ProcessInfo.processInfo.operatingSystemVersionString)"]
        defer { Attachment.record(report.joined(separator: "\n"), named: "contact-record-scale-\(contactCount).txt") }

        let derivation = try Self.enclaveDerivation()
        report.append("ML-KEM in the derivation: \(derivation.postQuantum ? "yes, Enclave ML-KEM-1024" : "no (below iOS 26)")")

        var rows = try Self.makeRows(key: try derivation.derive(), count: contactCount)
        let recordSize = try #require(rows.first?.sealed.count)
        let noise = (0..<Self.noiseRows).map { _ in (id: UUID(), sealed: Self.random(recordSize)) }

        var derive: [Duration] = []
        var trial: [Duration] = []
        var open: [Duration] = []
        var change: [Duration] = []
        var seal: [Duration] = []
        var total: [Duration] = []
        for pass in 0..<Self.scalePasses {
            var key = SymmetricKey(size: .bits256)
            let deriveTime = try self.clock.measure { key = try derivation.derive() }
            var rejected = 0
            let trialTime = self.clock.measure {
                for row in noise where (try? Self.open(row.sealed, rowID: row.id, key: key)) == nil {
                    rejected += 1
                }
            }
            #expect(rejected == Self.noiseRows, "no noise row may open")
            let times = try self.runPass(pass, rows: &rows, key: key)
            derive.append(deriveTime)
            trial.append(trialTime)
            open.append(times.open)
            change.append(times.change)
            seal.append(times.seal)
            total.append(deriveTime + trialTime + times.open + times.change + times.seal)
        }
        let finalKey = try derivation.derive()
        let final = try rows.map { try Self.open($0.sealed, rowID: $0.id, key: finalKey) }
        #expect(final.enumerated().allSatisfy { $1.note == "Pass \(Self.scalePasses - 1), contact \($0)" },
                "every record must keep the last pass's change")

        let perRecord = try self.clock.measure {
            for _ in 0..<contactCount {
                _ = try derivation.exchange()
            }
        }

        report.append("\(contactCount) records of \(recordSize) bytes and \(Self.noiseRows) noise rows, " +
                      "\(Self.scalePasses) passes; each figure is one pass")
        report.append("derive the key (Enclave ECDH + ML-KEM decapsulation + HKDF): \(Self.stats(derive))")
        report.append("try \(Self.noiseRows) noise rows (each fails AES-GCM): \(Self.stats(trial))")
        report.append("open (AES-GCM open + JSON decode): \(Self.stats(open))")
        report.append("change three fields: \(Self.stats(change))")
        report.append("seal (JSON encode + pad + AES-GCM seal): \(Self.stats(seal))")
        report.append("total: \(Self.stats(total))")
        report.append("for comparison, one Enclave ECDH per record (\(contactCount) calls, once): \(Self.stats([perRecord]))")
    }

    // MARK: - Pass

    private func runPass(_ pass: Int, rows: inout [(id: UUID, sealed: Data)], key: SymmetricKey) throws
        -> (open: Duration, change: Duration, seal: Duration) {
        var records: [MockContactRecord] = []
        let open = try self.clock.measure {
            records = try rows.map { try Self.open($0.sealed, rowID: $0.id, key: key) }
        }
        let change = self.clock.measure {
            for index in records.indices {
                records[index].note = "Pass \(pass), contact \(index)"
                records[index].phoneNumbers[0].value = "+1 555 \(1_000 + pass) \(1_000 + index)"
                records[index].prekeyBlobs[pass % records[index].prekeyBlobs.count] = Self.random(143)
            }
        }
        var resealed: [Data] = []
        let seal = try self.clock.measure {
            resealed = try zip(rows, records).map { row, record in try Self.seal(record, rowID: row.id, key: key) }
        }
        for index in rows.indices {
            rows[index].sealed = resealed[index]
        }
        return (open, change, seal)
    }

    private static func makeRows(key: SymmetricKey, count: Int = Self.contactCount) throws -> [(id: UUID, sealed: Data)] {
        try (0..<count).map { index in
            let id = UUID()
            return (id, try Self.seal(MockContactRecord.make(index), rowID: id, key: key))
        }
    }

    private static func expectLastPass(_ rows: [(id: UUID, sealed: Data)], key: SymmetricKey) throws {
        let final = try rows.map { try Self.open($0.sealed, rowID: $0.id, key: key) }
        #expect(final.enumerated().allSatisfy { $1.note == "Pass \(Self.passes - 1), contact \($0)" },
                "every record must keep the last pass's change")
    }

    // MARK: - Record

    private struct MockContactRecord: Codable, Equatable {
        struct Labeled: Codable, Equatable {
            var label: String
            var value: String
        }

        var givenName: String
        var familyName: String
        var organizationName: String
        var note: String
        var phoneNumbers: [Labeled]
        var emailAddresses: [Labeled]
        var postalAddress: String
        var identityKey: Data
        var agreementKey: Data
        var postQuantumKey: Data
        var prekeyBlobs: [Data]
        var photoRowIDs: [UUID]

        static func make(_ index: Int) -> MockContactRecord {
            MockContactRecord(
                givenName: "Given\(index)",
                familyName: "Family\(index)",
                organizationName: "Organization \(index)",
                note: String(repeating: "n", count: 200),
                phoneNumbers: [Labeled(label: "mobile", value: "+1 555 000 \(1_000 + index)"),
                               Labeled(label: "work", value: "+1 555 111 \(1_000 + index)")],
                emailAddresses: [Labeled(label: "home", value: "contact\(index)@example.com")],
                postalAddress: "\(index) Example Street, Springfield, 12345, US",
                identityKey: ContactRecordCryptoMeasurementTests.random(65),
                agreementKey: ContactRecordCryptoMeasurementTests.random(65),
                postQuantumKey: ContactRecordCryptoMeasurementTests.random(1_568),
                prekeyBlobs: (0..<23).map { _ in ContactRecordCryptoMeasurementTests.random(143) },
                photoRowIDs: [UUID()]
            )
        }
    }

    // MARK: - Sealing

    /// A 4-byte length, the JSON, then zeros up to the next padding step, sealed with the row's ID as AAD.
    private static func seal(_ record: MockContactRecord, rowID: UUID, key: SymmetricKey) throws -> Data {
        let json = try JSONEncoder().encode(record)
        var plaintext = withUnsafeBytes(of: UInt32(json.count).bigEndian) { Data($0) }
        plaintext.append(json)
        let padded = (plaintext.count + Self.paddingStep - 1) / Self.paddingStep * Self.paddingStep
        plaintext.append(Data(count: padded - plaintext.count))
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: Self.aad(rowID))
        return try #require(box.combined)
    }

    private static func open(_ sealed: Data, rowID: UUID, key: SymmetricKey) throws -> MockContactRecord {
        let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key,
                                         authenticating: Self.aad(rowID))
        let length = plaintext.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        return try JSONDecoder().decode(MockContactRecord.self, from: plaintext.dropFirst(4).prefix(length))
    }

    private static func aad(_ rowID: UUID) -> Data {
        withUnsafeBytes(of: rowID.uuid) { Data($0) }
    }

    // MARK: - Enclave

    private struct EnclaveDerivation {
        let enclaveKey: SecKey
        let peer: SecKey
        let postQuantum: Bool
        let exchange: () throws -> Data
        let derive: () throws -> SymmetricKey
    }

    /// A transient Enclave key, and the space-key derivation over it: one ECDH against P, on iOS 26 one ML-KEM
    /// decapsulation of an Enclave key kept as a blob, and HKDF with a tier secret.
    private static func enclaveDerivation() throws -> EnclaveDerivation {
        let enclaveKey = try #require(Self.transientEnclaveKey())
        let peer = try #require(Self.publicKey(x963: ShareStagingKeyManager.numsX963))
        let salt = try #require(SecKeyCopyPublicKey(enclaveKey).flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? })
        let tierSecret = Self.random(32)

        // On iOS 26 the tier record is hybrid: an Enclave ML-KEM key kept as a blob and a ciphertext to it.
        let provider = PostQuantumProviderFactory.create()
        var postQuantum: (keyBlob: Data, ciphertext: Data)?
        if let provider {
            let pair = try #require(provider.generatePersistentKeyPair())
            let encapsulated = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))
            postQuantum = (pair.keyBlob, encapsulated.ciphertext)
        }

        func exchange() throws -> Data {
            var error: Unmanaged<CFError>?
            return try #require(SecKeyCopyKeyExchangeResult(
                enclaveKey, .ecdhKeyExchangeCofactorX963SHA256, peer,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
            ) as Data?)
        }

        func derive() throws -> SymmetricKey {
            var ikm = try exchange()
            var info = Data("Occulta-measurement-space-key".utf8)
            if let provider, let postQuantum {
                ikm.append(try #require(provider.decapsulate(ciphertext: postQuantum.ciphertext, keyBlob: postQuantum.keyBlob)))
                info.append(Data(SHA256.hash(data: postQuantum.ciphertext)))
            }
            ikm.append(tierSecret)
            return HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info,
                                          outputByteCount: 32)
        }

        return EnclaveDerivation(enclaveKey: enclaveKey, peer: peer, postQuantum: postQuantum != nil,
                                 exchange: exchange, derive: derive)
    }

    /// A P-256 Enclave key with the access control production gives its keys, not stored in the keychain.
    static func transientEnclaveKey() -> SecKey? {
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil
        ) else { return nil }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access
            ] as [String: Any]
        ]
        return SecKeyCreateRandomKey(attributes as CFDictionary, nil)
    }

    private static func publicKey(x963: Data) -> SecKey? {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        return SecKeyCreateWithData(x963 as CFData, attrs as CFDictionary, nil)
    }

    // MARK: - Helpers

    private static func random(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }

    private static func deviceModel() -> String {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] {
            return "\(simulated) (Simulator)"
        }
        var system = utsname()
        uname(&system)
        return withUnsafeBytes(of: system.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    private static func milliseconds(_ duration: Duration) -> Double {
        let (seconds, attoseconds) = duration.components
        return Double(seconds) * 1_000 + Double(attoseconds) / 1e15
    }

    private static func stats(_ durations: [Duration]) -> String {
        let sorted = durations.map(Self.milliseconds).sorted()
        let median = sorted[sorted.count / 2]
        let p90    = sorted[Int(Double(sorted.count - 1) * 0.9)]
        return String(format: "median %.2f ms, p90 %.2f ms, max %.2f ms (n = %d)",
                      median, p90, sorted.last!, sorted.count)
    }
}
