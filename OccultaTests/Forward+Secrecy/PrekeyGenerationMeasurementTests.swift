//
//  PrekeyGenerationMeasurementTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave.
//
//  Supports `Docs/Features/Prekey Continuity/DESIGN.md` decisions D4 (batch size) and D9 (prekeys as
//  Enclave blobs in the sealed record, software keys as a fallback only with the owner's sign-off).
//
//  Asserted:
//    - creating a CryptoKit Enclave key leaves no keychain item behind (D9's premise that the record
//      holds the only copy), checked against a positive control so a "not found" means something.
//
//  Measured and attached as `prekey-measurement.txt`, not asserted, because the numbers belong to the
//  hardware they ran on:
//    - batch generation: today's keychain path, CryptoKit Enclave keys, software keys;
//    - opening one message: today's keychain lookup + ECDH, against rebuilding from a blob + ECDH;
//    - the size of an Enclave key's `dataRepresentation`, which sizes the record field.
//
//  D4 is decided at 15/5 without device numbers. An iPhone 11 run is needed only to revisit 50/15.
//
//  ⚠️  Never run this on a phone that holds real Occulta data. The suite is hosted in Occulta.app, so a
//  device run installs a Debug build over the real install and launches it against the real data. Use a
//  phone with nothing on it you need. To read the numbers:
//
//    xcodebuild -project Occulta.xcodeproj -scheme OccultaTests \
//      -destination 'platform=iOS,name=<device name>' \
//      -only-testing:OccultaTests/PrekeyGenerationMeasurementTests test
//    xcrun xcresulttool export attachments --path <the .xcresult it prints> --output-path <dir>
//

import Testing
import CryptoKit
import Foundation
import Security

@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@Suite("Prekey generation — Enclave blob measurement (D4, D9)")
@MainActor struct PrekeyGenerationMeasurementTests {

    let pm    = Manager.PrekeyManager()
    let clock = ContinuousClock()

    /// The proposed batch (D4). Today's is `PrekeyManager.defaultBatchSize`.
    static let proposedBatchSize = 50

    @Test("A CryptoKit Enclave key leaves no keychain item", .enabled(if: secureEnclaveAvailable()))
    func cryptoKitKeyLeavesNoKeychainItem() throws {
        let contactID = "measure.\(UUID().uuidString)"
        defer { self.pm.deleteAllKeys(for: contactID) }

        // Positive control: a keychain prekey is found by the hash of its public key. Without this,
        // "not found" below could mean the lookup is wrong rather than that nothing was saved.
        let control = try #require(try self.pm.generateBatch(contactID: contactID, count: 1).first)
        #expect(Self.keychainItemCount(publicKey: control.publicKey) == 1,
                "the lookup must find a known keychain prekey, or its negative result means nothing")

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: try Self.prekeyAccessControl())
        #expect(Self.keychainItemCount(publicKey: key.publicKey.x963Representation) == 0,
                "the record must hold the only copy of the blob")
    }

    @Test("Generation and open costs, attached for D4", .enabled(if: secureEnclaveAvailable()))
    func measureGenerationAndOpen() throws {
        let contactID = "measure.\(UUID().uuidString)"
        defer { self.pm.deleteAllKeys(for: contactID) }

        var report = ["device: \(Self.deviceModel()), \(ProcessInfo.processInfo.operatingSystemVersionString)"]
        defer { Attachment.record(report.joined(separator: "\n"), named: "prekey-measurement.txt") }

        let batch    = Manager.PrekeyManager.defaultBatchSize
        let proposed = Self.proposedBatchSize
        let access   = try Self.prekeyAccessControl()

        // ── Generation ───────────────────────────────────────────────────
        var keychainPrekeys: [Prekey] = []
        let keychainBatch = try self.clock.measure {
            keychainPrekeys = try self.pm.generateBatch(contactID: contactID, count: batch)
        }
        report.append("keychain batch of \(batch) (today): \(Self.ms(keychainBatch)) total")

        var enclaveKeys: [SecureEnclave.P256.KeyAgreement.PrivateKey] = []
        var enclaveTimes: [Duration] = []
        for _ in 0..<proposed {
            enclaveTimes.append(try self.clock.measure {
                enclaveKeys.append(try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access))
            })
        }
        report.append("CryptoKit Enclave, per key: \(Self.stats(enclaveTimes))")
        report.append("CryptoKit Enclave batch of \(batch): \(Self.ms(enclaveTimes.prefix(batch).reduce(.zero, +))) total")
        report.append("CryptoKit Enclave batch of \(proposed): \(Self.ms(enclaveTimes.reduce(.zero, +))) total")

        var softwareTimes: [Duration] = []
        for _ in 0..<proposed {
            softwareTimes.append(self.clock.measure { _ = P256.KeyAgreement.PrivateKey() })
        }
        report.append("software (fallback), per key: \(Self.stats(softwareTimes))")
        report.append("software batch of \(proposed): \(Self.ms(softwareTimes.reduce(.zero, +))) total")

        // ── Record field size ────────────────────────────────────────────
        let sizes = enclaveKeys.map { $0.dataRepresentation.count }
        report.append("dataRepresentation bytes: min \(sizes.min()!), max \(sizes.max()!)")

        // ── Opening one message: the receive path's per-message key work ───
        let sender = P256.KeyAgreement.PrivateKey().publicKey
        let senderSecKey = try #require(Self.publicSecKey(x963: sender.x963Representation))

        var keychainOpen: [Duration] = []
        for prekey in keychainPrekeys {
            keychainOpen.append(try self.clock.measure {
                let privateKey = try #require(self.pm.retrievePrivateKey(for: prekey))
                _ = try #require(Self.ecdh(privateKey, senderSecKey))
            })
        }
        report.append("open, keychain lookup + ECDH (today): \(Self.stats(keychainOpen))")

        let blobs = enclaveKeys.prefix(batch).map { $0.dataRepresentation }
        var blobOpen: [Duration] = []
        for blob in blobs {
            blobOpen.append(try self.clock.measure {
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
                _ = try key.sharedSecretFromKeyAgreement(with: sender)
            })
        }
        report.append("open, rebuild from blob + ECDH (D9): \(Self.stats(blobOpen))")
    }

    // MARK: - Helpers

    /// The access control `PrekeyManager.generateBatch` gives its keys, so both paths are measured
    /// under the same constraints.
    private static func prekeyAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error
        ) else { throw error!.takeRetainedValue() as Error }
        return access
    }

    /// Keychain keys whose application label matches this public key. For an EC key the label is the
    /// SHA-1 of its X9.63 public key; the positive control above confirms that on the running OS.
    private static func keychainItemCount(publicKey x963: Data) -> Int {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationLabel as String: Data(Insecure.SHA1.hash(data: x963)),
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var items: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess else { return 0 }
        return (items as? [[String: Any]])?.count ?? 0
    }

    private static func ecdh(_ privateKey: SecKey, _ peer: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        return SecKeyCopyKeyExchangeResult(
            privateKey, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &error
        ) as Data?
    }

    private static func publicSecKey(x963: Data) -> SecKey? {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        return SecKeyCreateWithData(x963 as CFData, attrs as CFDictionary, nil)
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

    private static func ms(_ duration: Duration) -> String {
        String(format: "%.2f ms", Self.milliseconds(duration))
    }

    private static func stats(_ durations: [Duration]) -> String {
        let sorted = durations.map(Self.milliseconds).sorted()
        let median = sorted[sorted.count / 2]
        let p90    = sorted[Int(Double(sorted.count - 1) * 0.9)]
        return String(format: "median %.2f ms, p90 %.2f ms, max %.2f ms (n = %d)",
                      median, p90, sorted.last!, sorted.count)
    }
}
