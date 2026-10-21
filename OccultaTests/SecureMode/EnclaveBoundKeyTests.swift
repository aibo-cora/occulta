//
//  EnclaveBoundKeyTests.swift
//  OccultaTests
//
//  Bug 171 (`Docs/Features/Secure Mode/bugs.md`), Stage 1: the Enclave-bound derivations, `enclaveBoundKey(_:)`,
//  which replace `HKDF(ECDH(enclave_priv, G) …)` with `HKDF(ECDH(enclave_priv, P) ‖ r_tier)`.
//
//  Nearly all of it runs without a Secure Enclave, on CI as well: the derivation takes any P-256 private key, so a
//  software key with a known scalar stands in for the Enclave key, and the expected values are rebuilt here with
//  CryptoKit alone, from the seed of P and the info strings, never from production constants. The tests that need
//  a real Enclave are in `EnclaveGeneratorECDHTests`.
//
//    - `NUMSPointTests`:              P recomputes from its seed, and every copy of it equals that.
//    - `EnclaveBoundDerivationTests`: known answers, domain separation, and "a missing secret stops the derivation
//                                     before any Enclave key is fetched".
//    - `TestKeyManagerEnclaveBoundTests`: the software mirror, and the tier separation the plan relies on.
//    - `TierSecretKeychainTests`:     the Keychain items `r_U`, `r_B`, `r_S` on accounts of the test's own.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import Security

@testable import Occulta

// MARK: - Helpers

/// P, recomputed from its seed: `x = SHA-256("Occulta-NUMS-P256-v1" ‖ be32(ctr))` for ctr = 0, 1, 2, …, the first x
/// for which `0x02 ‖ x` decompresses to a point. Shared with `EnclaveGeneratorECDHTests`.
enum NUMSPoint {
    static let seed = Data("Occulta-NUMS-P256-v1".utf8)

    static func x(counter: UInt32) -> Data {
        var input = Self.seed
        withUnsafeBytes(of: counter.bigEndian) { input.append(contentsOf: $0) }
        return Data(SHA256.hash(data: input))
    }

    static func recompute() -> (counter: UInt32, x963: Data) {
        var counter: UInt32 = 0
        while true {
            if let point = try? P256.KeyAgreement.PublicKey(compressedRepresentation: Data([0x02]) + Self.x(counter: counter)) {
                return (counter, point.x963Representation)
            }
            counter += 1
        }
    }
}

func keyBytes(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes { Data($0) }
}

/// A software P-256 private key with a known scalar, standing in for an Enclave key.
func softwareP256Key(scalar: Data) throws -> SecKey {
    let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
    let attributes: [String: Any] = [
        kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String:      kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits as String: 256
    ]
    var error: Unmanaged<CFError>?
    return try #require(SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error))
}

/// The 32-byte scalar of a software `SecKey` (its X9.63 form is `04 ‖ x ‖ y ‖ d`).
func scalarOf(_ key: SecKey) throws -> Data {
    let external = try #require(SecKeyCopyExternalRepresentation(key, nil) as Data?)
    #expect(external.count == 97)
    return external.suffix(32)
}

/// The Enclave-bound derivation rebuilt with CryptoKit alone: ECDH against the recomputed P, then the X9.63 KDF
/// that `.ecdhKeyExchangeCofactorX963SHA256` applies, then HKDF over `t ‖ r`, salted with the key's public point.
func rebuildEnclaveBound(scalar: Data, secret: Data, info: Data) throws -> Data {
    let key    = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
    let peer   = try P256.KeyAgreement.PublicKey(x963Representation: NUMSPoint.recompute().x963)
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    let t      = keyBytes(shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32))

    return keyBytes(HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: t + secret),
        salt: key.publicKey.x963Representation, info: info, outputByteCount: 32
    ))
}

/// The legacy derivation rebuilt the same way, against the generator G: `HKDF(ECDH(d, G) [‖ r], salt: Q, info)`.
func rebuildLegacy(scalar: Data, secret: Data?, info: Data) throws -> Data {
    let key    = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
    let g      = try P256.KeyAgreement.PublicKey(x963Representation: Data([
        0x04,
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
    ]))
    let shared = try key.sharedSecretFromKeyAgreement(with: g)
    let t      = keyBytes(shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32))

    return keyBytes(HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: t + (secret ?? Data())),
        salt: key.publicKey.x963Representation, info: info, outputByteCount: 32
    ))
}

/// Known-answer inputs: the scalar d = 01 02 … 20 and the tier secret r = A0 A1 … BF.
let katScalar = Data((1...32).map { UInt8($0) })
let katSecret = Data((0..<32).map { UInt8(0xA0 + $0) })

/// `HKDF(ECDH(d, P) ‖ r, salt: Q, info)` for the known-answer inputs, computed once by an independent script and
/// pinned, so a change to the IKM order, the salt or a string breaks a test and not only the rebuild.
let katVectors: [(name: String, info: Data, expected: String)] = [
    ("local DB",        SaltInfo.kLocalDBEnclaveBoundKeyInfo,     "51361a983803120e2de098615cad795d595181f6127157fb9736a8dbdd6f1ad3"),
    ("vault",           SaltInfo.kVaultEnclaveBoundKeyInfo,       "7210725865426cc69d53ef45427f1d0303621ecaa252a6d5a98448ae2614d130"),
    ("shard custody",   SaltInfo.kShardCustodyEnclaveBoundKeyInfo, "82261ae2be0a7b356d93eda5ddf2b038013ae607a6f44820c7da8fad67f3133d"),
    ("restore buffer",  SaltInfo.kRestoreVaultEnclaveBoundKeyInfo, "9de37657d7fbb9dce8ee2b3e2be1bc674d77730dc9e8a741f4be2fd022aa2243"),
    ("PIN wrap",        SaltInfo.kSecureModeWrapKeyInfo,          "03efab1157ba595f3ccd3d54cc2248d1c21caadfd56137d53e41fa3124aa9bdb")
]

let katStaging = (
    info: Data("Occulta-v2-share-staging-2026".utf8),
    expected: "7980df5a8b47bd8a8cde9c1467f5ac00412367fb069bd591131e1f094ea2894f"
)

func dataFromHex(_ string: String) -> Data {
    let digits = string.filter { $0.isHexDigit }
    var data = Data()
    var index = digits.startIndex
    while index < digits.endIndex {
        let next = digits.index(index, offsetBy: 2)
        data.append(UInt8(digits[index..<next], radix: 16)!)
        index = next
    }
    return data
}

// MARK: - P

@Suite("The nothing-up-my-sleeve point P")
@MainActor
struct NUMSPointTests {

    @Test("P recomputes from its seed by try-and-increment, at counter 1")
    func recomputesFromTheSeed() {
        let recomputed = NUMSPoint.recompute()

        #expect(recomputed.counter == 1)
        #expect(recomputed.x963.count == 65)
        #expect(recomputed.x963.first == 0x04)
        // Counter 0 is not a point, which is why the first one found is counter 1.
        #expect((try? P256.KeyAgreement.PublicKey(compressedRepresentation: Data([0x02]) + NUMSPoint.x(counter: 0))) == nil)
        // And x is the SHA-256 of the seed and the counter, as the doc comments say.
        #expect(NUMSPoint.x(counter: 1).map { String(format: "%02x", $0) }.joined()
                == "918e1d3bbc67c9debf175b384e8debe1b61934830fc72e778b17a8b871696186")
    }

    @Test("Manager.Key, ShareStagingKeyManager and TestKeyManager each carry exactly that point")
    func everyCopyEqualsTheRecomputedPoint() {
        let recomputed = NUMSPoint.recompute().x963

        #expect(Manager.Key().numsX963 == recomputed)
        #expect(ShareStagingKeyManager.numsX963 == recomputed)
        #expect(TestKeyManager().numsX963 == recomputed)
    }

    @Test("P is not the generator G, which only the legacy derivations keep")
    func differsFromTheGenerator() {
        let key = Manager.Key()

        #expect(key.numsX963 != key.fixedX963)
        #expect(ShareStagingKeyManager.numsX963 != key.fixedX963)
    }

    @Test("P is a point on the curve that the Security framework accepts as an ECDH peer")
    func isAUsablePeer() throws {
        _ = try P256.KeyAgreement.PublicKey(x963Representation: Manager.Key().numsX963)
        #expect(Manager.Key().convert(material: Manager.Key().numsX963) != nil)
    }
}

// MARK: - The derivation

@Suite("Enclave-bound derivation — HKDF(ECDH(d, P) ‖ r)")
@MainActor
struct EnclaveBoundDerivationTests {

    @Test("Each key equals its pinned known answer and its CryptoKit rebuild",
          arguments: katVectors.map { $0.name })
    func knownAnswer(name: String) throws {
        let vector = try #require(katVectors.first { $0.name == name })
        let key    = try softwareP256Key(scalar: katScalar)

        let derived = try #require(Manager.Key().deriveEnclaveBound(exchangingWith: key, secret: katSecret, info: vector.info))

        #expect(keyBytes(derived) == dataFromHex(vector.expected))
        #expect(keyBytes(derived) == (try rebuildEnclaveBound(scalar: katScalar, secret: katSecret, info: vector.info)))
    }

    @Test("The share staging key equals its pinned known answer and its CryptoKit rebuild")
    func stagingKnownAnswer() throws {
        let key = try softwareP256Key(scalar: katScalar)

        let derived = try ShareStagingKeyManager.enclaveBoundKey(exchangingWith: key, secret: katSecret)

        #expect(keyBytes(derived) == dataFromHex(katStaging.expected))
        #expect(keyBytes(derived) == (try rebuildEnclaveBound(scalar: katScalar, secret: katSecret, info: katStaging.info)))
    }

    @Test("Keys with the same Enclave key and secret differ by their info string alone, and none is a legacy key")
    func domainSeparation() throws {
        let key = try softwareP256Key(scalar: katScalar)
        let manager = Manager.Key()

        var outputs = try katVectors.map { vector in
            keyBytes(try #require(manager.deriveEnclaveBound(exchangingWith: key, secret: katSecret, info: vector.info)))
        }
        outputs.append(keyBytes(try ShareStagingKeyManager.enclaveBoundKey(exchangingWith: key, secret: katSecret)))
        #expect(Set(outputs).count == outputs.count)

        // The legacy forms of the same inputs: ECDH against G, no tier secret mixed in.
        let legacy = try [SaltInfo.kLocalDBHybridKeyInfo, SaltInfo.kVaultKeyInfo, SaltInfo.kShardCustodyKeyInfo,
                          SaltInfo.kRestoreVaultKeyInfo, SaltInfo.kSecureModeKeyInfo]
            .map { try rebuildLegacy(scalar: katScalar, secret: nil, info: $0) }
        #expect(Set(outputs).isDisjoint(with: legacy))
    }

    @Test("The key changes with the tier secret, with the Enclave key, and with a different peer")
    func dependsOnEveryInput() throws {
        let manager = Manager.Key()
        let info    = SaltInfo.kLocalDBEnclaveBoundKeyInfo
        let key     = try softwareP256Key(scalar: katScalar)
        let base    = keyBytes(try #require(manager.deriveEnclaveBound(exchangingWith: key, secret: katSecret, info: info)))

        var otherSecret = katSecret
        otherSecret[0] ^= 0x01
        #expect(keyBytes(try #require(manager.deriveEnclaveBound(exchangingWith: key, secret: otherSecret, info: info))) != base)

        var otherScalar = katScalar
        otherScalar[31] ^= 0x01
        let otherKey = try softwareP256Key(scalar: otherScalar)
        #expect(keyBytes(try #require(manager.deriveEnclaveBound(exchangingWith: otherKey, secret: katSecret, info: info))) != base)

        // The same inputs with G as the peer give the legacy exchange, a different key.
        #expect(base != (try rebuildLegacy(scalar: katScalar, secret: katSecret, info: info)))
    }

    @Test("A missing tier secret gives nil before the Enclave key is fetched, let alone created")
    func missingSecretStopsBeforeTheEnclaveKey() throws {
        var fetched = false

        var recordRead = false

        let derived = try Manager.Key().deriveEnclaveBound(
            secret:        { nil },
            record:        { recordRead = true; return .classical },
            provider:      nil,
            privateKey:    { fetched = true; return nil },
            classicalInfo: SaltInfo.kLocalDBEnclaveBoundKeyInfo,
            hybridInfo:    SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        )

        #expect(derived == nil)
        #expect(!fetched)
        #expect(!recordRead, "the secret is read first")
    }

    @Test("A secret that can't be read throws, and is not taken for a missing one")
    func unreadableSecretThrows() {
        struct Unreadable: Error {}
        var fetched = false

        #expect(throws: Unreadable.self) {
            try Manager.Key().deriveEnclaveBound(
                secret:        { throw Unreadable() },
                record:        { .classical },
                provider:      nil,
                privateKey:    { fetched = true; return nil },
                classicalInfo: SaltInfo.kLocalDBEnclaveBoundKeyInfo,
                hybridInfo:    SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
            )
        }
        #expect(!fetched)
    }

    @Test("A secret with no Enclave key gives nil")
    func missingEnclaveKeyGivesNil() throws {
        let derived = try Manager.Key().deriveEnclaveBound(
            secret:        { katSecret },
            record:        { .classical },
            provider:      nil,
            privateKey:    { nil },
            classicalInfo: SaltInfo.kLocalDBEnclaveBoundKeyInfo,
            hybridInfo:    SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        )

        #expect(derived == nil)
    }

    @Test("The legacy info strings are unchanged, and each new one differs from its legacy string")
    func infoStrings() {
        #expect(SaltInfo.kLocalDBHybridKeyInfo     == Data("Occulta-v2-local-db-pq-2026".utf8))
        #expect(SaltInfo.kVaultKeyInfo             == Data("Occulta-v1-vault-2026".utf8))
        #expect(SaltInfo.kShardCustodyKeyInfo      == Data("Occulta-v1-shard-custody-2026".utf8))
        #expect(SaltInfo.kRestoreVaultKeyInfo      == Data("Occulta-v1-recovery-buffer-2026".utf8))
        #expect(SaltInfo.kSecureModeKeyInfo        == Data("Occulta-v1-secure-mode-pin-2026".utf8))

        #expect(SaltInfo.kLocalDBEnclaveBoundKeyInfo      == Data("Occulta-v3-local-db-2026".utf8))
        #expect(SaltInfo.kVaultEnclaveBoundKeyInfo        == Data("Occulta-v2-vault-2026".utf8))
        #expect(SaltInfo.kShardCustodyEnclaveBoundKeyInfo == Data("Occulta-v2-shard-custody-2026".utf8))
        #expect(SaltInfo.kRestoreVaultEnclaveBoundKeyInfo == Data("Occulta-v2-restore-buffer-2026".utf8))
        #expect(SaltInfo.kSecureModeWrapKeyInfo           == Data("Occulta-v2-secure-mode-pin-wrap-2026".utf8))
    }
}

// MARK: - TestKeyManager

@Suite("TestKeyManager — the software mirror of the Enclave-bound keys")
@MainActor
struct TestKeyManagerEnclaveBoundTests {

    /// (case, the mirror's key for it, the info string, whether it takes the vault tier's secret)
    private func cases(_ manager: TestKeyManager) -> [(name: String, key: EnclaveBoundKey, enclaveKey: SecKey, info: Data, vault: Bool)] {
        [
            ("local DB",       .localDB,        manager.localDBPrivateKey,     SaltInfo.kLocalDBEnclaveBoundKeyInfo,      false),
            ("shard custody",  .shardCustody,   manager.shardCustodyPrivateKey, SaltInfo.kShardCustodyEnclaveBoundKeyInfo, false),
            ("restore buffer", .restoreVault,   manager.shardCustodyPrivateKey, SaltInfo.kRestoreVaultEnclaveBoundKeyInfo, false),
            ("PIN wrap",       .secureModeWrap, manager.secureModePrivateKey,   SaltInfo.kSecureModeWrapKeyInfo,           false),
            ("vault",          .vault(LAContext()), manager.vaultPrivateKey,    SaltInfo.kVaultEnclaveBoundKeyInfo,        true)
        ]
    }

    @Test("Every mirrored classical key equals the CryptoKit rebuild from its scalar and its tier secret")
    func equalsTheRebuild() throws {
        let manager = TestKeyManager()
        manager.tierPQRecordU = .classical
        manager.tierPQRecordB = .classical

        for entry in self.cases(manager) {
            let secret  = try #require(entry.vault ? manager.tierSecretB : manager.tierSecretU)
            let derived = try #require(try manager.enclaveBoundKey(entry.key), "\(entry.name)")

            #expect(keyBytes(derived) == (try rebuildEnclaveBound(scalar: try scalarOf(entry.enclaveKey), secret: secret, info: entry.info)), "\(entry.name)")
        }
    }

    @Test("Tiers don't reach each other: r_U moves the four device-unlock keys only, r_B the vault key only")
    func tierSeparation() throws {
        let manager = TestKeyManager()
        let before  = try self.cases(manager).map { keyBytes(try #require(try manager.enclaveBoundKey($0.key))) }

        manager.tierSecretU = Data(repeating: 0x11, count: 32)
        let afterU = try self.cases(manager).map { keyBytes(try #require(try manager.enclaveBoundKey($0.key))) }
        #expect(zip(before, afterU).map { $0 != $1 } == [true, true, true, true, false])

        manager.tierSecretB = Data(repeating: 0x22, count: 32)
        let afterB = try self.cases(manager).map { keyBytes(try #require(try manager.enclaveBoundKey($0.key))) }
        #expect(zip(afterU, afterB).map { $0 != $1 } == [false, false, false, false, true])
    }

    @Test("A missing secret gives nil and nothing is written: it is not created by the read")
    func missingSecretGivesNilAndWritesNothing() throws {
        let manager = TestKeyManager()
        manager.tierSecretU = nil
        manager.tierSecretB = nil

        for entry in self.cases(manager) {
            #expect(try manager.enclaveBoundKey(entry.key) == nil, "\(entry.name)")
        }
        #expect(manager.tierSecretU == nil)
        #expect(manager.tierSecretB == nil)
    }

    @Test("Only the missing tier's keys go missing")
    func oneMissingTier() throws {
        let manager = TestKeyManager()
        manager.tierSecretU = nil

        #expect(try manager.enclaveBoundKey(.localDB) == nil)
        #expect(try manager.enclaveBoundKey(.shardCustody) == nil)
        #expect(try manager.enclaveBoundKey(.restoreVault) == nil)
        #expect(try manager.enclaveBoundKey(.secureModeWrap) == nil)
        #expect(try manager.enclaveBoundKey(.vault(LAContext())) != nil)
    }

    @Test("simulatesTierSecretMissing hides the secrets without deleting them")
    func simulatedMissingSecret() throws {
        let manager = TestKeyManager()
        let before  = try #require(try manager.enclaveBoundKey(.localDB))
        let secrets = (manager.tierSecretU, manager.tierSecretB)

        manager.simulatesTierSecretMissing = true
        for entry in self.cases(manager) {
            #expect(try manager.enclaveBoundKey(entry.key) == nil, "\(entry.name)")
        }
        #expect(manager.tierSecretU == secrets.0)
        #expect(manager.tierSecretB == secrets.1)

        manager.simulatesTierSecretMissing = false
        #expect(try manager.enclaveBoundKey(.localDB) == before)
    }

    @Test("createTierSecretIfAbsent creates a missing secret once and never replaces one")
    func createsOnlyWhenAbsent() throws {
        let manager = TestKeyManager()
        manager.tierSecretU = nil

        #expect(try manager.createTierSecretIfAbsent(.deviceUnlock))
        let created = try #require(manager.tierSecretU)
        #expect(created.count == 32)

        #expect(try manager.createTierSecretIfAbsent(.deviceUnlock) == false)
        #expect(manager.tierSecretU == created)

        let vault = try #require(manager.tierSecretB)
        #expect(try manager.createTierSecretIfAbsent(.biometry(LAContext())) == false)
        #expect(manager.tierSecretB == vault)
    }

    @Test("The legacy hybrid local DB key creates a missing r_U, as production does; the Enclave-bound key never does")
    func legacyCreatesEnclaveBoundDoesNot() throws {
        let manager = TestKeyManager()
        manager.tierSecretU = nil

        #expect(try manager.enclaveBoundKey(.localDB) == nil)
        #expect(manager.tierSecretU == nil)

        #expect(try manager.legacyKey(.localDB) != nil)
        #expect(manager.tierSecretU?.count == 32)
        #expect(try manager.enclaveBoundKey(.localDB) != nil)
    }

    @Test("The four legacy protocol methods are legacyKey(_:), and equal the CryptoKit rebuild against G")
    func legacyKeysAreUnchanged() throws {
        let manager = TestKeyManager()
        let context = LAContext()

        #expect(try manager.createHybridLocalEncryptionKey() == manager.legacyKey(.localDB))
        #expect(try manager.deriveShardCustodyKey()          == manager.legacyKey(.shardCustody))
        #expect(try manager.deriveRestoreVaultKey()          == manager.legacyKey(.restoreVault))
        #expect(try manager.deriveVaultKey(context: context) == manager.legacyKey(.vault(context)))

        let secretU = try #require(manager.tierSecretU)
        let local   = try #require(try manager.legacyKey(.localDB))
        let custody = try #require(try manager.legacyKey(.shardCustody))
        let restore = try #require(try manager.legacyKey(.restoreVault))
        let vault   = try #require(try manager.legacyKey(.vault(context)))

        #expect(keyBytes(local)   == (try rebuildLegacy(scalar: try scalarOf(manager.localDBPrivateKey), secret: secretU, info: SaltInfo.kLocalDBHybridKeyInfo)))
        #expect(keyBytes(custody) == (try rebuildLegacy(scalar: try scalarOf(manager.shardCustodyPrivateKey), secret: nil, info: SaltInfo.kShardCustodyKeyInfo)))
        #expect(keyBytes(restore) == (try rebuildLegacy(scalar: try scalarOf(manager.shardCustodyPrivateKey), secret: nil, info: SaltInfo.kRestoreVaultKeyInfo)))
        #expect(keyBytes(vault)   == (try rebuildLegacy(scalar: try scalarOf(manager.vaultPrivateKey), secret: nil, info: SaltInfo.kVaultKeyInfo)))
    }

    @Test("Each Enclave-bound key differs from the legacy key of the same Enclave key")
    func differsFromLegacy() throws {
        let manager = TestKeyManager()
        let context = LAContext()

        #expect(try manager.enclaveBoundKey(.localDB)        != manager.legacyKey(.localDB))
        #expect(try manager.enclaveBoundKey(.shardCustody)   != manager.legacyKey(.shardCustody))
        #expect(try manager.enclaveBoundKey(.restoreVault)   != manager.legacyKey(.restoreVault))
        #expect(try manager.enclaveBoundKey(.vault(context)) != manager.legacyKey(.vault(context)))
        #expect(try manager.enclaveBoundKey(.secureModeWrap) != manager.deriveSecureModeKey())
    }

    @Test("The vault and PIN switches apply to the Enclave-bound keys as they do to the legacy ones")
    func switchesApply() throws {
        let manager = TestKeyManager()

        manager.simulatesSecureModeKeyUnavailable = true
        #expect(try manager.enclaveBoundKey(.secureModeWrap) == nil)
        #expect(try manager.deriveSecureModeKey() == nil)
        manager.simulatesSecureModeKeyUnavailable = false

        manager.simulateVaultKeyFailure = true
        #expect(throws: TestKeyManager.SimulatedFailure.self) { try manager.enclaveBoundKey(.vault(LAContext())) }
        #expect(throws: TestKeyManager.SimulatedFailure.self) { try manager.legacyKey(.vault(LAContext())) }
    }
}

// MARK: - Keychain items

@Suite("Tier secrets — Keychain items, on accounts of the test's own", .serialized)
@MainActor
struct TierSecretKeychainTests {

    private static func account() -> String { "test.tier.secret.\(UUID().uuidString)" }

    private static func attributes(account: String) -> [String: Any]? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      account,
            kSecReturnAttributes as String: true
        ] as CFDictionary, &item)
        return status == errSecSuccess ? item as? [String: Any] : nil
    }

    /// An item of the wrong size, as a damaged one would be.
    private static func addMalformed(account: String) {
        SecItemAdd([
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrAccount as String:    account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String:      Data(repeating: 0x42, count: 16)
        ] as CFDictionary, nil)
    }

    @Test("r_U: created once, read back, and a second create leaves it as it is")
    func deviceUnlockSecret() throws {
        let manager = Manager.Key()
        let account = Self.account()
        defer { _ = manager.deleteTierSecret(account: account) }

        #expect(try manager.readTierSecret(.deviceUnlock, account: account) == nil)

        #expect(try manager.createTierSecretIfAbsent(.deviceUnlock, account: account))
        let secret = try #require(try manager.readTierSecret(.deviceUnlock, account: account))
        #expect(secret.count == 32)

        // The duplicate path: re-read, not replace.
        #expect(try manager.createTierSecretIfAbsent(.deviceUnlock, account: account) == false)
        #expect(try manager.readTierSecret(.deviceUnlock, account: account) == secret)

        let attributes = try #require(Self.attributes(account: account))
        #expect(attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    @Test("r_B: created with the vault's access control, read through a context, and never replaced")
    func biometrySecret() throws {
        let manager = Manager.Key()
        let account = Self.account()
        let context = LAContext()
        defer { _ = manager.deleteTierSecret(account: account) }

        #expect(try manager.readTierSecret(.biometry(context), account: account) == nil)

        #expect(try manager.createTierSecretIfAbsent(.biometry(context), account: account))
        let secret = try #require(try manager.readTierSecret(.biometry(context), account: account))
        #expect(secret.count == 32)

        #expect(try manager.createTierSecretIfAbsent(.biometry(context), account: account) == false)
        #expect(try manager.readTierSecret(.biometry(context), account: account) == secret)

        // Carries an access control, and the accessibility the plan names. The Simulator doesn't enforce the access
        // control (Stage 0b checks that on a device); this checks it is the one asked for.
        let attributes = try #require(Self.attributes(account: account))
        #expect(attributes[kSecAttrAccessControl as String] != nil)
        #expect(attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    @Test("Reading a missing secret returns nil and writes nothing")
    func readingWritesNothing() throws {
        let manager = Manager.Key()
        let account = Self.account()

        #expect(try manager.readTierSecret(.deviceUnlock, account: account) == nil)
        #expect(try manager.readTierSecret(.biometry(LAContext()), account: account) == nil)
        #expect(Self.attributes(account: account) == nil)
    }

    @Test("An item of the wrong size reads as missing, and create neither replaces it nor pretends it is fine")
    func malformedItem() throws {
        let manager = Manager.Key()
        let account = Self.account()
        defer { _ = manager.deleteTierSecret(account: account) }

        Self.addMalformed(account: account)

        #expect(try manager.readTierSecret(.deviceUnlock, account: account) == nil)
        #expect(throws: Manager.Key.Errors.self) { try manager.createTierSecretIfAbsent(.deviceUnlock, account: account) }

        var item: CFTypeRef?
        SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: account, kSecReturnData as String: true
        ] as CFDictionary, &item)
        #expect((item as? Data)?.count == 16, "the damaged item must be left for a person to see, not overwritten")
    }

    @Test("deleteTierSecret removes the item, and a missing item counts as deleted")
    func deleting() throws {
        let manager = Manager.Key()
        let account = Self.account()

        try manager.createTierSecretIfAbsent(.biometry(LAContext()), account: account)
        #expect(manager.deleteTierSecret(account: account))
        #expect(Self.attributes(account: account) == nil)

        #expect(manager.deleteTierSecret(account: account))
    }

    @Test("r_S: created in the shared access group, read back, never replaced, and removed by deleteTierSecret")
    func stagingSecret() throws {
        let account = Self.account()
        let staging = ShareStagingKeyManager(tierSecretAccount: account)
        defer { staging.deleteTierSecret() }

        #expect(try staging.tierSecret() == nil)

        #expect(try staging.createTierSecretIfAbsent())
        let secret = try #require(try staging.tierSecret())
        #expect(secret.count == 32)

        #expect(try staging.createTierSecretIfAbsent() == false)
        #expect(try staging.tierSecret() == secret)

        var item: CFTypeRef?
        SecItemCopyMatching([
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  "group.com.occulta.shared",
            kSecReturnAttributes as String: true
        ] as CFDictionary, &item)
        let attributes = try #require(item as? [String: Any])
        #expect(attributes[kSecAttrAccessGroup as String] as? String == "group.com.occulta.shared")
        #expect(attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)

        #expect(staging.deleteTierSecret())
        #expect(try staging.tierSecret() == nil)
        #expect(staging.deleteTierSecret(), "a missing item counts as deleted")
    }

    @Test("The canonical r_S account is the one the plan names, in the shared group")
    func stagingDefaultAccount() {
        #expect(ShareStagingKeyManager.defaultTierSecretAccount == "share.staging.random.key.occulta")
    }

    @Test("Without r_S the staging derivation throws tierSecretMissing, before it fetches the Enclave key")
    func stagingMissingSecret() throws {
        let staging = ShareStagingKeyManager(tierSecretAccount: Self.account())

        #expect(throws: ShareStagingKeyManager.KeyError.tierSecretMissing) { try staging.deriveEnclaveBoundKey() }
        #expect(try staging.tierSecret() == nil, "a read must not create it")
    }
}
