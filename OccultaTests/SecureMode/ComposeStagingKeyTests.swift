//
//  ComposeStagingKeyTests.swift
//  OccultaTests
//
//  Bug 171, Stage 8: the key that seals attachments staged for a group, or for a contact we hold no key for. Release
//  derived it as ECDH(share staging key, G) with its own info string (`ShareStagingKeyManager.deriveComposeStagingKey`),
//  the Bug 171 construction: a function of the staging key's public point. It is now `EnclaveBoundKey.composeStaging`, a
//  tier U key: the local DB Enclave key and `r_U` in the form of tier U's record,
//
//      classical  HKDF(ECDH(d, P) ‖ r_U,        salt: Q, info: "Occulta-v2-compose-staging-2026")
//      hybrid     HKDF(ECDH(d, P) ‖ ss ‖ r_U,   salt: Q, info: "Occulta-v2-compose-staging-pq-2026" ‖ SHA-256(c))
//
//  and it follows tier U's process state (`Manager.Ambient.tierUKeys`): in a process the reseal left on the legacy keys
//  there is no compose key at all, so imports are refused and nothing is written in plaintext. There is no legacy form and
//  no fallback: files sealed under release's compose key (it only ever shipped in dev builds) are not carried over (the
//  user's decision, 2026-10-23).
//
//  The pins were computed by an independent script (P-256 arithmetic, SHA-256 and HMAC from the Python standard library),
//  which reproduces the pinned local DB vectors of `EnclaveBoundKeyTests` and `EnclaveBoundPostQuantumTests` first.
//
//  Written first (Stage 8a), against a stub whose key was always nil.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

/// `HKDF(ECDH(d, P) ‖ r, …)` of the known-answer inputs (`katScalar`, `katSecret`), and with `katPQSharedSecret` and
/// `katPQCiphertext` for the hybrid form.
private let katComposeClassical = "7bd6919307e6c3ed7b71a0d4254f89eb67beac5cd9bf0d0518456a024f7bebba"
private let katComposeHybrid    = "c63e237c490d8d115349129f6e0a4b84e17e5d732adef74bdeca010877bce489"

extension Frozen {
    /// `enclaveBoundKey(.composeStaging)` of the frozen manager: the local DB scalar, `r_U`, and the classical record or
    /// the frozen hybrid one.
    static let composeClassical = "7e242f45042ea39de9d199f04069712eb54f5c02dddaa75ce593babcdd2eb3c2"
    static let composeHybrid    = "50ad2fe6791f819863b1f0c8175eac54d1b2a8060e78ee8b7ca0229e6d6e979e"

    static func composeKey(_ form: KeyForm) -> SymmetricKey {
        SymmetricKey(data: dataFromHex(form == .hybrid ? Self.composeHybrid : Self.composeClassical))
    }
}

/// The hybrid derivation rebuilt with CryptoKit alone.
private func rebuildHybridCompose() throws -> Data {
    let key    = try P256.KeyAgreement.PrivateKey(rawRepresentation: katScalar)
    let peer   = try P256.KeyAgreement.PublicKey(x963Representation: NUMSPoint.recompute().x963)
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    let t      = keyBytes(shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32))

    return keyBytes(HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: t + katPQSharedSecret + katSecret),
        salt: key.publicKey.x963Representation,
        info: SaltInfo.kComposeStagingEnclaveBoundPQKeyInfo + Data(SHA256.hash(data: katPQCiphertext)),
        outputByteCount: 32
    ))
}

// MARK: - The derivation

@Suite("Compose staging key — the derivation")
@MainActor
struct ComposeStagingDerivationTests {

    @Test("The classical key equals its pinned known answer and its CryptoKit rebuild")
    func classicalKnownAnswer() throws {
        let key = try softwareP256Key(scalar: katScalar)

        let derived = try #require(Manager.Key().deriveEnclaveBound(
            exchangingWith: key, secret: katSecret, info: SaltInfo.kComposeStagingEnclaveBoundKeyInfo
        ))

        #expect(keyBytes(derived) == dataFromHex(katComposeClassical))
        #expect(keyBytes(derived) == (try rebuildEnclaveBound(scalar: katScalar, secret: katSecret, info: SaltInfo.kComposeStagingEnclaveBoundKeyInfo)))
    }

    @Test("The hybrid key equals its pinned known answer and its CryptoKit rebuild")
    func hybridKnownAnswer() throws {
        let key = try softwareP256Key(scalar: katScalar)

        let derived = try #require(Manager.Key().deriveEnclaveBound(
            exchangingWith: key, secret: katSecret, postQuantum: (katPQSharedSecret, katPQCiphertext),
            info: SaltInfo.kComposeStagingEnclaveBoundPQKeyInfo
        ))

        #expect(keyBytes(derived) == dataFromHex(katComposeHybrid))
        #expect(keyBytes(derived) == (try rebuildHybridCompose()))
    }

    @Test("The two info strings are the ones the key is pinned under, and differ from every other key's")
    func infoStrings() {
        #expect(SaltInfo.kComposeStagingEnclaveBoundKeyInfo == Data("Occulta-v2-compose-staging-2026".utf8))
        #expect(SaltInfo.kComposeStagingEnclaveBoundPQKeyInfo == Data("Occulta-v2-compose-staging-pq-2026".utf8))

        let others = katVectors.map(\.info) + [katStaging.info, Data("Occulta-v1-group-compose-staging-2026".utf8), SaltInfo.kLocalDBHybridKeyInfo]
        #expect(!others.contains(SaltInfo.kComposeStagingEnclaveBoundKeyInfo) && !others.contains(SaltInfo.kComposeStagingEnclaveBoundPQKeyInfo))
    }
}

// MARK: - On the test key manager

@Suite("Compose staging key — tier U's key on TestKeyManager", .ambientFrozenTestKeyManager)
@MainActor
struct ComposeStagingTierUTests {

    @Test("The frozen manager derives the pinned key in each form", arguments: KeyForm.allCases)
    func frozenKeys(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)

        let compose = try #require(try keys.enclaveBoundKey(.composeStaging))

        #expect(keyBytes(compose) == keyBytes(Frozen.composeKey(form)))
        #expect(compose.bitCount == 256)
        #expect(keyBytes(try #require(try keys.enclaveBoundKey(.composeStaging))) == keyBytes(compose), "stable")
    }

    @Test("It is distinct from every other key of the frozen manager, in each form, and the two forms differ", arguments: KeyForm.allCases)
    func distinctFromEveryOtherKey(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        keys.tierPQRecordB = VaultPins.record(form)
        let context = LAContext()
        let compose = keyBytes(try #require(try keys.enclaveBoundKey(.composeStaging)))

        var others: [String: Data] = [
            "local DB":       keyBytes(try #require(try keys.enclaveBoundKey(.localDB))),
            "custody":        keyBytes(try #require(try keys.enclaveBoundKey(.shardCustody))),
            "restore":        keyBytes(try #require(try keys.enclaveBoundKey(.restoreVault))),
            "PIN wrap":       keyBytes(try #require(try keys.enclaveBoundKey(.secureModeWrap))),
            "vault":          keyBytes(try #require(try keys.enclaveBoundKey(.vault(context)))),
            "legacy local":   keyBytes(try #require(try keys.legacyKey(.localDB))),
            "legacy custody": keyBytes(try #require(try keys.legacyKey(.shardCustody))),
            "legacy restore": keyBytes(try #require(try keys.legacyKey(.restoreVault))),
            "legacy vault":   keyBytes(try #require(try keys.legacyKey(.vault(context)))),
            "PIN inner":      keyBytes(try #require(try keys.deriveSecureModeKey())),
        ]
        keys.become(form == .hybrid ? .classical : .hybrid)
        others["compose, the other form"] = keyBytes(try #require(try keys.enclaveBoundKey(.composeStaging)))

        for (name, bytes) in others {
            #expect(bytes != compose, "the compose key equals the \(name) key")
        }
    }

    @Test("It follows tier U's process state: none in a legacy state (no fallback), the Enclave-bound key in the other",
          arguments: KeyForm.allCases)
    func followsTheState(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)

        Manager.Ambient.setTierUKeys(.legacy)
        #expect(try keys.deriveComposeStagingKey() == nil, "a process the reseal left on the legacy keys has no compose key")

        Manager.Ambient.setTierUKeys(.enclaveBound)
        #expect(keyBytes(try #require(try keys.deriveComposeStagingKey())) == keyBytes(Frozen.composeKey(form)))

        keys.derivesLegacyKeysOnly = true
        #expect(try keys.deriveComposeStagingKey() == nil, "and neither has a build from before the fix")
    }

    @Test("A missing secret gives none, a locked device throws, and nothing is created", arguments: KeyForm.allCases)
    func failures(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        Manager.Ambient.setTierUKeys(.enclaveBound)

        keys.simulatesTierSecretMissing = true
        #expect(try keys.deriveComposeStagingKey() == nil)
        keys.simulatesTierSecretMissing = false

        keys.simulatesLockedDevice = true
        #expect(throws: (any Error).self) { _ = try keys.deriveComposeStagingKey() }
        keys.simulatesLockedDevice = false

        let secret = keys.tierSecretU
        keys.tierSecretU = nil
        #expect(try keys.deriveComposeStagingKey() == nil)
        #expect(keys.tierSecretU == nil, "a read never creates the secret")
        keys.tierSecretU = secret
    }

    @Test("The default provider is tier U's key through the ambient key manager, and throws where there is none",
          arguments: KeyForm.allCases)
    func defaultProvider(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)

        Manager.Ambient.setTierUKeys(.enclaveBound)
        #expect(keyBytes(try TierUComposeStagingKey().deriveComposeStagingKey()) == keyBytes(Frozen.composeKey(form)))

        Manager.Ambient.setTierUKeys(.legacy)
        #expect(throws: ImportError.stagingKeyUnavailable) { _ = try TierUComposeStagingKey().deriveComposeStagingKey() }
    }
}
