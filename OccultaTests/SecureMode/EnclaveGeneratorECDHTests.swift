//
//  EnclaveGeneratorECDHTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave. Never run this on a phone that holds real Occulta data: the suite
//  is hosted in Occulta.app, and the production-path tests read and create real-tagged keys.
//
//  Bug 171 and its guard. Several keys were `ECDH(enclave_priv, G) → HKDF`, with G the P-256 generator. ECDH
//  with peer G computes d·G, which is Q, the key's own public point, so the exchange output was a function of
//  Q alone and the Enclave input was not a secret: those keys were only as strong as whatever else went into
//  them. The fix keeps the same Enclave keys and derives `HKDF(ECDH(enclave_priv, P) ‖ r_tier)` instead
//  (`enclaveBoundKey(_:)`), with P a nothing-up-my-sleeve point whose discrete log nobody knows and r_tier the
//  access tier's Keychain secret. Tier U's accessors call it once the epoch exists (Stage 2).
//
//  Asserted about the legacy derivations, which stay for migration and for a downgraded build, and which
//  document what anyone holding Q can still compute for data sealed under them:
//    - the exchange with peer G equals the ANSI X9.63 KDF (SHA-256, requested size 32, no shared info)
//      applied to x(Q), computed with no private key and no Enclave call;
//    - the HKDF output of every legacy site rebuilds from Q alone: share staging, vault, shard custody,
//      restore vault, the Secure Mode PIN inner verifier key, and the identity-derived v1 local DB key;
//    - the real `Manager.Key` and `ShareStagingKeyManager` legacy keys equal that rebuild, and the hybrid
//      local DB key rebuilds from Q plus the Keychain-random half it mixes in.
//
//  Asserted about the Enclave-bound derivations:
//    - the new peer is P, not G, and the exchange with P is *not* a function of Q;
//    - every site's new key differs from what a holder of Q can rebuild, both with and without the tier
//      secret: even knowing Q and r, the attacker is missing ECDH(d, P), which needs the Enclave;
//    - the hybrid form (iOS 26+, an Enclave ML-KEM secret `ss` as well) differs too, even for an attacker who
//      also holds the record's ciphertext c: he is missing ss as well, which needs the Enclave;
//    - the real `Manager.Key` and `ShareStagingKeyManager` Enclave-bound keys differ from that rebuild too, in
//      whichever form this device's records are.
//
//  Kept: a control (ECDH against a peer whose discrete log is unknown is not reproducible from Q, so the
//  equalities above are a property of G and not of the test), and a corollary for the planned layer keys
//  (`PASSPHRASE_LAYER_KEYS.md` §1): ECDH(enclave_priv, s·G) with s known equals software ECDH(s, Q), so a peer
//  derived from the guessed phrase gives the Enclave no say per guess either.
//
//  Removed: the case asserting that Q of a key carrying the vault's access control needs no `LAContext`
//  evaluation. It could only run on a device. With a derivation in which Q alone is irrelevant it stays true and
//  says nothing, which is what the Guard section of `bugs.md` Bug 171 said should happen to it. The measurement
//  it made stays recorded there.
//

import Testing
import CryptoKit
import Foundation
import Security
import OccultaCore

@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

/// An Enclave ML-KEM key needs iOS 26 as well.
private func enclaveMLKEMAvailable() -> Bool {
    guard #available(iOS 26, *) else { return false }
    return secureEnclaveAvailable()
}

@Suite("Bug 171 — ECDH against the P-256 generator is a function of the public key alone; against P it is not", .serialized)
struct EnclaveGeneratorECDHTests {

    // MARK: - Helpers

    /// The P-256 base point G, uncompressed X9.63. Typed independently of production so a wrong
    /// constant there cannot make these tests agree with themselves.
    private static let generatorG = Data([
        0x04,
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
        0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
        0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
        0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
    ])

    /// P, recomputed from its seed (`NUMSPoint`), never read from production.
    private static let pointP = NUMSPoint.recompute().x963

    /// `ShareStagingKeyManager.hkdfInfo` and `.hkdfInfoEnclaveBound` are private; the literals are repeated here.
    private static let stagingLegacyInfo = "Occulta-v1-share-index-2026".data(using: .utf8)!
    private static let stagingNewInfo    = "Occulta-v2-share-staging-2026".data(using: .utf8)!
    private static let stagingNewPQInfo  = "Occulta-v2-share-staging-pq-2026".data(using: .utf8)!

    /// Every legacy site, ECDH against G: its HKDF info, and whether the salt is Q (every site but one) or
    /// G ⊕ Q (the identity-derived v1 local DB key).
    private static let legacySites: [(name: String, info: Data, saltIsXOR: Bool)] = [
        ("share staging",                          stagingLegacyInfo,              false),
        ("vault",                                  SaltInfo.kVaultKeyInfo,         false),
        ("shard custody",                          SaltInfo.kShardCustodyKeyInfo,  false),
        ("restore vault",                          SaltInfo.kRestoreVaultKeyInfo,  false),
        ("secure mode PIN inner verifier key",     SaltInfo.kSecureModeKeyInfo,    false),
        ("v1 local DB (identity-derived, migration only)", SaltInfo.kLocalDBKeyInfo, true)
    ]

    /// Every site that has an Enclave-bound form: its new info, and the legacy info of the same key.
    private static let enclaveBoundSites: [(name: String, info: Data, hybridInfo: Data, legacyInfo: Data)] = [
        ("share staging",        stagingNewInfo,                              stagingNewPQInfo,                              stagingLegacyInfo),
        ("vault",                SaltInfo.kVaultEnclaveBoundKeyInfo,          SaltInfo.kVaultEnclaveBoundPQKeyInfo,          SaltInfo.kVaultKeyInfo),
        ("shard custody",        SaltInfo.kShardCustodyEnclaveBoundKeyInfo,   SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo,   SaltInfo.kShardCustodyKeyInfo),
        ("restore vault",        SaltInfo.kRestoreVaultEnclaveBoundKeyInfo,   SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo,   SaltInfo.kRestoreVaultKeyInfo),
        ("secure mode PIN wrap", SaltInfo.kSecureModeWrapKeyInfo,             SaltInfo.kSecureModeWrapPQKeyInfo,             SaltInfo.kSecureModeKeyInfo),
        ("local DB",             SaltInfo.kLocalDBEnclaveBoundKeyInfo,        SaltInfo.kLocalDBEnclaveBoundPQKeyInfo,        SaltInfo.kLocalDBHybridKeyInfo)
    ]

    private static func uniqueTag() -> String { "test.generator.ecdh.\(UUID().uuidString)" }

    /// A permanent Enclave P-256 key under `tag`. `flags` are the production access control being
    /// modelled; the accessibility is the one every production key carries.
    private static func makeEnclaveKey(tag: String, flags: SecAccessControlCreateFlags) throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: tag.data(using: .utf8)!,
                kSecAttrAccessControl:  access
            ]
        ]
        guard let key = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    private static func deleteKey(tag: String) {
        SecItemDelete([
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ] as CFDictionary)
    }

    /// Q as X9.63, from the key reference. No exchange, no signing.
    private static func publicPoint(of key: SecKey) throws -> Data {
        let pub = try #require(SecKeyCopyPublicKey(key))
        return try #require(SecKeyCopyExternalRepresentation(pub, nil) as Data?)
    }

    /// The reference to a permanent Enclave key by tag, as production fetches it.
    private static func reference(tag: String, accessGroup: String? = nil) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    /// The exchange exactly as production makes it: same algorithm, same requested size, no shared info,
    /// against `peerX963` — G for the legacy sites, P for the Enclave-bound ones.
    private static func productionExchange(_ privateKey: SecKey, peerX963: Data) throws -> Data {
        let peer = try #require(Manager.Key().convert(material: peerX963))
        var error: Unmanaged<CFError>?
        return try #require(
            SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, peer,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        )
    }

    /// ANSI X9.63 KDF, SHA-256: `SHA256(Z ∥ counter_be32 ∥ sharedInfo)` blocks, truncated to `size`.
    private static func x963KDF(z: Data, size: Int, sharedInfo: Data = Data()) -> Data {
        var output = Data()
        var counter: UInt32 = 1
        while output.count < size {
            var block = z
            withUnsafeBytes(of: counter.bigEndian) { block.append(contentsOf: $0) }
            block.append(sharedInfo)
            output.append(contentsOf: SHA256.hash(data: block))
            counter += 1
        }
        return output.prefix(size)
    }

    /// The exchange output recomputed from Q alone: x(Q) through the X9.63 KDF. This is what ECDH against G
    /// gives, and what an attacker holding Q substitutes for ECDH against P, which he can't compute.
    private static func exchangeFromPublicPoint(_ q: Data) -> Data {
        Self.x963KDF(z: q.subdata(in: 1..<33), size: 32)
    }

    private static func xor(_ a: Data, _ b: Data) -> Data {
        Data(zip(a, b).map { $0 ^ $1 })
    }

    private static func bytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    /// The HKDF step of a site, with the salt that site uses.
    private static func hkdf(_ ikm: Data, salt: Data, info: Data) -> Data {
        Self.bytes(HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: 32
        ))
    }

    private static func salt(forQ q: Data, xor: Bool) -> Data {
        xor ? Self.xor(Self.generatorG, q) : q
    }

    /// What a holder of Q and nothing else can build for an Enclave-bound key, trying the strongest guesses:
    /// the legacy exchange in place of ECDH(d, P), without the tier secret and with it.
    private static func attackerRebuilds(q: Data, secret: Data, info: Data) -> (withoutSecret: Data, withSecret: Data) {
        let exchange = Self.exchangeFromPublicPoint(q)
        return (Self.hkdf(exchange, salt: q, info: info), Self.hkdf(exchange + secret, salt: q, info: info))
    }

    /// The production Enclave-bound derivation of a site, over a key reference and a tier secret, classical or, with
    /// `postQuantum`, hybrid. `info` is the base string of the form in use.
    private static func productionEnclaveBound(
        siteNamed name: String, key: SecKey, secret: Data,
        postQuantum: (secret: Data, ciphertext: Data)? = nil, info: Data
    ) throws -> Data {
        if name == "share staging" {
            return Self.bytes(try ShareStagingKeyManager.enclaveBoundKey(exchangingWith: key, secret: secret, postQuantum: postQuantum))
        }
        return Self.bytes(try #require(Manager.Key().deriveEnclaveBound(
            exchangingWith: key, secret: secret, postQuantum: postQuantum, info: info
        )))
    }

    /// The info string of a record's mode, with SHA-256(c) appended for a hybrid one: what the attacker, who has the
    /// record, knows the derivation used.
    private static func info(of record: TierPQRecord, classical: Data, hybrid: Data) -> Data {
        record.mode == .hybrid ? hybrid + Data(SHA256.hash(data: record.ciphertext)) : classical
    }

    // MARK: - The peer

    @Test("The new peer is the nothing-up-my-sleeve point P and not the generator; G stays only as the legacy peer")
    func newPeerIsPAndNotTheGenerator() {
        let key = Manager.Key()

        #expect(key.numsX963 == Self.pointP)
        #expect(key.numsX963 != Self.generatorG)
        #expect(ShareStagingKeyManager.numsX963 == Self.pointP)
        #expect(ShareStagingKeyManager.numsX963 != Self.generatorG)

        // The legacy derivations keep G.
        #expect(key.fixedX963 == Self.generatorG)
    }

    // MARK: - The exchange

    @Test("Legacy: ECDH(enclave_priv, G) equals the X9.63 KDF of x(Q), recomputed with no private key",
          .enabled(if: secureEnclaveAvailable()))
    func legacyExchangeIsAFunctionOfThePublicPoint() throws {
        let tag = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q   = try Self.publicPoint(of: key)

        let exchanged = try Self.productionExchange(key, peerX963: Manager.Key().fixedX963)
        let fromQ     = Self.exchangeFromPublicPoint(q)

        #expect(exchanged.count == 32)
        #expect(exchanged == fromQ)
    }

    @Test("ECDH(enclave_priv, P) is not a function of Q: it is not the X9.63 KDF of x(Q)",
          .enabled(if: secureEnclaveAvailable()))
    func exchangeAgainstPIsNotAFunctionOfThePublicPoint() throws {
        let tag = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q   = try Self.publicPoint(of: key)

        let exchanged = try Self.productionExchange(key, peerX963: Manager.Key().numsX963)

        #expect(exchanged.count == 32)
        #expect(exchanged != Self.exchangeFromPublicPoint(q))
    }

    @Test("Control: ECDH against a peer of unknown discrete log is not reproducible from Q",
          .enabled(if: secureEnclaveAvailable()))
    func exchangeAgainstAnotherPeerIsNotAFunctionOfThePublicPoint() throws {
        let tag = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q   = try Self.publicPoint(of: key)

        let otherPeer = try #require(Manager.Key().convert(
            material: P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        ))
        var error: Unmanaged<CFError>?
        let exchanged = try #require(
            SecKeyCopyKeyExchangeResult(
                key, .ecdhKeyExchangeCofactorX963SHA256, otherPeer,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        )

        #expect(exchanged != Self.exchangeFromPublicPoint(q))
    }

    // MARK: - The derived keys

    @Test("Legacy: every ECDH(enclave_priv, G) site still rebuilds from Q alone — legacy and migration-only",
          .enabled(if: secureEnclaveAvailable()),
          arguments: EnclaveGeneratorECDHTests.legacySites.map { $0.name })
    func legacyDerivedKeyRebuildsFromThePublicPoint(siteName: String) throws {
        let site = try #require(Self.legacySites.first { $0.name == siteName })
        let tag  = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q   = try Self.publicPoint(of: key)
        let salt = Self.salt(forQ: q, xor: site.saltIsXOR)

        let withEnclave = Self.hkdf(try Self.productionExchange(key, peerX963: Manager.Key().fixedX963), salt: salt, info: site.info)
        let fromQ       = Self.hkdf(Self.exchangeFromPublicPoint(q), salt: salt, info: site.info)

        #expect(withEnclave == fromQ)
    }

    @Test("Every Enclave-bound site differs from what Q rebuilds, with the tier secret and without it",
          .enabled(if: secureEnclaveAvailable()),
          arguments: EnclaveGeneratorECDHTests.enclaveBoundSites.map { $0.name })
    func enclaveBoundKeyDoesNotRebuildFromThePublicPoint(siteName: String) throws {
        let site = try #require(Self.enclaveBoundSites.first { $0.name == siteName })
        let tag  = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key    = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q      = try Self.publicPoint(of: key)
        let secret = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })

        let actual   = try Self.productionEnclaveBound(siteNamed: siteName, key: key, secret: secret, info: site.info)
        let rebuilds = Self.attackerRebuilds(q: q, secret: secret, info: site.info)

        #expect(actual != rebuilds.withoutSecret)
        #expect(actual != rebuilds.withSecret, "an attacker holding Q and the tier secret still lacks ECDH(d, P)")

        // And not the legacy key of the same Enclave key either. The legacy local DB key mixes the same r_U in.
        let legacyIKM = Self.exchangeFromPublicPoint(q) + (siteName == "local DB" ? secret : Data())
        let legacy    = Self.hkdf(legacyIKM, salt: q, info: site.legacyInfo)
        #expect(actual != legacy)
    }

    @Test("Every hybrid site differs from what Q rebuilds, even given the tier secret and the record's ciphertext",
          .enabled(if: enclaveMLKEMAvailable()),
          arguments: EnclaveGeneratorECDHTests.enclaveBoundSites.map { $0.name })
    func hybridKeyDoesNotRebuildFromThePublicPoint(siteName: String) throws {
        guard #available(iOS 26, *) else { return }

        let site = try #require(Self.enclaveBoundSites.first { $0.name == siteName })
        let tag  = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key    = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q      = try Self.publicPoint(of: key)
        let secret = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })

        // A real Enclave ML-KEM key and a ciphertext to it, as the tier's record holds.
        let provider     = try #require(PostQuantumProviderFactory.create())
        let pair         = try #require(provider.generatePersistentKeyPair())
        let encapsulated = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))
        let shared       = try #require(provider.decapsulate(ciphertext: encapsulated.ciphertext, keyBlob: pair.keyBlob))
        #expect(shared == encapsulated.sharedSecret)

        let hybrid = try Self.productionEnclaveBound(
            siteNamed: siteName, key: key, secret: secret,
            postQuantum: (shared, encapsulated.ciphertext), info: site.hybridInfo
        )

        // The attacker holds Q, r and c, and substitutes the legacy exchange for ECDH(d, P). He has no ss: he tries
        // none, and a zero one.
        let hybridInfo = site.hybridInfo + Data(SHA256.hash(data: encapsulated.ciphertext))
        let exchange   = Self.exchangeFromPublicPoint(q)
        let guesses = [
            Self.hkdf(exchange + secret, salt: q, info: hybridInfo),
            Self.hkdf(exchange + Data(repeating: 0, count: 32) + secret, salt: q, info: hybridInfo),
            Self.attackerRebuilds(q: q, secret: secret, info: site.info).withSecret
        ]
        for guess in guesses { #expect(hybrid != guess) }

        // And the classical form of the same Enclave key and secret is another key.
        let classical = try Self.productionEnclaveBound(siteNamed: siteName, key: key, secret: secret, info: site.info)
        #expect(hybrid != classical)
    }

    // MARK: - The production code, not a mirror of it

    @Test("Legacy: the real shard custody, restore vault and Secure Mode PIN keys still equal the rebuild from Q",
          .enabled(if: secureEnclaveAvailable()))
    func realManagerLegacyKeysRebuildFromThePublicPoint() throws {
        let manager = Manager.Key()

        // Tags are private to `Manager.Key`; these are its `Tags.shardCustody` and `.secureModePin`.
        let custodyKey = try #require(try manager.legacyKey(.shardCustody).map(Self.bytes))
        let restoreKey = try #require(try manager.legacyKey(.restoreVault).map(Self.bytes))
        let pinKey     = try #require(try manager.deriveSecureModeKey().map(Self.bytes))

        let custodyQ = try Self.publicPoint(of: try #require(Self.reference(tag: "shard.custody.occulta")))
        let pinQ     = try Self.publicPoint(of: try #require(Self.reference(tag: "app.layer.key.occulta.v1")))

        #expect(custodyKey == Self.hkdf(Self.exchangeFromPublicPoint(custodyQ), salt: custodyQ,
                                        info: SaltInfo.kShardCustodyKeyInfo))
        #expect(restoreKey == Self.hkdf(Self.exchangeFromPublicPoint(custodyQ), salt: custodyQ,
                                        info: SaltInfo.kRestoreVaultKeyInfo))
        #expect(pinKey     == Self.hkdf(Self.exchangeFromPublicPoint(pinQ), salt: pinQ,
                                        info: SaltInfo.kSecureModeKeyInfo))
    }

    @Test("The real shard custody, restore vault and PIN wrap keys differ from the rebuild from Q, with r_U and without",
          .enabled(if: secureEnclaveAvailable()))
    func realManagerEnclaveBoundKeysDoNotRebuildFromThePublicPoint() throws {
        let manager = Manager.Key()
        let secret  = try #require(try manager.tierSecret(.deviceUnlock))

        // The device's own record, in whichever form this OS makes it: hybrid on iOS 26+, classical below.
        try manager.createTierPQRecordIfAbsent(.deviceUnlock)
        let record = try #require(try manager.tierPQRecord(.deviceUnlock))

        let custodyKey = try #require(try manager.enclaveBoundKey(.shardCustody).map(Self.bytes))
        let restoreKey = try #require(try manager.enclaveBoundKey(.restoreVault).map(Self.bytes))
        let wrapKey    = try #require(try manager.enclaveBoundKey(.secureModeWrap).map(Self.bytes))

        let custodyQ = try Self.publicPoint(of: try #require(Self.reference(tag: "shard.custody.occulta")))
        let pinQ     = try Self.publicPoint(of: try #require(Self.reference(tag: "app.layer.key.occulta.v1")))

        let custody = Self.attackerRebuilds(q: custodyQ, secret: secret, info: Self.info(of: record, classical: SaltInfo.kShardCustodyEnclaveBoundKeyInfo, hybrid: SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo))
        let restore = Self.attackerRebuilds(q: custodyQ, secret: secret, info: Self.info(of: record, classical: SaltInfo.kRestoreVaultEnclaveBoundKeyInfo, hybrid: SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo))
        let wrap    = Self.attackerRebuilds(q: pinQ,     secret: secret, info: Self.info(of: record, classical: SaltInfo.kSecureModeWrapKeyInfo, hybrid: SaltInfo.kSecureModeWrapPQKeyInfo))

        #expect(custodyKey != custody.withoutSecret && custodyKey != custody.withSecret)
        #expect(restoreKey != restore.withoutSecret && restoreKey != restore.withSecret)
        #expect(wrapKey    != wrap.withoutSecret    && wrapKey    != wrap.withSecret)

        // Custody and restore share an Enclave key and a secret, and still differ.
        #expect(custodyKey != restoreKey)

        // None is the legacy key of the same Enclave key.
        let legacyCustody = try #require(try manager.legacyKey(.shardCustody).map(Self.bytes))
        let legacyRestore = try #require(try manager.legacyKey(.restoreVault).map(Self.bytes))
        let legacyPIN     = try #require(try manager.deriveSecureModeKey().map(Self.bytes))
        #expect(custodyKey != legacyCustody)
        #expect(restoreKey != legacyRestore)
        #expect(wrapKey    != legacyPIN)
    }

    @Test("Legacy: the real hybrid local DB key equals the rebuild from Q plus the Keychain-random half",
          .enabled(if: secureEnclaveAvailable()))
    func realHybridLocalDBKeyRebuildsFromThePublicPointAndTheKeychainHalf() throws {
        let hybrid = try #require(try Manager.Key().legacyKey(.localDB).map(Self.bytes))

        let q = try Self.publicPoint(of: try #require(Self.reference(tag: "local.db.se.key.occulta")))

        // The random half is a generic-password item the same process reads with no gate beyond
        // device unlock; `Manager.Key.localDBRandomKeychainAccount` is private.
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: "local.db.random.key.occulta",
            kSecReturnData as String:  true
        ] as CFDictionary, &item)
        #expect(status == errSecSuccess)
        let randomHalf = try #require(item as? Data)

        let rebuilt = Self.hkdf(Self.exchangeFromPublicPoint(q) + randomHalf, salt: q,
                                info: SaltInfo.kLocalDBHybridKeyInfo)
        #expect(hybrid == rebuilt)
    }

    @Test("The real Enclave-bound local DB key differs from the rebuild from Q, even given the Keychain-random half",
          .enabled(if: secureEnclaveAvailable()))
    func realEnclaveBoundLocalDBKeyDoesNotRebuildFromThePublicPoint() throws {
        let manager = Manager.Key()
        let secret  = try #require(try manager.tierSecret(.deviceUnlock))

        try manager.createTierPQRecordIfAbsent(.deviceUnlock)
        let record = try #require(try manager.tierPQRecord(.deviceUnlock))
        let key    = try #require(try manager.enclaveBoundKey(.localDB).map(Self.bytes))

        let q = try Self.publicPoint(of: try #require(Self.reference(tag: "local.db.se.key.occulta")))
        let rebuilds = Self.attackerRebuilds(
            q: q, secret: secret,
            info: Self.info(of: record, classical: SaltInfo.kLocalDBEnclaveBoundKeyInfo, hybrid: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo)
        )

        #expect(key != rebuilds.withoutSecret)
        #expect(key != rebuilds.withSecret)

        // The same r_U, and the same Enclave key, as the legacy hybrid key: only the peer and the info differ.
        let legacy = try #require(try manager.legacyKey(.localDB).map(Self.bytes))
        #expect(key != legacy)
        // Reading it created nothing: r_U is the item the legacy key already made.
        #expect(try manager.tierSecret(.deviceUnlock) == secret)
    }

    @Test("Legacy: the real ShareStagingKeyManager key still equals the rebuild from Q",
          .enabled(if: secureEnclaveAvailable()))
    func realShareStagingLegacyKeyRebuildsFromThePublicPoint() throws {
        let staging = try Self.bytes(ShareStagingKeyManager().deriveLegacySymmetricKey())

        // Its private key lives in the shared access group, so the lookup carries the group.
        let key = try #require(Self.reference(tag: "share.index.se.key.occulta",
                                              accessGroup: "group.com.occulta.shared"))
        let q = try Self.publicPoint(of: key)

        #expect(staging == Self.hkdf(Self.exchangeFromPublicPoint(q), salt: q, info: Self.stagingLegacyInfo))
    }

    @Test("The real ShareStagingKeyManager Enclave-bound key differs from the rebuild from Q, given r_S too",
          .enabled(if: secureEnclaveAvailable()))
    func realShareStagingEnclaveBoundKeyDoesNotRebuildFromThePublicPoint() throws {
        // An `r_S` and a PQ record of the test's own, so the canonical items are left alone.
        let manager = ShareStagingKeyManager(
            tierSecretAccount:   "test.generator.ecdh.\(UUID().uuidString)",
            tierPQRecordAccount: "test.generator.ecdh.\(UUID().uuidString)"
        )
        defer { manager.deleteTierSecret(); manager.deleteTierPQRecord() }

        try manager.createTierSecretIfAbsent()
        try manager.createTierPQRecordIfAbsent()
        let secret  = try #require(try manager.tierSecret())
        let record  = try #require(try manager.tierPQRecord())
        let staging = try Self.bytes(manager.deriveEnclaveBoundKey())

        let key = try #require(Self.reference(tag: "share.index.se.key.occulta",
                                              accessGroup: "group.com.occulta.shared"))
        let q = try Self.publicPoint(of: key)
        let rebuilds = Self.attackerRebuilds(
            q: q, secret: secret,
            info: record.mode == .hybrid ? Self.stagingNewPQInfo + Data(SHA256.hash(data: record.ciphertext)) : Self.stagingNewInfo
        )

        let legacy = try Self.bytes(manager.deriveLegacySymmetricKey())

        #expect(staging != rebuilds.withoutSecret)
        #expect(staging != rebuilds.withSecret)
        #expect(staging != legacy)
    }

    // MARK: - The planned layer keys

    /// `PASSPHRASE_LAYER_KEYS.md` §1 feeds the stretched phrase `s` into the Enclave as
    /// `ECDH(SE_priv, Q_D)` with `Q_D = s·G`, so that every guess costs an Enclave call. That output is
    /// `s·d·G = s·Q`, and an attacker holding the guess `s` and the public Q computes it in software.
    @Test("Corollary: ECDH(enclave_priv, s·G) equals software ECDH(s, Q), with no Enclave call",
          .enabled(if: secureEnclaveAvailable()))
    func exchangeWithAPeerDerivedFromAKnownScalarIsComputableFromThePublicPoint() throws {
        let tag = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q   = try Self.publicPoint(of: key)

        let s    = P256.KeyAgreement.PrivateKey()    // stands for the stretched phrase s_D
        let peer = try #require(Manager.Key().convert(material: s.publicKey.x963Representation))

        var error: Unmanaged<CFError>?
        let withEnclave = try #require(
            SecKeyCopyKeyExchangeResult(
                key, .ecdhKeyExchangeCofactorX963SHA256, peer,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        )

        let shared = try s.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: q))
        let fromQ  = Self.x963KDF(z: shared.withUnsafeBytes { Data($0) }, size: 32)

        #expect(withEnclave == fromQ)
    }
}
