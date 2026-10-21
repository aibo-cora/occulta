//
//  EnclaveGeneratorECDHTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave. Never run this on a phone that holds real Occulta data: the suite
//  is hosted in Occulta.app, and the production-path tests read and create real-tagged keys.
//
//  The question: several keys are `ECDH(enclave_priv, G) → HKDF` with G the P-256 generator. ECDH
//  with peer G computes d·G, which is Q, the key's own public point. If the exchange output is a
//  function of Q alone, the Enclave input is not a secret, and these keys are only as strong as
//  whatever else goes into them.
//
//  Asserted:
//    - the exchange output equals the ANSI X9.63 KDF (SHA-256, requested size 32, no shared info)
//      applied to x(Q), computed with no private key and no Enclave call;
//    - the HKDF output of every production site rebuilds from Q alone: share staging, vault, shard
//      custody, restore vault, Secure Mode PIN, and the legacy local DB key;
//    - the real `Manager.Key` and `ShareStagingKeyManager` derivations equal that rebuild;
//    - the hybrid local DB key rebuilds from Q plus the Keychain-random half it already mixes in;
//    - a control: ECDH against a peer whose discrete log is unknown is *not* reproducible from Q, so
//      the equality above is a property of G and not of the test;
//    - a corollary for the planned layer keys (`PASSPHRASE_LAYER_KEYS.md` §1): ECDH(enclave_priv, s·G)
//      with s known equals software ECDH(s, Q), so a peer derived from the guessed phrase gives the
//      Enclave no say per guess either.
//
//  Skipped where the host cannot create the vault's access control (the Simulator refuses it, LAError
//  -1020), so that case shows as skipped and not as a pass: whether Q of a key carrying that access
//  control comes back through a fresh `LAContext` that may not interact, with no evaluation. Attached
//  as `vault-acl-public-point.txt` where it runs.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import Security

@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@Suite("ECDH against the P-256 generator is a function of the public key alone", .serialized)
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

    /// `ShareStagingKeyManager.hkdfInfo` is private; the literal is repeated here.
    private static let stagingInfo = "Occulta-v1-share-index-2026".data(using: .utf8)!

    /// Every site that derives from `ECDH(enclave_priv, G)`: its HKDF info, and whether the salt is
    /// Q (every site but one) or G ⊕ Q (the legacy local DB key).
    private static let sites: [(name: String, info: Data, saltIsXOR: Bool)] = [
        ("share staging",     stagingInfo,                    false),
        ("vault",             SaltInfo.kVaultKeyInfo,         false),
        ("shard custody",     SaltInfo.kShardCustodyKeyInfo,  false),
        ("restore vault",     SaltInfo.kRestoreVaultKeyInfo,  false),
        ("secure mode PIN",   SaltInfo.kSecureModeKeyInfo,    false),
        ("legacy local DB",   SaltInfo.kLocalDBKeyInfo,       true)
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
    private static func reference(tag: String, accessGroup: String? = nil, context: LAContext? = nil) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    /// The exchange exactly as the production sites make it: same algorithm, same peer, same
    /// requested size, no shared info.
    private static func productionExchange(_ privateKey: SecKey) throws -> Data {
        let peer = try #require(Manager.Key().convert(material: Manager.Key().fixedX963))
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

    /// The exchange output recomputed from Q alone: x(Q) through the X9.63 KDF.
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

    // MARK: - The peer

    @Test("The production peer is the standard P-256 generator")
    func productionPeerIsTheGenerator() {
        #expect(Manager.Key().fixedX963 == Self.generatorG)
    }

    // MARK: - The exchange

    @Test("ECDH(enclave_priv, G) equals the X9.63 KDF of x(Q), recomputed with no private key",
          .enabled(if: secureEnclaveAvailable()))
    func exchangeIsAFunctionOfThePublicPoint() throws {
        let tag = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q   = try Self.publicPoint(of: key)

        let exchanged = try Self.productionExchange(key)
        let fromQ     = Self.exchangeFromPublicPoint(q)

        #expect(exchanged.count == 32)
        #expect(exchanged == fromQ)
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

    @Test("Every ECDH(enclave_priv, G) site rebuilds from Q alone",
          .enabled(if: secureEnclaveAvailable()),
          arguments: EnclaveGeneratorECDHTests.sites.map { $0.name })
    func derivedKeyRebuildsFromThePublicPoint(siteName: String) throws {
        let site = try #require(Self.sites.first { $0.name == siteName })
        let tag  = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        let key = try Self.makeEnclaveKey(tag: tag, flags: [.privateKeyUsage])
        let q   = try Self.publicPoint(of: key)
        let salt = Self.salt(forQ: q, xor: site.saltIsXOR)

        let withEnclave = Self.hkdf(try Self.productionExchange(key), salt: salt, info: site.info)
        let fromQ       = Self.hkdf(Self.exchangeFromPublicPoint(q), salt: salt, info: site.info)

        #expect(withEnclave == fromQ)
    }

    // MARK: - The production code, not a mirror of it

    @Test("The real shard custody, restore vault and Secure Mode PIN keys equal the rebuild from Q",
          .enabled(if: secureEnclaveAvailable()))
    func realManagerKeysRebuildFromThePublicPoint() throws {
        let manager = Manager.Key()

        // Tags are private to `Manager.Key`; these are its `Tags.shardCustody` and `.secureModePin`.
        let custodyKey = try #require(try manager.deriveShardCustodyKey().map(Self.bytes))
        let restoreKey = try #require(try manager.deriveRestoreVaultKey().map(Self.bytes))
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

    @Test("The real hybrid local DB key equals the rebuild from Q plus the Keychain-random half",
          .enabled(if: secureEnclaveAvailable()))
    func realHybridLocalDBKeyRebuildsFromThePublicPointAndTheKeychainHalf() throws {
        let hybrid = try #require(try Manager.Key().createHybridLocalEncryptionKey().map(Self.bytes))

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

    @Test("The real ShareStagingKeyManager key equals the rebuild from Q",
          .enabled(if: secureEnclaveAvailable()))
    func realShareStagingKeyRebuildsFromThePublicPoint() throws {
        let staging = try Self.bytes(ShareStagingKeyManager().deriveSymmetricKey())

        // Its private key lives in the shared access group, so the lookup carries the group.
        let key = try #require(Self.reference(tag: "share.index.se.key.occulta",
                                              accessGroup: "group.com.occulta.shared"))
        let q = try Self.publicPoint(of: key)

        #expect(staging == Self.hkdf(Self.exchangeFromPublicPoint(q), salt: q, info: Self.stagingInfo))
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

    // MARK: - Is Q behind the gate?

    /// True where the host can create a key with the vault's access control. The Simulator cannot.
    private static func vaultACLKeyCreatable() -> Bool {
        let tag = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }
        return (try? Self.makeEnclaveKey(tag: tag, flags: Self.vaultFlags)) != nil
    }

    /// `Manager.Key.createVaultSEKey`'s access control flags.
    private static let vaultFlags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]

    /// A fresh context that may not interact and has evaluated nothing must still return Q. If the
    /// reference fetch needed an evaluation, `#require` fails here, and that is the answer.
    @Test("Q of a key carrying the vault's access control needs no LAContext evaluation",
          .enabled(if: EnclaveGeneratorECDHTests.vaultACLKeyCreatable()))
    func publicPointOfTheVaultACLKeyNeedsNoEvaluation() throws {
        let tag = Self.uniqueTag()
        defer { Self.deleteKey(tag: tag) }

        var report: [String] = []
        defer { Attachment.record(report.joined(separator: "\n"), named: "vault-acl-public-point.txt") }

        let key     = try Self.makeEnclaveKey(tag: tag, flags: Self.vaultFlags)
        let created = try Self.publicPoint(of: key)

        let context = LAContext()
        context.interactionNotAllowed = true

        let fetched  = try #require(Self.reference(tag: tag, context: context))
        let fetchedQ = try Self.publicPoint(of: fetched)
        report.append("ref fetch + SecKeyCopyPublicKey, non-interactive unevaluated context, returned Q: \(fetchedQ == created)")
        #expect(fetchedQ == created)

        // Measured, not asserted: whether the gate holds for a use of the key under the same context.
        var error: Unmanaged<CFError>?
        let peer = try #require(Manager.Key().convert(material: Manager.Key().fixedX963))
        let exchange = SecKeyCopyKeyExchangeResult(
            fetched, .ecdhKeyExchangeCofactorX963SHA256, peer,
            [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
        ) as? Data
        let reason = error.map { String(describing: $0.takeRetainedValue()) } ?? "none"
        report.append("ECDH with the same non-interactive unevaluated context: \(exchange == nil ? "nothing" : "a 32-byte result") (error: \(reason))")
    }
}
