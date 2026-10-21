//
//  EnclaveBoundPostQuantumTests.swift
//  OccultaTests
//
//  Bug 171 (`Docs/Features/Secure Mode/bugs.md`), Stage 1b: term 3, the Enclave's ML-KEM secret, on iOS 26+.
//
//  A tier's `TierPQRecord` is classical (no ML-KEM key, `HKDF(t ‖ r)`) or hybrid (an Enclave ML-KEM-1024 key, a
//  ciphertext c to it, and `HKDF(t ‖ ss ‖ r)` with `ss` the Enclave's decapsulation of c). Everything here runs
//  without a Secure Enclave, on CI as well, except the real-Enclave round trips, which are gated: the ML-KEM key
//  is the in-memory one from `PostQuantumProviderFactory.createForTesting()` (a 64-byte seed as its blob), and the
//  P-256 key is a software key with a known scalar.
//
//    - `TierPQRecordTests`:            the record's format, its size in both modes, and the staging copy of the codec.
//    - `HybridDerivationTests`:        known answers from a fixed seed and a fixed c, tampering, corruption, and
//                                      "a hybrid record is never read as classical".
//    - `TestKeyManagerPostQuantumTests`: the software mirror's two modes.
//    - `TierPQRecordKeychainTests`:    the Keychain items on accounts of the test's own, and the real Enclave key.
//    - `StagingPostQuantumTests`:      share staging's own record and ML-KEM seam.
//
//  The expected values are rebuilt here with CryptoKit alone, from the seed of P and the info strings, and pinned
//  in known-answer vectors computed by an independent script.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import OccultaCore

@testable import Occulta

// MARK: - Helpers

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

/// An Enclave ML-KEM key needs iOS 26 as well.
private func enclaveMLKEMAvailable() -> Bool {
    guard #available(iOS 26, *) else { return false }
    return secureEnclaveAvailable()
}

/// The in-memory ML-KEM key's seed: 00 01 … 3F. Its blob, for the in-memory provider, is this seed.
private let katPQSeed = Data((0..<64).map { UInt8($0) })

/// The shared secret that `katPQSeed`'s key decapsulates `katPQCiphertext` to.
private let katPQSharedSecret = dataFromHex("c4117b1207f799511d3c4b4fb43a745c766cb2b2605a66475852607ccf2774b0")

/// A ML-KEM-1024 ciphertext made once to `katPQSeed`'s public key (1,568 bytes).
private let katPQCiphertext = dataFromHex("""
        e512314e8409cf4c3c6bb820dc384d2805b5eb5fd4d460f3ba938ea238172ca16100425152997be94dff0d26122f01b5
        a604cf9a7c024e72afcf0144e164b011b84e22e3b2d7994cd9ace10e8bba8f2465cc23384bba7dc6a76823c44f9e147e
        76e864d47853d9aa560a63aaa189babbcae614abab96b3c2b5999b82440ab8bab6cf0c8c513164def15c7d605eab3b85
        d2bdf6926a7d075f4d23d2ef4fa7462a12294aa9976b6f6f8cbd9f751c362c2a1e7cc1b0e76d96ad7ea369d57cfa6991
        54fac3e9585e7b7ed9e1db041effa4ffd1cdf6ad37f991a38877a2757ee0277c8b2cc73ebce76fdb0baca410a495faca
        033cbe1e693a2546310ae3bbeb57e13a2304ef5e24761e5918c7196b05e3baa5c5bf8e202a583c26d52a41f8e20e0729
        6335691fe7c82a62979db8ed03c87fb5169f1a8310fdcc6b56cce45236c2c104aec473a4961c6322a5f418a3375c8202
        1d7333178409b1b9e44938dcba2947230f7201f8a1403734d2363f1cb6eabbad65f4d9aac94f6c065ff8c7785040cf20
        91c9aea920628da55dab8024afae932eaef46b924e3a6b9dc9324051f9de07ac56786072bb0034afc0a7c98d78767647
        52ab700381c803e43a427f17008779a0c77fd0f290b9814b224a5e5ab832e3c5910543c9cb005f3ebfe5cab2eb331f22
        5b7f5caff747ab9cf84373d8aa2d00e77216d83762f235ff43d1a1a0b382b47d7baa8488ede4d0cfd414751c78098556
        2d084a42c524f97c3123c46a138d0ff8f53d0e089f69884973f2b70d530d1ea9459f94cbb5ecad40367bdc0446689b02
        c6e590c44fb73bb2f3cce5374a69aa214a93e4aa5cd535c04ba84500081938affd8fb29c6205657cb68d3ebd52414a86
        9f54b3ac43c9c936f5ab6574115c2976ab0b528e420c13e442b1a37edd1c55406422e6d7e8eb12d60555d72b6d765b8b
        cb25080ec51891918d2cba72f2cc7a59563763e5feb9d07ff5ce03927d5ccab557aa67a225042f5eb52202759557373a
        12cf4deb106ac11b6c46f5f2ee7db91767df8ec1f751ec304b83f11d9c26f76fe41219dbed31a25af9b96b594cf4cdab
        3f46747b74bf27a83f53b9165cd141db4ecbbec0ef6ca1143e54974cfd0ec098234287fb524d47b7cbfe79eed8b5f15c
        3a7c741a610bfcd2dc73f7ac5adc9e8baf5bb40eafa3725f1026cff00ac1d0c436d8c1f5b6f6b9adf99f5b53c6b10609
        19e4f8dbb4b560b9e03e905187da0e861e1233aa2aef41a5ca91e4b49f3a30f3bc5c5565407f1996ad28386b285c2175
        6e8059a7eaafd1aa1a7974042285663221a8d8647ff806392b05c013738fa6facdb63d37b7181c7fb5c5d18910e22c9e
        02eb5a6dc4859dc1f02ed2f0ab5531cad278cfe003586bef3ef203811afb30a3f7af5e7f764ebe2d63a7ea596874af41
        ba24135699372b576db032c59f5ac4abbfb6921200a470284b3f37dfa77e29ce64978226e937d2840478acd302d93a57
        207325734270b4eceec5197e5458177cb0df2eba921a67a96754cac66a1aa13697bad2208a7a4d79626a25873bbeb8f7
        57b8cd30a10ae03e330d4720b8fc8b66657ec704c28bba77f43e96afa915b3f0db1c4791add2dbac7da9f66cc3375ff5
        ee65eb6eefe582b04016dc3c6694d287103cc00e6b6f073c5eb57458188eb6c1d819efe74ab98b4d93c05730c92b4aaa
        497a0d2548e72e5e1b815634144c85d74543677e66dabad85d526102e4b8c0330b8389a9ff36162b1d51287eef2a5069
        c030d7a59c69f59617ab231e0f24e60479a6dea9be15ba5a9d3fe430f1d38ca0dac26cdefdc123ce517b8ba8b0e20dc6
        1bd048ab6660b904457211d9039f29c3bd2798482fadf80cfb7b3b1bab115b6b3b0b18d39ef8cbbe3640977beed0b3a6
        d8e48c4a904c03031f267b8d0932b245a78b307c791ec4abd4bcec60e9931084e0c9d974b14611d60b1e49aac7866363
        f5139b4c74cb565a6e81dc3253febdd4fb9a7bf49243481940e20b551220c13bcdcedbbb542d574bbdd21cb68c7683d1
        ade31d6f399641c892c2c6d47a360b8a9cedd6404acaed0ae510c89769c48dbe2d0e27ed944c23df309c46dc99b4a9b8
        eca2c078642a7ab91dd2bccd4a9834cc2d55a01552d7681295219c5ab6e841868b6c2e8b13564ab629ea7aa8b41f32ba
        45c475e436194adb3e5eb92d4c9722fbaef7870671477af72dbd6d68297c431a
""")

/// `HKDF(ECDH(d, P) ‖ ss ‖ r, salt: Q, info: hybrid info ‖ SHA-256(c))` for the known-answer inputs
/// (`katScalar`, `katSecret`, `katPQSharedSecret`, `katPQCiphertext`), pinned. The info here is the base string.
private let katPQVectors: [(name: String, info: Data, expected: String)] = [
    ("local DB",        SaltInfo.kLocalDBEnclaveBoundPQKeyInfo,      "a1633e750e75fc31d7aaeff8e33cff26c8da5cf39da13479af0deaba6a397d43"),
    ("vault",           SaltInfo.kVaultEnclaveBoundPQKeyInfo,        "6af96626701dd5cfc63244c8f6f0e90972ad48b8dc4ecc336361be4fb6fe5bb8"),
    ("shard custody",   SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo, "605229d48cf1c67b611a689e5e7778c82c43abbdf94693fc77f48d25e3d61f9d"),
    ("restore buffer",  SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo, "1542a8bd8a993fe573c94854c14604a03b03520180e4fb9b231d0818f2cf7ccf"),
    ("PIN wrap",        SaltInfo.kSecureModeWrapPQKeyInfo,           "af62a62e23bbe4743326230a919bc67e4186ca0b512add02d74b8c1fa5c6fe57"),
    ("share staging",   Data("Occulta-v2-share-staging-pq-2026".utf8), "4c159ad42b3219520dd3b3fa9b5fe1e3771f022a4bd1a18c36b09f3149141428")
]

/// The hybrid derivation rebuilt with CryptoKit alone.
private func rebuildHybrid(scalar: Data, secret: Data, sharedSecret: Data, ciphertext: Data, info: Data) throws -> Data {
    let key    = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
    let peer   = try P256.KeyAgreement.PublicKey(x963Representation: NUMSPoint.recompute().x963)
    let shared = try key.sharedSecretFromKeyAgreement(with: peer)
    let t      = keyBytes(shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32))

    return keyBytes(HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: t + sharedSecret + secret),
        salt: key.publicKey.x963Representation, info: info + Data(SHA256.hash(data: ciphertext)), outputByteCount: 32
    ))
}

/// A classical info string no test expects to be used: a hybrid record must never reach it.
private let unusedClassicalInfo = Data("unused".utf8)

private func inMemoryProvider() throws -> any PostQuantumProvider {
    try #require(PostQuantumProviderFactory.createForTesting())
}

/// A provider that misbehaves in one way, for the cases the real ones don't produce on demand.
nonisolated private struct FakePostQuantum: PostQuantumProvider {
    enum Behavior {
        case cannotGenerate
        case oversizedBlob
        case shortSecret
    }

    let behavior: Behavior

    func generateKeyPair() -> (publicKeyData: Data, privateKeyHandle: Any)? { nil }

    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)? {
        (Data(repeating: 1, count: 32), Data(repeating: 2, count: 1568))
    }

    func decapsulate(ciphertext: Data, privateKeyHandle: Any) -> Data? { nil }

    func generatePersistentKeyPair() -> (publicKeyData: Data, keyBlob: Data)? {
        switch self.behavior {
        case .cannotGenerate: return nil
        case .oversizedBlob:  return (Data(repeating: 3, count: 1568), Data(repeating: 4, count: TierPQRecord.blobCapacity + 1))
        case .shortSecret:    return (Data(repeating: 3, count: 1568), Data(repeating: 4, count: 64))
        }
    }

    func decapsulate(ciphertext: Data, keyBlob: Data) -> Data? {
        self.behavior == .shortSecret ? Data(repeating: 5, count: 31) : Data(repeating: 5, count: 32)
    }

    func publicKey(forKeyBlob keyBlob: Data) -> Data? { nil }
}

/// `PostQuantumProvider`'s persistent-key methods, as share staging's `StagingPostQuantum` asks for them, over the
/// in-memory ML-KEM key. Nil below iOS 26.
nonisolated private struct InMemoryStagingPostQuantum: StagingPostQuantum {
    private let provider: any PostQuantumProvider

    init?() {
        guard let provider = PostQuantumProviderFactory.createForTesting() else { return nil }
        self.provider = provider
    }

    func generatePersistentKeyPair() -> (publicKeyData: Data, keyBlob: Data)? {
        self.provider.generatePersistentKeyPair()
    }

    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)? {
        self.provider.encapsulate(peerPublicKeyData: peerPublicKeyData)
    }

    func decapsulate(ciphertext: Data, keyBlob: Data) -> Data? {
        self.provider.decapsulate(ciphertext: ciphertext, keyBlob: keyBlob)
    }
}

/// A staging provider that can't make a key.
nonisolated private struct RefusingStagingPostQuantum: StagingPostQuantum {
    func generatePersistentKeyPair() -> (publicKeyData: Data, keyBlob: Data)? { nil }
    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)? { nil }
    func decapsulate(ciphertext: Data, keyBlob: Data) -> Data? { nil }
}

// MARK: - The record

@Suite("Tier PQ record — format")
struct TierPQRecordTests {

    /// A hybrid record with a blob the size the Enclave's is on the Simulator.
    private static func hybrid(blobSize: Int = 4788) throws -> TierPQRecord {
        try TierPQRecord.hybrid(
            keyBlob:    Data((0..<blobSize).map { UInt8($0 % 251) }),
            ciphertext: Data((0..<1568).map { UInt8(($0 &* 7) % 256) })
        )
    }

    @Test("A record is 9,763 bytes whichever the mode and whatever the blob's length")
    func sizeIsTheSameInBothModes() throws {
        #expect(TierPQRecord.size == 1 + 2 + 8192 + 1568)
        #expect(TierPQRecord.size == 9763)

        #expect(try TierPQRecord.classical.encoded().count == TierPQRecord.size)
        #expect(try Self.hybrid().encoded().count == TierPQRecord.size)
        #expect(try Self.hybrid(blobSize: 1).encoded().count == TierPQRecord.size)
        #expect(try Self.hybrid(blobSize: TierPQRecord.blobCapacity).encoded().count == TierPQRecord.size)
    }

    @Test("The padded blob size leaves room over the 4,788 bytes measured on the Simulator")
    func capacityHasMargin() {
        let measured = 4788

        #expect(TierPQRecord.blobCapacity >= measured * 3 / 2)
        #expect(TierPQRecord.blobCapacity == ShareStagingKeyManager.PQRecord.blobCapacity)
        #expect(TierPQRecord.ciphertextSize == 1568)
    }

    @Test("A hybrid record encodes and decodes to itself, whatever the padding")
    func hybridRoundTrips() throws {
        let record = try Self.hybrid()
        let first  = try record.encoded()
        let second = try record.encoded()

        #expect(TierPQRecord(decoding: first) == record)
        #expect(TierPQRecord(decoding: second) == record)
        #expect(first != second, "the padding is random")
        #expect(first.first == 1)
    }

    @Test("A classical record decodes to classical with nothing in it, and is random after the mode byte")
    func classicalRoundTrips() throws {
        let first  = try TierPQRecord.classical.encoded()
        let second = try TierPQRecord.classical.encoded()

        let decoded = try #require(TierPQRecord(decoding: first))
        #expect(decoded == .classical)
        #expect(decoded.keyBlob.isEmpty && decoded.ciphertext.isEmpty)
        #expect(first.first == 0)
        #expect(first.dropFirst() != second.dropFirst())
    }

    @Test("Bytes that are not a record decode to nil")
    func rejectsWhatIsNotARecord() throws {
        let good = try Self.hybrid().encoded()

        #expect(TierPQRecord(decoding: Data()) == nil)
        #expect(TierPQRecord(decoding: good.dropLast()) == nil)
        #expect(TierPQRecord(decoding: good + Data([0])) == nil)

        var unknownMode = good
        unknownMode[0] = 2
        #expect(TierPQRecord(decoding: unknownMode) == nil)

        var zeroLength = good
        zeroLength[1] = 0
        zeroLength[2] = 0
        #expect(TierPQRecord(decoding: zeroLength) == nil)

        var overlong = good
        overlong[1] = UInt8((TierPQRecord.blobCapacity + 1) >> 8)
        overlong[2] = UInt8((TierPQRecord.blobCapacity + 1) & 0xFF)
        #expect(TierPQRecord(decoding: overlong) == nil)
    }

    @Test("A blob that doesn't fit, or a ciphertext of the wrong size, is refused and never cut")
    func hybridRefusesWhatDoesNotFit() {
        #expect(throws: TierPQRecord.CodecError.blobSize(0)) {
            try TierPQRecord.hybrid(keyBlob: Data(), ciphertext: Data(count: 1568))
        }
        #expect(throws: TierPQRecord.CodecError.blobSize(TierPQRecord.blobCapacity + 1)) {
            try TierPQRecord.hybrid(keyBlob: Data(count: TierPQRecord.blobCapacity + 1), ciphertext: Data(count: 1568))
        }
        #expect(throws: TierPQRecord.CodecError.ciphertextSize(1567)) {
            try TierPQRecord.hybrid(keyBlob: Data(count: 64), ciphertext: Data(count: 1567))
        }
    }

    @Test("The ciphertext size is an ML-KEM-1024 ciphertext's")
    func ciphertextSizeIsMLKEM1024s() throws {
        let provider = try inMemoryProvider()
        let pair     = try #require(provider.generatePersistentKeyPair())
        let sent     = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))

        #expect(sent.ciphertext.count == TierPQRecord.ciphertextSize)
        #expect(pair.publicKeyData.count == TierPQRecord.ciphertextSize)
    }

    @Test("Share staging's own copy of the codec has the same size and reads the app's records, and the reverse")
    func stagingCopyMatches() throws {
        #expect(ShareStagingKeyManager.PQRecord.size == TierPQRecord.size)
        #expect(ShareStagingKeyManager.PQRecord.blobCapacity == TierPQRecord.blobCapacity)
        #expect(ShareStagingKeyManager.PQRecord.ciphertextSize == TierPQRecord.ciphertextSize)

        let app = try Self.hybrid()
        let theirs = try #require(ShareStagingKeyManager.PQRecord(decoding: try app.encoded()))
        #expect(theirs.mode == .hybrid)
        #expect(theirs.keyBlob == app.keyBlob && theirs.ciphertext == app.ciphertext)

        let staging = try #require(ShareStagingKeyManager.PQRecord.hybrid(keyBlob: app.keyBlob, ciphertext: app.ciphertext))
        let ours    = try #require(TierPQRecord(decoding: try staging.encoded()))
        #expect(ours == app)
        #expect(try staging.encoded().count == TierPQRecord.size)

        #expect(ShareStagingKeyManager.PQRecord(decoding: try TierPQRecord.classical.encoded())?.mode == .classical)
        #expect(TierPQRecord(decoding: try ShareStagingKeyManager.PQRecord.classical.encoded()) == .classical)
    }
}

// MARK: - The hybrid derivation

@Suite("Hybrid Enclave-bound derivation — HKDF(ECDH(d, P) ‖ ss ‖ r)")
@MainActor
struct HybridDerivationTests {

    private static let record = try! TierPQRecord.hybrid(keyBlob: katPQSeed, ciphertext: katPQCiphertext)

    private static func derive(
        record: TierPQRecord?, provider: (any PostQuantumProvider)?, info: Data,
        classicalInfo: Data = unusedClassicalInfo, key: SecKey? = nil, fetched: UnsafeMutablePointer<Bool>? = nil
    ) throws -> SymmetricKey? {
        try Manager.Key().deriveEnclaveBound(
            secret:        { katSecret },
            record:        { record },
            provider:      provider,
            privateKey:    { fetched?.pointee = true; return key },
            classicalInfo: classicalInfo,
            hybridInfo:    info
        )
    }

    @Test("The in-memory key decapsulates the pinned ciphertext to the pinned secret")
    func pinnedSharedSecret() throws {
        let provider = try inMemoryProvider()

        #expect(provider.decapsulate(ciphertext: katPQCiphertext, keyBlob: katPQSeed) == katPQSharedSecret)
        #expect(katPQCiphertext.count == 1568)
    }

    @Test("Each hybrid key equals its pinned known answer, its CryptoKit rebuild, and the whole path through a record",
          arguments: katPQVectors.map { $0.name })
    func knownAnswer(name: String) throws {
        let vector = try #require(katPQVectors.first { $0.name == name })
        let key    = try softwareP256Key(scalar: katScalar)

        let direct: SymmetricKey
        if name == "share staging" {
            direct = try ShareStagingKeyManager.enclaveBoundKey(
                exchangingWith: key, secret: katSecret, postQuantum: (katPQSharedSecret, katPQCiphertext)
            )
        } else {
            direct = try #require(Manager.Key().deriveEnclaveBound(
                exchangingWith: key, secret: katSecret, postQuantum: (katPQSharedSecret, katPQCiphertext), info: vector.info
            ))
        }

        #expect(keyBytes(direct) == dataFromHex(vector.expected))
        #expect(keyBytes(direct) == (try rebuildHybrid(
            scalar: katScalar, secret: katSecret, sharedSecret: katPQSharedSecret, ciphertext: katPQCiphertext, info: vector.info
        )))

        // Secret, then record, then the provider's decapsulation, then the key.
        if name != "share staging" {
            let viaRecord = try #require(try Self.derive(record: Self.record, provider: try inMemoryProvider(), info: vector.info, key: key))
            #expect(viaRecord == direct)
        }
    }

    @Test("The hybrid and classical keys of the same Enclave key and secret differ, for every key")
    func hybridDiffersFromClassical() throws {
        let key = try softwareP256Key(scalar: katScalar)
        let provider = try inMemoryProvider()

        for (classical, hybrid) in zip(katVectors.map(\.info), [
            SaltInfo.kLocalDBEnclaveBoundPQKeyInfo, SaltInfo.kVaultEnclaveBoundPQKeyInfo, SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo,
            SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo, SaltInfo.kSecureModeWrapPQKeyInfo
        ]) {
            let asClassical = try #require(try Self.derive(record: .classical, provider: provider, info: hybrid, classicalInfo: classical, key: key))
            let asHybrid    = try #require(try Self.derive(record: Self.record, provider: provider, info: hybrid, classicalInfo: classical, key: key))

            #expect(asClassical != asHybrid)
        }
    }

    @Test("A classical record derives exactly the Stage 1 key: t ‖ r under the classical info")
    func classicalRecordIsTheStage1Key() throws {
        let key  = try softwareP256Key(scalar: katScalar)
        let info = SaltInfo.kLocalDBEnclaveBoundKeyInfo

        // Even with a provider on hand.
        let derived = try #require(try Self.derive(record: .classical, provider: try inMemoryProvider(), info: unusedClassicalInfo, classicalInfo: info, key: key))

        #expect(keyBytes(derived) == dataFromHex(katVectors[0].expected))
    }

    @Test("A tampered ciphertext gives a different key, not a chosen one and not an error")
    func tamperedCiphertext() throws {
        let key      = try softwareP256Key(scalar: katScalar)
        let provider = try inMemoryProvider()
        let info     = SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        let original = try #require(try Self.derive(record: Self.record, provider: provider, info: info, key: key))

        var tampered = katPQCiphertext
        tampered[100] ^= 0x01
        let record = try TierPQRecord.hybrid(keyBlob: katPQSeed, ciphertext: tampered)

        // ML-KEM rejects implicitly: a tampered c decapsulates to an unrelated secret, not to a failure.
        let changed = try #require(try Self.derive(record: record, provider: provider, info: info, key: key))
        #expect(changed != original)

        // And the ciphertext is in the info even if the secret were somehow kept.
        let sameSecret = try #require(Manager.Key().deriveEnclaveBound(
            exchangingWith: key, secret: katSecret, postQuantum: (katPQSharedSecret, tampered), info: info
        ))
        #expect(sameSecret != original)
    }

    @Test("A wrong key gives a different key; the record's blob is what binds it to this device")
    func differentBlobGivesADifferentKey() throws {
        let key      = try softwareP256Key(scalar: katScalar)
        let provider = try inMemoryProvider()
        let info     = SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        let original = try #require(try Self.derive(record: Self.record, provider: provider, info: info, key: key))

        let otherSeed = Data((0..<64).map { UInt8($0 &+ 1) })
        let record    = try TierPQRecord.hybrid(keyBlob: otherSeed, ciphertext: katPQCiphertext)

        let other = try #require(try Self.derive(record: record, provider: provider, info: info, key: key))
        #expect(other != original)
    }

    @Test("A hybrid record whose blob is corrupt gives nil, is never read as classical, and fetches no Enclave key")
    func corruptBlobGivesNil() throws {
        let key      = try softwareP256Key(scalar: katScalar)
        let provider = try inMemoryProvider()
        let info     = SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        let classical = unusedClassicalInfo
        // A blob of the wrong length: the in-memory provider, like the Enclave's, refuses it.
        let corrupt = try TierPQRecord.hybrid(keyBlob: Data(count: 63), ciphertext: katPQCiphertext)

        var fetched = false
        let refused = try Self.derive(record: corrupt, provider: provider, info: info, classicalInfo: classical, key: key, fetched: &fetched)
        #expect(refused == nil)
        #expect(!fetched)

        // The classical key from the same inputs exists, so nil is a refusal and not a missing input.
        #expect(try Self.derive(record: .classical, provider: provider, info: info, classicalInfo: classical, key: key) != nil)
    }

    @Test("A hybrid record on a device with no ML-KEM gives nil, never a classical key")
    func hybridWithoutAProviderGivesNil() throws {
        let key = try softwareP256Key(scalar: katScalar)
        var fetched = false

        let derived = try Self.derive(record: Self.record, provider: nil, info: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo, key: key, fetched: &fetched)
        #expect(derived == nil)
        #expect(!fetched)
    }

    @Test("A decapsulation that doesn't give 32 bytes gives nil")
    func wrongSizeSecretGivesNil() throws {
        let key = try softwareP256Key(scalar: katScalar)
        var fetched = false

        let derived = try Self.derive(record: Self.record, provider: FakePostQuantum(behavior: .shortSecret),
                                      info: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo, key: key, fetched: &fetched)
        #expect(derived == nil)
        #expect(!fetched)
    }

    @Test("A missing record gives nil and fetches no Enclave key; an unreadable one throws")
    func missingRecord() throws {
        let key = try softwareP256Key(scalar: katScalar)
        var fetched = false

        let derived = try Self.derive(record: nil, provider: try inMemoryProvider(), info: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo, key: key, fetched: &fetched)
        #expect(derived == nil)
        #expect(!fetched)

        struct Unreadable: Error {}
        #expect(throws: Unreadable.self) {
            try Manager.Key().deriveEnclaveBound(
                secret: { katSecret }, record: { throw Unreadable() }, provider: nil,
                privateKey: { fetched = true; return key },
                classicalInfo: SaltInfo.kLocalDBEnclaveBoundKeyInfo, hybridInfo: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
            )
        }
        #expect(!fetched)
    }

    @Test("Every hybrid info string is distinct from every other and from its classical string")
    func infoStrings() {
        let hybrid = [
            SaltInfo.kLocalDBEnclaveBoundPQKeyInfo, SaltInfo.kVaultEnclaveBoundPQKeyInfo, SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo,
            SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo, SaltInfo.kSecureModeWrapPQKeyInfo
        ]
        let classical = katVectors.prefix(5).map(\.info)

        #expect(Set(hybrid).count == hybrid.count)
        #expect(Set(hybrid).isDisjoint(with: classical))
        #expect(SaltInfo.kLocalDBEnclaveBoundPQKeyInfo      == Data("Occulta-v3-local-db-pq-2026".utf8))
        #expect(SaltInfo.kVaultEnclaveBoundPQKeyInfo        == Data("Occulta-v2-vault-pq-2026".utf8))
        #expect(SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo == Data("Occulta-v2-shard-custody-pq-2026".utf8))
        #expect(SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo == Data("Occulta-v2-restore-buffer-pq-2026".utf8))
        #expect(SaltInfo.kSecureModeWrapPQKeyInfo           == Data("Occulta-v2-secure-mode-pin-wrap-pq-2026".utf8))
    }
}

// MARK: - TestKeyManager

@Suite("TestKeyManager — the two modes of the Enclave-bound keys")
@MainActor
struct TestKeyManagerPostQuantumTests {

    @Test("A new mirror holds hybrid records where the OS has ML-KEM, and a hybrid key equals the CryptoKit rebuild")
    func hybridEqualsTheRebuild() throws {
        let manager = TestKeyManager()
        let record  = try #require(manager.tierPQRecordU)
        #expect(record.mode == .hybrid)
        #expect(manager.tierPQRecordB?.mode == .hybrid)
        #expect(manager.tierPQRecordU != manager.tierPQRecordB, "each tier has its own key")

        let provider = try inMemoryProvider()
        let shared   = try #require(provider.decapsulate(ciphertext: record.ciphertext, keyBlob: record.keyBlob))
        let secret   = try #require(manager.tierSecretU)
        let key      = try #require(try manager.enclaveBoundKey(.localDB))

        #expect(keyBytes(key) == (try rebuildHybrid(
            scalar: try scalarOf(manager.localDBPrivateKey), secret: secret, sharedSecret: shared,
            ciphertext: record.ciphertext, info: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        )))

        let vaultRecord = try #require(manager.tierPQRecordB)
        let vaultShared = try #require(provider.decapsulate(ciphertext: vaultRecord.ciphertext, keyBlob: vaultRecord.keyBlob))
        let vault       = try #require(try manager.enclaveBoundKey(.vault(LAContext())))
        #expect(keyBytes(vault) == (try rebuildHybrid(
            scalar: try scalarOf(manager.vaultPrivateKey), secret: try #require(manager.tierSecretB), sharedSecret: vaultShared,
            ciphertext: vaultRecord.ciphertext, info: SaltInfo.kVaultEnclaveBoundPQKeyInfo
        )))
    }

    @Test("The hybrid and classical keys of the same mirror differ")
    func modesDiffer() throws {
        let manager = TestKeyManager()
        let hybrid  = try #require(try manager.enclaveBoundKey(.shardCustody))

        manager.tierPQRecordU = .classical
        let classical = try #require(try manager.enclaveBoundKey(.shardCustody))

        #expect(hybrid != classical)
    }

    @Test("With no ML-KEM, a hybrid record gives nil and a new record is classical")
    func noPostQuantum() throws {
        let manager = TestKeyManager()
        manager.simulatesNoPostQuantum = true

        #expect(try manager.enclaveBoundKey(.localDB) == nil, "a hybrid record is never read as classical")
        #expect(manager.tierPQRecordU?.mode == .hybrid, "and reading it changed nothing")

        manager.tierPQRecordU = nil
        #expect(try manager.createTierPQRecordIfAbsent(.deviceUnlock))
        #expect(manager.tierPQRecordU == .classical)
        #expect(try manager.enclaveBoundKey(.localDB) != nil)
    }

    @Test("A missing record gives nil and nothing is written; the creator makes one once and never replaces it")
    func missingRecord() throws {
        let manager = TestKeyManager()
        manager.tierPQRecordU = nil
        manager.tierPQRecordB = nil

        #expect(try manager.enclaveBoundKey(.localDB) == nil)
        #expect(try manager.enclaveBoundKey(.vault(LAContext())) == nil)
        #expect(manager.tierPQRecordU == nil && manager.tierPQRecordB == nil)

        #expect(try manager.createTierPQRecordIfAbsent(.deviceUnlock))
        let created = try #require(manager.tierPQRecordU)
        #expect(try manager.createTierPQRecordIfAbsent(.deviceUnlock) == false)
        #expect(manager.tierPQRecordU == created)
        #expect(manager.tierPQRecordB == nil, "the tiers are independent")

        #expect(try manager.enclaveBoundKey(.localDB) != nil)
    }

    @Test("A tampered ciphertext in the record changes the key; each tier's record moves only its own keys")
    func tamperingAndTiers() throws {
        let manager = TestKeyManager()
        let local   = try #require(try manager.enclaveBoundKey(.localDB))
        let vault   = try #require(try manager.enclaveBoundKey(.vault(LAContext())))

        let record = try #require(manager.tierPQRecordU)
        var ciphertext = record.ciphertext
        ciphertext[0] ^= 0x01
        manager.tierPQRecordU = try TierPQRecord.hybrid(keyBlob: record.keyBlob, ciphertext: ciphertext)

        #expect(try manager.enclaveBoundKey(.localDB) != local)
        #expect(try manager.enclaveBoundKey(.vault(LAContext())) == vault)
    }
}

// MARK: - Keychain records

@Suite("Tier PQ records — Keychain items, on accounts of the test's own", .serialized)
@MainActor
struct TierPQRecordKeychainTests {

    private static func account() -> String { "test.tier.pq.\(UUID().uuidString)" }

    private static func rawItem(account: String, group: String? = nil) -> (data: Data, attributes: [String: Any])? {
        var query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      account,
            kSecReturnData as String:       true,
            kSecReturnAttributes as String: true
        ]
        if let group { query[kSecAttrAccessGroup as String] = group }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let dict = item as? [String: Any],
              let data = dict[kSecValueData as String] as? Data else { return nil }
        return (data, dict)
    }

    @Test("A classical record is created without a provider, and is the same size as a hybrid one")
    func classicalAndHybridAreTheSameSize() throws {
        let manager   = Manager.Key()
        let classical = Self.account()
        let hybrid    = Self.account()
        defer { _ = manager.deleteTierSecret(account: classical); _ = manager.deleteTierSecret(account: hybrid) }

        #expect(try manager.readTierPQRecord(account: classical) == nil)

        #expect(try manager.createTierPQRecordIfAbsent(account: classical, provider: nil))
        #expect(try manager.createTierPQRecordIfAbsent(account: hybrid, provider: try inMemoryProvider()))

        #expect(try manager.readTierPQRecord(account: classical)?.mode == .classical)
        let record = try #require(try manager.readTierPQRecord(account: hybrid))
        #expect(record.mode == .hybrid)
        #expect(record.keyBlob.count == 64 && record.ciphertext.count == 1568)

        let storedClassical = try #require(Self.rawItem(account: classical))
        let storedHybrid    = try #require(Self.rawItem(account: hybrid))
        #expect(storedClassical.data.count == TierPQRecord.size)
        #expect(storedHybrid.data.count == TierPQRecord.size)
        #expect(storedClassical.data.first == 0 && storedHybrid.data.first == 1)
        #expect(storedClassical.attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    @Test("An existing record is read, not replaced, and costs no new key")
    func existingRecordIsKept() throws {
        let manager = Manager.Key()
        let account = Self.account()
        defer { _ = manager.deleteTierSecret(account: account) }

        #expect(try manager.createTierPQRecordIfAbsent(account: account, provider: try inMemoryProvider()))
        let first = try #require(try manager.readTierPQRecord(account: account))

        // A provider that would throw if asked for a key: it isn't asked.
        #expect(try manager.createTierPQRecordIfAbsent(account: account, provider: FakePostQuantum(behavior: .cannotGenerate)) == false)
        #expect(try manager.readTierPQRecord(account: account) == first)
    }

    @Test("Two creators racing end with one record: the second add finds the first and reads it")
    func duplicateAddReturnsTheSameRecord() throws {
        let manager = Manager.Key()
        let account = Self.account()
        defer { _ = manager.deleteTierSecret(account: account) }

        let provider = try inMemoryProvider()
        func make() throws -> TierPQRecord {
            let pair = try #require(provider.generatePersistentKeyPair())
            let sent = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))
            return try TierPQRecord.hybrid(keyBlob: pair.keyBlob, ciphertext: sent.ciphertext)
        }
        let first  = try make()
        let second = try make()
        #expect(first != second)

        #expect(try manager.addTierPQRecord(first, account: account))
        #expect(try manager.addTierPQRecord(second, account: account) == false)
        #expect(try manager.addTierPQRecord(.classical, account: account) == false)
        #expect(try manager.readTierPQRecord(account: account) == first)
    }

    @Test("Reading a missing record returns nil and writes nothing")
    func readingWritesNothing() throws {
        let manager = Manager.Key()
        let account = Self.account()

        #expect(try manager.readTierPQRecord(account: account) == nil)
        #expect(Self.rawItem(account: account) == nil)
    }

    @Test("An item that isn't a record throws, is never replaced, and blocks the creator")
    func malformedItem() throws {
        let manager = Manager.Key()
        let account = Self.account()
        defer { _ = manager.deleteTierSecret(account: account) }

        SecItemAdd([
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrAccount as String:    account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String:      Data(repeating: 0x42, count: 100)
        ] as CFDictionary, nil)

        #expect(throws: Manager.Key.Errors.tierPQRecordUnreadable) { try manager.readTierPQRecord(account: account) }
        #expect(throws: Manager.Key.Errors.tierPQRecordUnreadable) { try manager.createTierPQRecordIfAbsent(account: account, provider: nil) }
        #expect(Self.rawItem(account: account)?.data.count == 100)
    }

    @Test("A provider that can't make the key, or whose blob doesn't fit, throws and stores nothing")
    func creationFailureStoresNothing() throws {
        let manager = Manager.Key()
        let account = Self.account()
        defer { _ = manager.deleteTierSecret(account: account) }

        #expect(throws: Manager.Key.Errors.postQuantumKeyUnavailable) {
            try manager.createTierPQRecordIfAbsent(account: account, provider: FakePostQuantum(behavior: .cannotGenerate))
        }
        #expect(throws: Manager.Key.Errors.postQuantumKeyUnavailable) {
            try manager.createTierPQRecordIfAbsent(account: account, provider: FakePostQuantum(behavior: .oversizedBlob))
        }
        #expect(Self.rawItem(account: account) == nil, "no classical record is left in their place")
    }

    @Test("deleteTierSecret removes a record, and a missing one counts as deleted")
    func deleting() throws {
        let manager = Manager.Key()
        let account = Self.account()

        try manager.createTierPQRecordIfAbsent(account: account, provider: nil)
        #expect(manager.deleteTierSecret(account: account))
        #expect(Self.rawItem(account: account) == nil)
        #expect(manager.deleteTierSecret(account: account))
    }

    @Test("The canonical creators write the accounts named for them, one record each, at the full size",
          .enabled(if: secureEnclaveAvailable()))
    func canonicalAccountsHoldTheRecords() throws {
        let manager = Manager.Key()

        // These are the records Stage 2's bootstrap creates; this Simulator is left holding them, as it is left
        // holding `r_U`. They are never replaced.
        try manager.createTierPQRecordIfAbsent(.deviceUnlock)
        try manager.createTierPQRecordIfAbsent(.vault)

        let deviceUnlock = try #require(Self.rawItem(account: "local.db.pq.key.occulta"))
        let vault        = try #require(Self.rawItem(account: "vault.pq.key.occulta"))

        #expect(deviceUnlock.data.count == TierPQRecord.size && vault.data.count == TierPQRecord.size)
        // A plain item, `WhenUnlockedThisDeviceOnly`: the vault's gate is on `r_B`, not on its record.
        #expect(deviceUnlock.attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        #expect(vault.attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        let deviceUnlockRecord = try #require(try manager.tierPQRecord(.deviceUnlock))
        let vaultRecord        = try #require(try manager.tierPQRecord(.vault))
        #expect(deviceUnlockRecord.mode == vaultRecord.mode)
        if deviceUnlockRecord.mode == .hybrid {
            #expect(deviceUnlockRecord != vaultRecord, "one key per tier")
        }
    }

    @Test("A real Enclave ML-KEM record: created, read back, decapsulates the same secret twice, and derives a hybrid key",
          .enabled(if: enclaveMLKEMAvailable()))
    func realEnclaveRoundTrip() throws {
        guard #available(iOS 26, *) else { return }

        let manager  = Manager.Key()
        let account  = Self.account()
        let provider = try #require(PostQuantumProviderFactory.create())
        defer { _ = manager.deleteTierSecret(account: account) }

        #expect(try manager.createTierPQRecordIfAbsent(account: account, provider: provider))
        let record = try #require(try manager.readTierPQRecord(account: account))

        #expect(record.mode == .hybrid)
        #expect(!record.keyBlob.isEmpty && record.keyBlob.count <= TierPQRecord.blobCapacity)
        #expect(record.ciphertext.count == TierPQRecord.ciphertextSize)
        #expect(Self.rawItem(account: account)?.data.count == TierPQRecord.size)

        // The Enclave decapsulates the same ciphertext to the same secret each time.
        let first  = try #require(provider.decapsulate(ciphertext: record.ciphertext, keyBlob: record.keyBlob))
        let second = try #require(provider.decapsulate(ciphertext: record.ciphertext, keyBlob: record.keyBlob))
        #expect(first == second && first.count == 32)

        // And the derivation through the stored record uses it.
        let key     = try softwareP256Key(scalar: katScalar)
        let hybrid  = try #require(try manager.deriveEnclaveBound(
            secret: { katSecret }, record: { try manager.readTierPQRecord(account: account) }, provider: provider,
            privateKey: { key },
            classicalInfo: SaltInfo.kLocalDBEnclaveBoundKeyInfo, hybridInfo: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        ))
        #expect(keyBytes(hybrid) == (try rebuildHybrid(
            scalar: katScalar, secret: katSecret, sharedSecret: first, ciphertext: record.ciphertext,
            info: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
        )))
        #expect(keyBytes(hybrid) != dataFromHex(katVectors[0].expected))
    }
}

// MARK: - Share staging

@Suite("Share staging — its own PQ record and ML-KEM seam", .serialized)
@MainActor
struct StagingPostQuantumTests {

    private static let group = "group.com.occulta.shared"

    @MainActor
    private struct Accounts {
        let secret = "test.staging.secret.\(UUID().uuidString)"
        let record = "test.staging.pq.\(UUID().uuidString)"

        func manager(postQuantum: @escaping () -> (any StagingPostQuantum)?) -> ShareStagingKeyManager {
            ShareStagingKeyManager(tierSecretAccount: self.secret, tierPQRecordAccount: self.record, postQuantum: postQuantum)
        }

        func clean() {
            let manager = self.manager { nil }
            manager.deleteTierSecret()
            manager.deleteTierPQRecord()
        }
    }

    private static func raw(account: String) -> (data: Data, attributes: [String: Any])? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  Self.group,
            kSecReturnData as String:       true,
            kSecReturnAttributes as String: true
        ] as CFDictionary, &item)
        guard status == errSecSuccess, let dict = item as? [String: Any], let data = dict[kSecValueData as String] as? Data else { return nil }
        return (data, dict)
    }

    @Test("The record is created in the shared group, hybrid with a provider and classical without, at one size")
    func createsTheRecord() throws {
        let hybridAccounts = Accounts(), classicalAccounts = Accounts()
        defer { hybridAccounts.clean(); classicalAccounts.clean() }

        let hybrid    = hybridAccounts.manager { InMemoryStagingPostQuantum() }
        let classical = classicalAccounts.manager { nil }

        #expect(try hybrid.tierPQRecord() == nil)
        #expect(try hybrid.createTierPQRecordIfAbsent())
        #expect(try classical.createTierPQRecordIfAbsent())

        let hybridRecord = try #require(try hybrid.tierPQRecord())
        #expect(hybridRecord.mode == .hybrid)
        #expect(hybridRecord.keyBlob.count == 64 && hybridRecord.ciphertext.count == 1568)
        #expect(try classical.tierPQRecord()?.mode == .classical)

        let storedHybrid    = try #require(Self.raw(account: hybridAccounts.record))
        let storedClassical = try #require(Self.raw(account: classicalAccounts.record))
        #expect(storedHybrid.data.count == TierPQRecord.size && storedClassical.data.count == TierPQRecord.size)
        #expect(storedHybrid.attributes[kSecAttrAccessGroup as String] as? String == Self.group)
        #expect(storedHybrid.attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)

        // Never replaced.
        #expect(try hybrid.createTierPQRecordIfAbsent() == false)
        #expect(try hybrid.tierPQRecord() == hybridRecord)
    }

    @Test("Two creators racing end with one record")
    func duplicateAddReturnsTheSameRecord() throws {
        let accounts = Accounts()
        defer { accounts.clean() }
        let manager = accounts.manager { InMemoryStagingPostQuantum() }

        let first  = try #require(ShareStagingKeyManager.PQRecord.hybrid(keyBlob: katPQSeed, ciphertext: katPQCiphertext))
        let second = ShareStagingKeyManager.PQRecord.classical

        #expect(try manager.addTierPQRecord(first))
        #expect(try manager.addTierPQRecord(second) == false)
        #expect(try manager.tierPQRecord() == first)
    }

    @Test("A provider that can't make the key stores nothing; an item that isn't a record throws")
    func failures() throws {
        let accounts = Accounts()
        defer { accounts.clean() }

        let manager = accounts.manager { RefusingStagingPostQuantum() }
        #expect(throws: ShareStagingKeyManager.KeyError.postQuantumUnavailable) { try manager.createTierPQRecordIfAbsent() }
        #expect(Self.raw(account: accounts.record) == nil, "no classical record in its place")

        SecItemAdd([
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrAccount as String:     accounts.record,
            kSecAttrAccessGroup as String: Self.group,
            kSecAttrAccessible as String:  kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String:       Data(repeating: 0x42, count: 100)
        ] as CFDictionary, nil)
        #expect(throws: ShareStagingKeyManager.KeyError.tierPQRecordUnreadable) { try manager.tierPQRecord() }
        #expect(throws: ShareStagingKeyManager.KeyError.tierPQRecordUnreadable) { try manager.createTierPQRecordIfAbsent() }
    }

    @Test("Without its record the derivation throws before it fetches the Enclave key, and a read creates nothing")
    func missingRecord() throws {
        let accounts = Accounts()
        defer { accounts.clean() }
        let manager = accounts.manager { InMemoryStagingPostQuantum() }

        try manager.createTierSecretIfAbsent()
        #expect(throws: ShareStagingKeyManager.KeyError.tierPQRecordMissing) { try manager.deriveEnclaveBoundKey() }
        #expect(try manager.tierPQRecord() == nil)
    }

    @Test("A hybrid record never derives a classical key: no ML-KEM, or a corrupt blob, throws")
    func hybridFailuresThrow() throws {
        let accounts = Accounts()
        defer { accounts.clean() }
        let withMLKEM = accounts.manager { InMemoryStagingPostQuantum() }
        try withMLKEM.createTierSecretIfAbsent()
        try withMLKEM.createTierPQRecordIfAbsent()

        // Same items, on a device with no ML-KEM.
        let without = accounts.manager { nil }
        #expect(throws: ShareStagingKeyManager.KeyError.postQuantumFailed) { try without.deriveEnclaveBoundKey() }

        // A blob the provider refuses.
        accounts.manager { nil }.deleteTierPQRecord()
        let corrupt = try #require(ShareStagingKeyManager.PQRecord.hybrid(keyBlob: Data(count: 63), ciphertext: katPQCiphertext))
        try withMLKEM.addTierPQRecord(corrupt)
        #expect(throws: ShareStagingKeyManager.KeyError.postQuantumFailed) { try withMLKEM.deriveEnclaveBoundKey() }
    }

    @Test("The hybrid and classical keys differ, and two instances on the same items agree on the key",
          .enabled(if: secureEnclaveAvailable()))
    func modesDifferAndInstancesAgree() throws {
        let hybridAccounts = Accounts()
        defer { hybridAccounts.clean() }

        // The same r_S for both; only the record differs.
        let hybrid = hybridAccounts.manager { InMemoryStagingPostQuantum() }
        try hybrid.createTierSecretIfAbsent()
        try hybrid.createTierPQRecordIfAbsent()
        let hybridKey = keyBytes(try hybrid.deriveEnclaveBoundKey())

        // The app and the extension: separate instances over the same items.
        let other = hybridAccounts.manager { InMemoryStagingPostQuantum() }
        #expect(keyBytes(try other.deriveEnclaveBoundKey()) == hybridKey)

        let classicalAccounts = Accounts()
        defer { classicalAccounts.clean() }
        let classical = ShareStagingKeyManager(
            tierSecretAccount: hybridAccounts.secret, tierPQRecordAccount: classicalAccounts.record, postQuantum: { nil }
        )
        try classical.createTierPQRecordIfAbsent()
        #expect(try classical.tierPQRecord()?.mode == .classical)
        #expect(keyBytes(try classical.deriveEnclaveBoundKey()) != hybridKey)
    }

    @Test("A real Enclave ML-KEM staging record: created in the group, derives the same hybrid key from two instances",
          .enabled(if: enclaveMLKEMAvailable()))
    func realEnclaveRoundTrip() throws {
        guard #available(iOS 26, *) else { return }

        let accounts = Accounts()
        defer { accounts.clean() }

        // The default seam: the Secure Enclave's ML-KEM.
        let first = ShareStagingKeyManager(tierSecretAccount: accounts.secret, tierPQRecordAccount: accounts.record)
        try first.createTierSecretIfAbsent()
        #expect(try first.createTierPQRecordIfAbsent())

        let record = try #require(try first.tierPQRecord())
        #expect(record.mode == .hybrid)
        #expect(!record.keyBlob.isEmpty && record.keyBlob.count <= TierPQRecord.blobCapacity)
        #expect(Self.raw(account: accounts.record)?.data.count == TierPQRecord.size)

        let second = ShareStagingKeyManager(tierSecretAccount: accounts.secret, tierPQRecordAccount: accounts.record)
        let a = keyBytes(try first.deriveEnclaveBoundKey())
        let b = keyBytes(try second.deriveEnclaveBoundKey())
        #expect(a == b)

        // Sealed with one instance, opened by the other: what the extension and the app need.
        let sealed = try AES.GCM.seal(Data("staged".utf8), using: SymmetricKey(data: a))
        #expect(try AES.GCM.open(sealed, using: SymmetricKey(data: b)) == Data("staged".utf8))
    }
}
