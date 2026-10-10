//
//  ForwardSecrecyIntegrationTests.swift
//  OccultaTests
//
//  ⚠️  DEVICE ONLY — requires Secure Enclave.
//
//  End-to-end forward secrecy tests using real SE keys and real AES-GCM.
//  Exercises PrekeyManager + Manager.Crypto together.
//  Does NOT test ContactManager (that layer requires full SwiftData contact setup). The batch
//  replenishment cycle it drives is tested through it in `PrekeyReplenishmentTriggerTests`.
//
//  Coverage:
//    - FS encrypt/decrypt single message roundtrip
//    - Forward secrecy guarantee: consumed key cannot decrypt again
//    - Pool isolation: Alice-Bob pool never touches Alice-Jake pool
//    - Batch delivery idempotency via duplicate bundle
//    - SecKey lifetime: double-temp-Prekey pattern, no crash
//    - SE pool deletion on contact removal
//

import Testing
import CryptoKit
import Foundation
import Security
import SwiftData

@testable import Occulta
@testable import OccultaFormats

/// True when this host can derive the real hybrid local DB key. False on GitHub-hosted CI
/// runners, which are VMs with no Secure Enclave. Tests gated on this report as *skipped*
/// rather than silently passing, so the size of the untested surface stays visible.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}


// MARK: - Shared helpers

private func inMemoryKeyPair() -> (privateKey: SecKey, publicKey: Data) {
    let attrs: NSDictionary = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
    ]
    var e: Unmanaged<CFError>?
    let priv = SecKeyCreateRandomKey(attrs, &e)!
    let pub  = SecKeyCopyPublicKey(priv)!
    return (priv, SecKeyCopyExternalRepresentation(pub, nil)! as Data)
}

private func cid() -> String { "inttest.\(UUID().uuidString)" }

/// Well-formed ML-KEM material for exercising the hybrid PQ path.
/// Contents are unstructured filler — `isValid` only requires correct byte counts.
private func testQuantumMaterial() -> QuantumKeyMaterial {
    QuantumKeyMaterial(
        encapsulatedSecret: Data(count: 32), decapsulatedSecret: Data(count: 32),
        ourCiphertext: Data(count: 32), peerCiphertext: Data(count: 32)
    )
}

/// Derive session key using the prekey private key and the bundle's ephemeral public key.
/// This mirrors what ContactManager.decrypt does on the recipient side.
private func deriveSessionKey(
    prekeyPrivateKey:    SecKey,
    ephemeralPublicKey:  Data,
    crypto:              Manager.Crypto
) -> SymmetricKey? {
    crypto.deriveSessionKey(
        ephemeralPrivateKey: prekeyPrivateKey,
        recipientMaterial:   ephemeralPublicKey
    )
}

/// Open a bundle and decode the SealedPayload. Mirrors ContactManager.decrypt steps 3-5.
private func openBundle(
    _ bundle:    OccultaBundle,
    prekeyPriv:  SecKey,
    crypto:      Manager.Crypto
) throws -> OccultaBundle.SealedPayload? {
    guard
        let sessKey = deriveSessionKey(
            prekeyPrivateKey:   prekeyPriv,
            ephemeralPublicKey: bundle.secrecy.ephemeralPublicKey,
            crypto:             crypto
        )
    else { return nil }
    let raw = try crypto.open(bundle, using: sessKey)
    return try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: raw)
}

// MARK: - FS roundtrip

@Suite("Integration — FS roundtrip")
@MainActor struct FSRoundtripTests {

    let pm     = Manager.PrekeyManager()
    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    @Test(.enabled(if: secureEnclaveAvailable())) func roundtrip_singleMessage() throws {
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        let prekeys     = try pm.generateBatch(contactID: contactID, count: 1)
        let prekey      = prekeys[0]
        let (_, recip)  = inMemoryKeyPair()
        let message     = Data("roundtrip test".utf8)
        let quantum     = testQuantumMaterial()

        let payload  = OccultaBundle.SealedPayload(message: message, prekeyBatch: nil)
        let encoded  = try JSONEncoder().encode(payload)
        let bundle   = try crypto.seal(message: encoded, contactPrekey: prekey, recipientMaterial: recip, quantumMaterial: quantum)

        #expect(bundle.secrecy.mode == .forwardSecret)
        #expect(bundle.secrecy.prekeyID == prekey.id)

        // Recipient opens — closure releases SecKey before consume
        let result: OccultaBundle.SealedPayload? = try {
            guard
                let privKey = pm.retrievePrivateKey(for: prekey),
                let sessKey = crypto.deriveSessionKey(
                    ephemeralPrivateKey: privKey,
                    recipientMaterial:   bundle.secrecy.ephemeralPublicKey,
                    quantumMaterial:     quantum
                )
            else { return nil }
            let raw = try crypto.open(bundle, using: sessKey)
            return try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: raw)
        }()

        #expect(result?.message == message)
    }

    @Test(.enabled(if: secureEnclaveAvailable())) func roundtrip_fiveSequentialMessages_eachKeyConsumed() throws {
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        let prekeys    = try pm.generateBatch(contactID: contactID, count: 5)
        let (_, recip) = inMemoryKeyPair()

        for (i, prekey) in prekeys.enumerated() {
            let msg     = Data("message \(i)".utf8)
            let payload = OccultaBundle.SealedPayload(message: msg, prekeyBatch: nil)
            let encoded = try JSONEncoder().encode(payload)
            let bundle  = try crypto.seal(message: encoded, contactPrekey: prekey, recipientMaterial: recip)

            let opened: Data? = try {
                guard
                    let priv = pm.retrievePrivateKey(for: prekey),
                    let key  = crypto.deriveSessionKey(ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey)
                else { return nil }
                return try crypto.open(bundle, using: key)
            }()
            #expect(opened != nil)

            pm.consume(prekey: prekey)
            #expect(pm.retrievePrivateKey(for: prekey) == nil, "Key \(i) must be consumed")
        }
    }

    @Test(.enabled(if: secureEnclaveAvailable())) func roundtrip_batchPreservedInsidePayload() throws {
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        let prekeys    = try pm.generateBatch(contactID: contactID, count: 1)
        let prekey     = prekeys[0]
        let (_, recip) = inMemoryKeyPair()

        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            prekeys: [
                OccultaBundle.WirePrekey(id: "pk1", publicKey: Data(repeating: 0x04, count: 65)),
                OccultaBundle.WirePrekey(id: "pk2", publicKey: Data(repeating: 0x05, count: 65))
            ]
        )
        let payload = OccultaBundle.SealedPayload(message: Data("msg".utf8), prekeyBatch: batch)
        let encoded = try JSONEncoder().encode(payload)
        let bundle  = try crypto.seal(message: encoded, contactPrekey: prekey, recipientMaterial: recip)

        let opened: OccultaBundle.SealedPayload? = try {
            guard
                let priv = pm.retrievePrivateKey(for: prekey),
                let key  = crypto.deriveSessionKey(ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey)
            else { return nil }
            let raw = try crypto.open(bundle, using: key)
            return try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: raw)
        }()

        #expect(opened?.prekeyBatch?.prekeys.count == 2)
        #expect(opened?.prekeyBatch?.prekeys.first?.id == "pk1")
        #expect(opened?.prekeyBatch?.prekeys.last?.id == "pk2")
    }
}

// MARK: - Forward secrecy guarantee

@Suite("Integration — Forward secrecy guarantee")
@MainActor struct ForwardSecrecyGuaranteeTests {

    let pm     = Manager.PrekeyManager()
    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    @Test(.enabled(if: secureEnclaveAvailable())) func consumedKey_cannotDecryptAgain_nocrash() throws {
        // ⚠️ CRASH CANDIDATE: consumed key must return nil, not crash.
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        let prekeys    = try pm.generateBatch(contactID: contactID, count: 1)
        let prekey     = prekeys[0]
        let (_, recip) = inMemoryKeyPair()

        let payload = OccultaBundle.SealedPayload(message: Data("once".utf8), prekeyBatch: nil)
        let encoded = try JSONEncoder().encode(payload)
        let bundle  = try crypto.seal(message: encoded, contactPrekey: prekey, recipientMaterial: recip)

        // First decrypt — succeeds
        let first: Data? = try {
            guard
                let priv = pm.retrievePrivateKey(for: prekey),
                let key  = crypto.deriveSessionKey(ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey)
            else { return nil }
            return try crypto.open(bundle, using: key)
        }()
        #expect(first != nil)
        pm.consume(prekey: prekey)

        // Second decrypt — key is gone, must return nil without crashing
        let second: Data? = try {
            guard
                let priv = pm.retrievePrivateKey(for: prekey),   // returns nil — key consumed
                let key  = crypto.deriveSessionKey(ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey)
            else { return nil }
            return try crypto.open(bundle, using: key)
        }()
        #expect(second == nil, "Consumed key must never decrypt again")
    }
}

// MARK: - Pool isolation

@Suite("Integration — Pool isolation")
@MainActor struct PoolIsolationTests {

    let pm     = Manager.PrekeyManager()
    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    @Test(.enabled(if: secureEnclaveAvailable())) func bobPool_isIsolatedFromJakePool() throws {
        let bobCID  = cid() + ".bob"
        let jakeCID = cid() + ".jake"
        defer { pm.deleteAllKeys(for: bobCID); pm.deleteAllKeys(for: jakeCID) }

        let bobKeys  = try pm.generateBatch(contactID: bobCID,  count: 3)
        let jakeKeys = try pm.generateBatch(contactID: jakeCID, count: 3)

        // Consume a Bob key
        pm.consume(prekey: bobKeys[0])

        // Bob's key is gone; Jake's are untouched
        #expect(pm.retrievePrivateKey(for: bobKeys[0])  == nil)
        #expect(pm.retrievePrivateKey(for: jakeKeys[0]) != nil, "Jake's key must be unaffected")
        #expect(pm.retrievePrivateKey(for: jakeKeys[1]) != nil)
        #expect(pm.retrievePrivateKey(for: jakeKeys[2]) != nil)
    }

    @Test(.enabled(if: secureEnclaveAvailable())) func deleteAllKeys_isContactScoped() throws {
        let c1 = cid() + ".c1"
        let c2 = cid() + ".c2"
        defer { pm.deleteAllKeys(for: c2) }

        let k1 = try pm.generateBatch(contactID: c1, count: 3)
        let k2 = try pm.generateBatch(contactID: c2, count: 3)

        pm.deleteAllKeys(for: c1)

        for k in k1 { #expect(pm.retrievePrivateKey(for: k) == nil) }
        for k in k2 { #expect(pm.retrievePrivateKey(for: k) != nil, "c2 pool untouched") }
    }

    @Test(.enabled(if: secureEnclaveAvailable())) func tempPrekey_wrongContactID_returnsNil() throws {
        // Verifies contactID scoping prevents cross-contact injection.
        let realCID  = cid() + ".real"
        let fakeCID  = cid() + ".fake"
        defer { pm.deleteAllKeys(for: realCID) }

        let keys = try pm.generateBatch(contactID: realCID, count: 1)
        let real = keys[0]

        // Attempt to retrieve real key using wrong contactID
        let injected = Prekey(id: real.id, contactID: fakeCID, publicKey: Data())
        #expect(pm.retrievePrivateKey(for: injected) == nil,
                "Wrong contactID must not retrieve another contact's SE key")
    }
}

// MARK: - AAD tamper (integration — real SE)

@Suite("Integration — AAD tamper with real crypto")
@MainActor struct IntegrationAADTamperTests {

    let pm     = Manager.PrekeyManager()
    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    @Test(.enabled(if: secureEnclaveAvailable())) func tamper_prekeyID_throwsOnOpen() throws {
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        let prekeys    = try pm.generateBatch(contactID: contactID, count: 1)
        let prekey     = prekeys[0]
        let (_, recip) = inMemoryKeyPair()

        let payload = OccultaBundle.SealedPayload(message: Data("test".utf8), prekeyBatch: nil)
        let encoded = try JSONEncoder().encode(payload)
        let bundle  = try crypto.seal(message: encoded, contactPrekey: prekey, recipientMaterial: recip)

        // Derive the correct session key before tampering
        let sessKey: SymmetricKey? = {
            guard
                let priv = pm.retrievePrivateKey(for: prekey),
                let key  = crypto.deriveSessionKey(ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey)
            else { return nil }
            pm.consume(prekey: prekey)
            return key
        }()
        guard let sessKey else {
            Issue.record("Could not derive session key"); return
        }

        // Tamper prekeyID in the bundle — AAD must change → GCM must fail
        let tampered = OccultaBundle(
            version: bundle.version,
            secrecy: OccultaBundle.SecrecyContext(
                mode:               bundle.secrecy.mode,
                ephemeralPublicKey: bundle.secrecy.ephemeralPublicKey,
                prekeyID:           "attacker-injected"
            ),
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        #expect(throws: (any Error).self) {
            try crypto.open(tampered, using: sessKey)
        }
    }
}
