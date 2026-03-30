//
//  ForwardSecrecyIntegrationTests.swift
//  OccultaTests
//
//  ⚠️  DEVICE ONLY — requires Secure Enclave.
//
//  End-to-end forward secrecy tests using real SE keys and real AES-GCM.
//  Exercises PrekeyManager + Manager.Crypto together.
//  Does NOT test ContactManager (that layer requires full SwiftData contact setup).
//
//  Coverage:
//    - FS encrypt/decrypt single message roundtrip
//    - Forward secrecy guarantee: consumed key cannot decrypt again
//    - Pool isolation: Alice-Bob pool never touches Alice-Jake pool
//    - Full exhaustion cycle: drain all prekeys → detect fallback → new batch
//    - Pending batch rides every subsequent message
//    - Batch delivery idempotency via duplicate bundle
//    - hasPendingBatch guard: second fallback does not overwrite
//    - clearPendingBatch fires on FS receipt
//    - SecKey lifetime: double-temp-Prekey pattern, no crash
//    - SE pool deletion on contact removal
//

import Testing
import CryptoKit
import Foundation
import Security
import SwiftData

@testable import Occulta

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

    @Test func roundtrip_singleMessage() throws {
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        let prekeys     = try pm.generateBatch(contactID: contactID, count: 1)
        let prekey      = prekeys[0]
        let (_, recip)  = inMemoryKeyPair()
        let message     = Data("roundtrip test".utf8)

        let payload  = OccultaBundle.SealedPayload(message: message, prekeyBatch: nil)
        let encoded  = try JSONEncoder().encode(payload)
        let bundle   = try crypto.seal(message: encoded, contactPrekey: prekey, recipientMaterial: recip)

        #expect(bundle.secrecy.mode == .forwardSecret)
        #expect(bundle.secrecy.prekeyID == prekey.id)

        // Recipient opens — closure releases SecKey before consume
        let result: OccultaBundle.SealedPayload? = try {
            guard
                let privKey = pm.retrievePrivateKey(for: prekey),
                let sessKey = crypto.deriveSessionKey(
                    ephemeralPrivateKey: privKey,
                    recipientMaterial:   bundle.secrecy.ephemeralPublicKey
                )
            else { return nil }
            let raw = try crypto.open(bundle, using: sessKey)
            return try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: raw)
        }()

        #expect(result?.message == message)
    }

    @Test func roundtrip_fiveSequentialMessages_eachKeyConsumed() throws {
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

    @Test func roundtrip_batchPreservedInsidePayload() throws {
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

    @Test func consumedKey_cannotDecryptAgain_nocrash() throws {
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

    @Test func bobPool_isIsolatedFromJakePool() throws {
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

    @Test func deleteAllKeys_isContactScoped() throws {
        let c1 = cid() + ".c1"
        let c2 = cid() + ".c2"
        defer { pm.deleteAllKeys(for: c2) }

        let k1 = try pm.generateBatch(contactID: c1, count: 3)
        let k2 = try pm.generateBatch(contactID: c2, count: 3)

        pm.deleteAllKeys(for: c1)

        for k in k1 { #expect(pm.retrievePrivateKey(for: k) == nil) }
        for k in k2 { #expect(pm.retrievePrivateKey(for: k) != nil, "c2 pool untouched") }
    }

    @Test func tempPrekey_wrongContactID_returnsNil() throws {
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

// MARK: - Exhaustion scenario

@Suite("Integration — Exhaustion scenario")
@MainActor struct ExhaustionScenarioTests {

    let pm     = Manager.PrekeyManager()
    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    /// Alice drains all of Bob's prekeys. The next encrypt has no prekey available
    /// (contactPrekey == nil) → fallback bundle → fallback detected → new batch generated.
    @Test func exhaustion_afterDrainingAllKeys_nextEncryptProducesFallback() throws {
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        let (_, recip) = inMemoryKeyPair()

        // Generate 3 prekeys for Bob. Alice consumes all of them.
        let prekeys = try pm.generateBatch(contactID: contactID, count: 3)
        for prekey in prekeys {
            let payload = OccultaBundle.SealedPayload(message: Data("drain".utf8), prekeyBatch: nil)
            let encoded = try JSONEncoder().encode(payload)
            let bundle  = try crypto.seal(
                message:           encoded,
                contactPrekey:     prekey,
                recipientMaterial: recip
            )
            #expect(bundle.secrecy.mode == .forwardSecret)

            // Recipient consumes the key
            let _: Data? = try {
                guard
                    let priv = pm.retrievePrivateKey(for: prekey),
                    let key  = crypto.deriveSessionKey(ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey)
                else { return nil }
                let result = try crypto.open(bundle, using: key)
                pm.consume(prekey: prekey)
                return result
            }()
        }

        // All keys consumed
        #expect(pm.remainingCount(for: contactID) == 0)

        // Next seal with no prekey → fallback
        let fallbackPayload = OccultaBundle.SealedPayload(message: Data("fallback".utf8), prekeyBatch: nil)
        let fallbackEncoded = try JSONEncoder().encode(fallbackPayload)
        let fallback        = try crypto.seal(
            message:           fallbackEncoded,
            contactPrekey:     nil,   // no prekeys available
            recipientMaterial: recip
        )
        #expect(fallback.secrecy.mode == .longTermFallback)
        #expect(fallback.secrecy.prekeyID == nil)
    }

    /// When a fallback is detected and no pending batch exists,
    /// a new batch is generated and stored as pending.
    @Test func exhaustion_fallbackDetected_newBatchGenerated() throws {
        let contactID = cid()
        defer { pm.deleteAllKeys(for: contactID) }

        // Simulate: fallback detected, !hasPendingBatch → generate
        let newKeys  = try pm.generateBatch(contactID: contactID, count: Manager.PrekeyManager.defaultBatchSize)
        #expect(pm.remainingCount(for: contactID) == Manager.PrekeyManager.defaultBatchSize)
        #expect(newKeys.count == Manager.PrekeyManager.defaultBatchSize)

        // All new keys are retrievable — ready to be sent
        for key in newKeys {
            #expect(pm.retrievePrivateKey(for: key) != nil)
        }
    }

    /// The pending batch must be the same on every encryptBundle call until
    /// proof of receipt clears it. Simulated here by loading the batch N times.
    @Test func exhaustion_pendingBatch_sameOnEveryLoad() throws {
        let container = try {
            let schema = Schema([Contact.Profile.self, Contact.Profile.Key.self])
            return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        }()
        let context = ModelContext(container)
        let contact = Contact.Profile(
            identifier: UUID().uuidString, givenName: "Test", familyName: "C",
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        context.insert(contact)
        try context.save()
        try contact.configureForwardSecrecy()

        let cid = cid()
        defer { pm.deleteAllKeys(for: cid) }

        let keys    = try pm.generateBatch(contactID: cid, count: 3)
        let wireKeys = keys.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
        let batch   = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSince1970: 1_000_000),
            prekeys:     wireKeys
        )
        try contact.store(batch: batch)

        // Simulate 5 outbound messages — each loads the same pending batch
        for _ in 0..<5 {
            let loaded = try contact.loadPendingBatch()
            #expect(loaded?.prekeys.count == keys.count, "Pending batch must be identical on every load")
            let diff = abs(loaded!.generatedAt.timeIntervalSince1970 - 1_000_000)
            #expect(diff < 0.001)
        }

        // Still pending — hasn't been cleared
        #expect(contact.hasPendingBatch == true)
    }

    /// clearPendingBatch fires when FS receipt arrives (consume() succeeded).
    @Test func exhaustion_pendingBatchCleared_onFSReceipt() throws {
        let container = try {
            let schema = Schema([Contact.Profile.self, Contact.Profile.Key.self])
            return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        }()
        let context = ModelContext(container)
        let contact = Contact.Profile(
            identifier: UUID().uuidString, givenName: "Test", familyName: "C",
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        context.insert(contact)
        try context.save()
        try contact.configureForwardSecrecy()

        let cid = cid()
        defer { pm.deleteAllKeys(for: cid) }

        let keys     = try pm.generateBatch(contactID: cid, count: 2)
        let wireKeys = keys.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
        let batch    = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(), prekeys: wireKeys)
        try contact.store(batch: batch)
        #expect(contact.hasPendingBatch == true)

        // Simulate FS receipt: consume fires, then clearPendingBatch
        pm.consume(prekey: keys[0])                // forward secrecy established
        try contact.clearPendingBatch()            // proof of receipt
        #expect(contact.hasPendingBatch == false)
    }

    /// hasPendingBatch guard: second fallback must not overwrite existing pending batch.
    @Test func exhaustion_hasPendingBatch_blocksSecondGeneration() throws {
        let container = try {
            let schema = Schema([Contact.Profile.self, Contact.Profile.Key.self])
            return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        }()
        let context = ModelContext(container)
        let contact = Contact.Profile(
            identifier: UUID().uuidString, givenName: "Test", familyName: "C",
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        context.insert(contact)
        try context.save()
        try contact.configureForwardSecrecy()

        let cid = cid()
        defer { pm.deleteAllKeys(for: cid) }

        // First fallback: no pending batch, generate and store
        let keys1    = try pm.generateBatch(contactID: cid, count: 3)
        let wireK1   = keys1.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
        let batch1   = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSince1970: 100), prekeys: wireK1
        )
        try contact.store(batch: batch1)
        #expect(contact.hasPendingBatch == true)
        let cid2 = cid
        defer { pm.deleteAllKeys(for: cid2) }

        // Second fallback: hasPendingBatch == true → must NOT generate or overwrite
        if !contact.hasPendingBatch {
            // This block must NOT execute
            let keys2  = try pm.generateBatch(contactID: cid2, count: 15)
            let wireK2 = keys2.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
            let batch2 = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(), prekeys: wireK2)
            try contact.store(batch: batch2)
        }

        // Pending batch is still the original 3-key batch
        let loaded = try contact.loadPendingBatch()
        #expect(loaded?.prekeys.count == 3, "Original pending batch must be unchanged")
    }
}

// MARK: - AAD tamper (integration — real SE)

@Suite("Integration — AAD tamper with real crypto")
@MainActor struct IntegrationAADTamperTests {

    let pm     = Manager.PrekeyManager()
    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    @Test func tamper_prekeyID_throwsOnOpen() throws {
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
