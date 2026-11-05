//
//  PairwiseConversationTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave: prekeys are Enclave blobs, generated as each phone's refills come due.
//
//  Bug 196, stage 2, end to end: two phones whose pairing was made with pair keys exchange real bundles through
//  `ContactManager.encryptBundle` and `openGroup`. The first message is long-term, sealed with the pair-key ECDH; the next
//  ones are forward-secret, with the pair signing key's signature. Which phone is "this device" is the `Manager.Ambient`
//  task-local, bound per call (as `PrekeyConversationTests` does). Pair keys are software keys behind `SoftwareCardKeys`.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

@MainActor
private final class Phone {
    let keyManager = TestKeyManager()
    let override: Manager.Ambient.Override
    let contactManager: ContactManager
    let contactID: String

    init(contactID: String) throws {
        self.override = Manager.Ambient.Override(self.keyManager)
        self.contactID = contactID
        let schema = Schema([
            Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        self.contactManager = ContactManager(
            modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()),
            pairKeys: SoftwareCardKeys()
        )
    }

    func run<Result>(_ body: () throws -> Result) throws -> Result {
        try Manager.Ambient.$override.withValue(self.override) { try body() }
    }

    /// The other phone as a contact recorded at the pairing tier, holding `state`.
    func add(_ other: Phone, state: PairingState) throws {
        try self.run {
            let profile = Contact.Profile(
                identifier: self.contactID, givenName: "", familyName: "", middleName: "",
                nickname: "", organizationName: "", departmentName: "", jobTitle: ""
            )
            let key = Contact.Profile.Key(
                material: try Manager.Crypto().encrypt(data: try other.keyManager.retrieveIdentity()),
                owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
            )
            try self.contactManager.store(state, in: key)
            profile.contactPublicKeys = [key]
            let tier = try #require(OccultaBundle.Version.pairingCapable.wireByte)
            profile.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([tier]))
            profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(.empty).encrypt()
            try self.contactManager.insertProfile(profile)
        }
    }

    var contact: Contact.Profile {
        get throws { try #require(try self.contactManager.fetchContact(by: self.contactID)) }
    }

    func setState(_ state: PairingState) throws {
        try self.run { try self.contactManager.store(state, in: try #require(try self.contact.currentKey)) }
    }

    func send() throws -> Data {
        try self.run { try self.contactManager.encryptBundle(basket: Basket(files: []), for: self.contactID) }
    }

    func receive(_ encoded: Data) throws {
        try self.run {
            _ = try self.contactManager.openGroup(bundle: try OccultaBundle.decoded(from: encoded), ownerID: self.contactID)
        }
    }
}

private func mode(of encoded: Data) throws -> OccultaBundle.Mode? {
    try OccultaBundle.decoded(from: encoded).group?.recipients.first?.secrecyContext.mode
}

@MainActor
@Suite("Bug 196 — a pair-key conversation", .serialized)
struct PairwiseConversationTests {

    private let routingKey = Data(repeating: 0x42, count: 32)

    /// Two phones, each holding the other as a pair-key pairing with one shared routing key.
    private func pair(aliceState: ((PairKeys) -> PairingState)? = nil) throws -> (alice: Phone, bob: Phone, keys: PairKeyFixtureLike) {
        let alice = try Phone(contactID: "bob"), bob = try Phone(contactID: "alice")
        let keys = try PairKeyFixtureLike()
        try alice.add(bob, state: aliceState?(keys.alice) ?? .paired(routingKey: self.routingKey, keys: keys.alice))
        try bob.add(alice, state: .paired(routingKey: self.routingKey, keys: keys.bob))
        return (alice, bob, keys)
    }

    @Test("Every message opens on the other phone: long-term first, then forward-secret", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func conversationOpens() throws {
        let (alice, bob, _) = try self.pair()
        var modes = [OccultaBundle.Mode]()

        for _ in 0..<4 {
            let fromAlice = try alice.send()
            try bob.receive(fromAlice)
            modes.append(try #require(try mode(of: fromAlice)))

            let fromBob = try bob.send()
            try alice.receive(fromBob)
            modes.append(try #require(try mode(of: fromBob)))
        }

        #expect(modes.first == .longTermNoPQ, "no prekey of theirs yet")
        #expect(modes.contains { $0 == .forwardSecretNoPQ || $0 == .forwardSecret }, "a forward-secret message was signed by the pair key and verified: \(modes)")
        // Both pairings still hold the pair keys and the routing key, unchanged by the conversation.
        #expect(try alice.run { alice.contactManager.pairingState(for: try alice.contact).keys } != nil)
        #expect(try bob.run { bob.contactManager.pairingState(for: try bob.contact).secret } == self.routingKey)
    }

    @Test("A forward-secret file signed by the identity key is refused by a pair-key pairing", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func identityKeySignatureIsRefused() throws {
        let (alice, bob, _) = try self.pair()
        // Get both phones past the first long-term message so Alice holds one of Bob's prekeys.
        try bob.receive(try alice.send())
        try alice.receive(try bob.send())
        try bob.receive(try alice.send())
        try alice.receive(try bob.send())

        // Alice now seals as a plain pairing would: the routing key, but the identity key and no pair keys.
        try alice.setState(.derived(secret: self.routingKey))
        let file = try alice.send()
        let kind = try #require(try mode(of: file))
        try #require(kind == .forwardSecretNoPQ || kind == .forwardSecret)

        #expect(throws: GroupDecryptError.senderEphemeralSignatureMismatch) { try bob.receive(file) }
    }

    @Test("A forward-secret file signed by the pair key is refused by a pairing that has no pair keys", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func pairKeySignatureIsNotTheIdentityKeys() throws {
        let (alice, bob, _) = try self.pair()
        try bob.receive(try alice.send())
        try alice.receive(try bob.send())
        try bob.receive(try alice.send())
        try alice.receive(try bob.send())

        let file = try alice.send()
        let kind = try #require(try mode(of: file))
        try #require(kind == .forwardSecretNoPQ || kind == .forwardSecret)

        // Bob holds the routing key but no pair keys, so he checks the signature against the identity key.
        try bob.setState(.derived(secret: self.routingKey))
        #expect(throws: GroupDecryptError.senderEphemeralSignatureMismatch) { try bob.receive(file) }
    }
}

/// Mirrored pair keys for two phones.
private struct PairKeyFixtureLike {
    let alice: PairKeys
    let bob: PairKeys

    init() throws {
        let provider = SoftwareCardKeys()
        let aa = try provider.makeAgreementKey(), asig = try provider.makeSigningKey()
        let ba = try provider.makeAgreementKey(), bsig = try provider.makeSigningKey()
        self.alice = PairKeys(
            ourAgreementBlob: aa.blob, ourAgreementKey: aa.publicKey, ourSigningBlob: asig.blob, ourSigningKey: asig.publicKey,
            peerAgreementKey: ba.publicKey, peerSigningKey: bsig.publicKey, ourMLDSABlob: nil, peerMLDSAKey: nil
        )
        self.bob = PairKeys(
            ourAgreementBlob: ba.blob, ourAgreementKey: ba.publicKey, ourSigningBlob: bsig.blob, ourSigningKey: bsig.publicKey,
            peerAgreementKey: aa.publicKey, peerSigningKey: asig.publicKey, ourMLDSABlob: nil, peerMLDSAKey: nil
        )
    }
}
