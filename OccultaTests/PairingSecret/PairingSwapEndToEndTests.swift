//
//  PairingSwapEndToEndTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave: prekeys are Enclave blobs, generated as each phone's refills come due.
//
//  Bug 196, stage 6, end to end: two phones whose pairing began before this fix, each with its own identity and store,
//  exchange real bundles through `ContactManager.encryptBundle` and `openGroup`. Which phone is "this device" is the
//  `Manager.Ambient` task-local, bound per call (as `PrekeyConversationTests` does). Every message must open on the other
//  phone, whichever form it is in, and the pairing must end holding one secret on both sides.
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
            modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        )
    }

    func run<Result>(_ body: () throws -> Result) throws -> Result {
        try Manager.Ambient.$override.withValue(self.override) { try body() }
    }

    /// The other phone as a contact recorded at the pairing-secret tier, with no secret yet: a pairing from before this fix.
    /// - Parameter pairingFieldFilled: false leaves the key row as an install from before this fix holds it, with nothing
    ///   in the pairing-secret column, for the launch migration to fill.
    func add(_ other: Phone, pairingFieldFilled: Bool = true) throws {
        try self.run {
            let profile = Contact.Profile(
                identifier: self.contactID, givenName: "", familyName: "", middleName: "",
                nickname: "", organizationName: "", departmentName: "", jobTitle: ""
            )
            let key = Contact.Profile.Key(
                material: try Manager.Crypto().encrypt(data: try other.keyManager.retrieveIdentity()),
                owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
            )
            if pairingFieldFilled { try self.contactManager.store(.empty, in: key) }
            profile.contactPublicKeys = [key]
            let tier = try #require(OccultaBundle.Version.pairingSecretCapable.wireByte)
            profile.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([tier]))
            profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(.empty).encrypt()
            try self.contactManager.insertProfile(profile)
        }
    }

    var contact: Contact.Profile {
        get throws { try #require(try self.contactManager.fetchContact(by: self.contactID)) }
    }

    var state: PairingSecretState {
        get throws { try self.run { self.contactManager.pairingSecretState(for: try self.contact) } }
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

@MainActor
@Suite("Bug 196 — the swap over an ordinary conversation", .serialized)
struct PairingSwapEndToEndTests {

    private func pair() throws -> (alice: Phone, bob: Phone) {
        let alice = try Phone(contactID: "bob"), bob = try Phone(contactID: "alice")
        try alice.add(bob)
        try bob.add(alice)
        return (alice, bob)
    }

    @Test("The first message, with no key of theirs to seal to, carries no half", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func firstMessageStartsNothing() throws {
        let (alice, bob) = try self.pair()
        try bob.receive(try alice.send())

        #expect(try alice.state == .empty, "a long-term slot opens again, so it is never a place for a half")
    }

    @Test("A conversation settles the swap: both phones hold one secret and send the new form",
          .enabled(if: TestSupport.secureEnclaveAvailable()))
    func conversationSettles() throws {
        let (alice, bob) = try self.pair()

        // Alice first (long-term: she holds no key of Bob's), then back and forth. Every message opens, in whichever form.
        for round in 0..<4 {
            try bob.receive(try alice.send())
            try alice.receive(try bob.send())
            _ = round
        }

        let a = try alice.state, b = try bob.state
        #expect(a.secret != nil && a.secret == b.secret)
        #expect(a.sendsNewForm && b.sendsNewForm)
        #expect(a.refusesOldForm && b.refusesOldForm, "once the peer's new-form file has arrived, a swapped pairing refuses the old form")
    }

    @Test("Once settled, a file is of the new form: random header, tagged slot", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func settledFilesAreNewForm() throws {
        let (alice, bob) = try self.pair()
        for _ in 0..<4 {
            try bob.receive(try alice.send())
            try alice.receive(try bob.send())
        }
        let secret = try #require(try alice.state.secret)

        let encoded = try alice.send()
        let bundle = try OccultaBundle.decoded(from: encoded)
        let aliceKey = try alice.keyManager.retrieveIdentity()

        #expect(bundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: aliceKey, nonce: bundle.fingerprintNonce))
        #expect(bundle.group?.recipients.first?.routingTag == PairingSecret.routingTag(secret: secret, nonce: bundle.fingerprintNonce))
        try bob.receive(encoded)
    }

    @Test("A lost answer is tolerated: the retry carries the same half and the swap still completes",
          .enabled(if: TestSupport.secureEnclaveAvailable()))
    func lostAnswer() throws {
        let (alice, bob) = try self.pair()

        // The two long-term messages that bootstrap a pair, each carrying the sender's first batch.
        try bob.receive(try alice.send())
        try alice.receive(try bob.send())

        // Alice's next message goes on one of Bob's one-time keys, so it carries her half: she is waiting for his.
        try bob.receive(try alice.send())
        guard case .swapping = try alice.state.phase else { Issue.record("Alice should be waiting for Bob's half"); return }
        let bobHolds = try bob.state
        #expect(bobHolds.secret != nil && !bobHolds.sendsNewForm)

        // Bob's answer is lost on the way.
        _ = try bob.send()
        #expect(try alice.state.secret == nil && !(try alice.state.sendsNewForm), "Alice still sends the old form")

        // His next message carries the same half and confirmation, and reaches her.
        try alice.receive(try bob.send())
        #expect(try bob.state.secret == bobHolds.secret, "the secret did not change between his sends")
        #expect(try alice.state.sendsNewForm)

        for _ in 0..<3 {
            try bob.receive(try alice.send())
            try alice.receive(try bob.send())
        }
        let a = try alice.state, b = try bob.state
        #expect(a.secret != nil && a.secret == b.secret)
        #expect(a.sendsNewForm && b.sendsNewForm)
    }

    // MARK: Migration: an install from before the change

    @Test("An install from before the change loses nothing: the migration fills the column, old-form files go out and open until the swap settles",
          .enabled(if: TestSupport.secureEnclaveAvailable()))
    func migrationLosesNothing() throws {
        let alice = try Phone(contactID: "bob"), bob = try Phone(contactID: "alice")
        try alice.add(bob, pairingFieldFilled: false)
        try bob.add(alice, pairingFieldFilled: false)

        // Before the launch migration the column is nil; code reads that as no secret, and the pairing works.
        try bob.receive(try alice.send())
        try alice.receive(try bob.send())

        let before = try alice.run { try alice.contact.prekeyRecordEncrypted }
        for phone in [alice, bob] {
            try phone.run { try DatabaseMigration.migratePairingSecretFields(modelContext: phone.contactManager.modelContext) }
        }
        #expect(try alice.run { try alice.contact.prekeyRecordEncrypted } == before, "the migration leaves the prekey record byte-identical")
        #expect(try alice.state == .empty && (try bob.state) == .empty)

        // The first message after it is still the old form: the identity fingerprint, until the swap completes.
        let encoded = try alice.send()
        let bundle = try OccultaBundle.decoded(from: encoded)
        #expect(bundle.senderFingerprint == OccultaBundle.SecrecyContext.fingerprint(
            for: try alice.keyManager.retrieveIdentity(), nonce: bundle.fingerprintNonce))
        try bob.receive(encoded)

        for _ in 0..<4 {
            try alice.receive(try bob.send())
            try bob.receive(try alice.send())
        }
        let a = try alice.state, b = try bob.state
        #expect(a.secret != nil && a.secret == b.secret)
        #expect(a.sendsNewForm && b.sendsNewForm)
    }
}
