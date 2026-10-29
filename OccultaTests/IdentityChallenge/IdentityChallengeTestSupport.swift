//
//  IdentityChallengeTestSupport.swift
//  OccultaTests
//
//  A phone, a clock and Alice for the identity-challenge tests that move between depths (`bugs.md` Bug 180).
//  No Secure Enclave: `TestKeyManager` for Secure Mode, and `.ambientTestKeyManager` on the tests for the rest.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

/// A clock the test moves. The coordinator, the manager and Alice's phone all read it.
@MainActor
final class ChallengeClock {
    var seconds: TimeInterval = 1_700_000_000
    var date: Date { Date(timeIntervalSince1970: self.seconds) }
}

/// What a person looking at the screen could tell, after one step.
struct ChallengeObservation: Equatable {
    var step: String
    var outcomePassed: Bool?
    var outcomeNote: String?
    var badge: String?
    var waiting: Bool
    var createError: String?
    var errorMessage: String?
    var sharing: Bool
}

@MainActor
struct ChallengePhone {
    let coordinator: IdentityChallenge.Coordinator
    let contacts: ContactManager
    let security: Manager.Security
    let clock: ChallengeClock
    let container: ModelContainer
    let keys: TestKeyManager
    /// Whether Secure Mode is on, so a restart knows to ask for a PIN.
    let secureMode: Bool

    /// - Parameter depth: nil is Secure Mode off; 0 is the real layer with Secure Mode on; 1 is the duress layer.
    init(depth: Int?, clock: ChallengeClock) throws {
        let schema = Schema([
            AppLayerConfig.self, Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self, Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self, Contact.Profile.Key.self, VaultEntry.self,
        ])
        let container = try ModelContainer(
            for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
        )
        let keys = TestKeyManager()
        let security = Manager.Security(modelContainer: container, keyManager: keys)
        let contacts = ContactManager(modelContainer: container, security: security)
        if let depth {
            try security.configurePIN("111111")
            try security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
            if depth == 1 { try Self.unlock("999999", on: security) }
            #expect(security.currentDepth == depth)
        } else {
            #expect(security.currentDepth == 0)
        }
        self.coordinator = IdentityChallenge.Coordinator(ledger: contacts, sealer: contacts, now: { clock.date })
        self.contacts = contacts
        self.security = security
        self.clock = clock
        self.container = container
        self.keys = keys
        self.secureMode = depth != nil
    }

    /// The process dies and the app starts again over the same store: new `Security`, `ContactManager` and
    /// `Coordinator`, nothing in memory, and the PIN entered again (`pin` is nil with Secure Mode off).
    func restarted(enteringPIN pin: String?) throws -> ChallengePhone {
        ChallengePhone(restartingOver: self, enteringPIN: pin)
    }

    private init(restartingOver old: ChallengePhone, enteringPIN pin: String?) {
        let security = Manager.Security(modelContainer: old.container, keyManager: old.keys)
        let contacts = ContactManager(modelContainer: old.container, security: security)
        if let pin { try? Self.unlock(pin, on: security) }
        let clock = old.clock
        self.coordinator = IdentityChallenge.Coordinator(ledger: contacts, sealer: contacts, now: { clock.date })
        self.contacts = contacts
        self.security = security
        self.clock = clock
        self.container = old.container
        self.keys = old.keys
        self.secureMode = old.secureMode
    }

    static func unlock(_ pin: String, on security: Manager.Security) throws {
        security.applyVerifyState(for: try security.verify(pin))
    }

    func unlock(_ pin: String) throws {
        try Self.unlock(pin, on: self.security)
    }

    /// What `RootView.endSession` clears on a lock or a depth change.
    func endSession() {
        self.coordinator.outboundShare       = nil
        self.coordinator.incomingChallenge   = nil
        self.coordinator.verificationOutcome = nil
    }

    func observe(_ step: String, createError: Error? = nil) -> ChallengeObservation {
        ChallengeObservation(
            step: step,
            outcomePassed: self.coordinator.verificationOutcome?.passed,
            outcomeNote: self.coordinator.verificationOutcome?.contextNote,
            badge: self.coordinator.verifiedBadge(for: "alice", now: self.clock.date),
            waiting: self.contacts.hasOutstanding(for: "alice", now: self.clock.date),
            createError: createError.map { String(describing: $0) },
            errorMessage: self.coordinator.errorMessage,
            sharing: self.coordinator.outboundShare != nil
        )
    }
}

/// Alice's phone: she holds her own key, answers whatever we send her, and has no ledger entry of her own.
@MainActor
struct ChallengeAlice {
    let keys = TestKeyManager()
    let clock: ChallengeClock
    let envelope = IdentityChallengeEnvelope.response(payload: Data())

    /// ChallengeAlice, stored on `contacts`: the challenge state is a column on her row.
    func profile(in contacts: ContactManager) throws -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: "alice", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: try self.keys.retrieveIdentity()),
            owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]
        contacts.modelContext.insert(profile)
        try contacts.modelContext.save()
        return profile
    }

    /// ChallengeAlice answers the challenge in the share sheet now.
    func answer(_ coordinator: IdentityChallenge.Coordinator) throws -> OccultaBundle {
        let file = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: file) }
        let manager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.keys), ledger: IdentityChallenge.OutstandingChallengeStore(),
            now: { [clock = self.clock] in clock.date }
        )
        let pending = try manager.decryptChallenge(
            bundle: try OccultaBundle.decoded(from: try Data(contentsOf: file)),
            senderKey: try Manager.Ambient.keyManager.retrieveIdentity(), senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        return try manager.respond(to: pending)
    }

    /// A response to a challenge this phone never sent: the stray reply of the sequence.
    func strayAnswer() throws -> OccultaBundle {
        let elsewhere = IdentityChallenge.Manager(
            crypto: Manager.Crypto(), ledger: IdentityChallenge.OutstandingChallengeStore(), now: { [clock = self.clock] in clock.date }
        )
        let challenge = try elsewhere.createChallenge(
            recipientKey: try self.keys.retrieveIdentity(), recipientQuantum: nil, contactID: "alice"
        )
        let manager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.keys), ledger: IdentityChallenge.OutstandingChallengeStore(),
            now: { [clock = self.clock] in clock.date }
        )
        let pending = try manager.decryptChallenge(
            bundle: challenge, senderKey: try Manager.Ambient.keyManager.retrieveIdentity(), senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        return try manager.respond(to: pending)
    }
}

