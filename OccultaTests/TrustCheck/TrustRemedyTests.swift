//
//  TrustRemedyTests.swift
//  OccultaTests
//
//  The "Remedies by contact state" table of the Trust Check top-level design, cell by cell. `TrustRemedy.make`
//  is a pure function of scenario, verification status and whether the key can still be revoked, so none of this
//  needs a view, a contact, or an Enclave.
//

import Testing
@testable import Occulta

/// The states a contact can be in. A contact whose last key was revoked reads as Pending, and one with no key
/// can't be revoked; a card-only Not verified contact has no key either.
private let states: [(status: VerificationStatus, canRevoke: Bool)] = [
    (.verified, true), (.unverified, true), (.unverified, false), (.pending, false),
]

@MainActor
@Suite("Trust Check — remedy by scenario and contact state")
struct TrustRemedyTests {

    @Test("Suspicious call or message: Challenge a Verified contact, meet anyone else")
    func suspiciousMessage() {
        for state in states {
            let expected: TrustRemedy = state.status == .verified ? .challenge : .meetInPerson
            #expect(TrustRemedy.make(for: .suspiciousMessage, status: state.status, canRevoke: state.canRevoke) == expected, "\(state)")
        }
    }

    @Test("Lost or stolen phone: Revoke whenever there is a key to revoke")
    func lostPhone() {
        for state in states {
            let expected: TrustRemedy = state.canRevoke ? .revoke : .meetInPerson
            #expect(TrustRemedy.make(for: .lostPhone, status: state.status, canRevoke: state.canRevoke) == expected, "\(state)")
        }
    }

    @Test("New phone or number: Challenge a Verified contact, never accept a replacement key for anyone else")
    func newPhone() {
        for state in states {
            let expected: TrustRemedy = state.status == .verified ? .challenge : .meetInPerson
            #expect(TrustRemedy.make(for: .newPhone, status: state.status, canRevoke: state.canRevoke) == expected, "\(state)")
        }
    }

    @Test("A contact shows Not verified: Revoke the shared key; the other states are not offered")
    func notVerified() {
        #expect(TrustRemedy.make(for: .notVerified, status: .unverified, canRevoke: true) == .revoke)
        #expect(TrustRemedy.make(for: .notVerified, status: .unverified, canRevoke: false) == .meetInPerson)
        #expect(TrustRemedy.make(for: .notVerified, status: .verified, canRevoke: true) == .alreadyVerified)
        #expect(TrustRemedy.make(for: .notVerified, status: .pending, canRevoke: false) == .meetInPerson)
    }

    @Test("A scenario with no contact explains itself in every state")
    func scenariosWithoutAContact() {
        for scenario in TrustScenario.allCases where !scenario.needsContact {
            for state in states {
                #expect(TrustRemedy.make(for: scenario, status: state.status, canRevoke: state.canRevoke) == .explain(scenario))
            }
            #expect(TrustRemedy.make(for: scenario, profile: nil) == .explain(scenario))
        }
    }

    @Test("A contact scenario with no contact falls back to its explanation")
    func contactScenarioWithoutAContact() {
        for scenario in TrustScenario.allCases where scenario.needsContact {
            #expect(TrustRemedy.make(for: scenario, profile: nil) == .explain(scenario))
        }
    }

    @Test("Four scenarios need a contact and four don't")
    func needsContact() {
        #expect(TrustScenario.allCases.filter(\.needsContact) == [.suspiciousMessage, .lostPhone, .newPhone, .notVerified])
        #expect(TrustScenario.allCases.filter { !$0.needsContact }.count == 4)
    }

    @Test("Only the Not verified scenario narrows its list")
    func listsNarrowOnlyNotVerified() {
        for scenario in TrustScenario.allCases {
            for status in [VerificationStatus.verified, .unverified, .pending] {
                let expected = scenario != .notVerified || status == .unverified
                #expect(scenario.lists(status: status) == expected, "\(scenario) \(status)")
            }
        }
    }

    @Test("Only Challenge and Revoke sort above the divider")
    func actsOnContact() {
        #expect(TrustRemedy.challenge.actsOnContact)
        #expect(TrustRemedy.revoke.actsOnContact)
        #expect(!TrustRemedy.meetInPerson.actsOnContact)
        #expect(!TrustRemedy.alreadyVerified.actsOnContact)
        #expect(!TrustRemedy.explain(.other).actsOnContact)
    }

    @Test("The signed-text scenario is offered only when the Verify tab is")
    func signedTextFollowsTheFlag() {
        #expect(TrustScenario.signedText.isOffered == FeatureFlags.isEnabled(.signature))

        for scenario in TrustScenario.allCases where scenario != .signedText {
            #expect(scenario.isOffered)
        }
    }

    @Test("Every picker row says something for a contact scenario, and nothing for one without a contact")
    func rowLines() {
        for scenario in TrustScenario.allCases {
            for state in states {
                let remedy = TrustRemedy.make(for: scenario, status: state.status, canRevoke: state.canRevoke)
                let line = remedy.line(for: scenario, status: state.status)

                #expect(line.isEmpty == !scenario.needsContact, "\(scenario) \(state)")
            }
        }
    }

    @Test("The lost-phone remedy is the approved three steps and a footnote, naming the contact")
    func lostPhoneContent() {
        let content = TrustRemedy.revoke.content(for: .lostPhone, status: .verified, name: "Alex")

        #expect(content.heading == "Alex's phone was lost or stolen")
        #expect(content.steps == [
            "Open any files Alex sent you that you haven't opened yet. After you revoke, they won't open.",
            "Revoke Alex's key. Occulta stops accepting anything from that phone, and you can't message each other until step 3.",
            "Meet Alex and exchange keys on their new phone. Then send again anything you sent before: it was made for their old phone and won't open on the new one.",
        ])
        #expect(content.footnote == "Anything you sent Alex that they hadn't opened yet may still be readable on the lost phone by someone who can unlock it.")
    }

    @Test("A Pending contact's lost-phone remedy says there is nothing to revoke")
    func lostPhonePendingContent() {
        let content = TrustRemedy.meetInPerson.content(for: .lostPhone, status: .pending, name: "Alex")

        #expect(content.steps == [
            "Nothing to revoke. Files Alex sent from their old phone won't open. When you meet and exchange keys, send again anything you sent before, and ask Alex to send again anything you couldn't open.",
        ])
    }

    @Test("The new-phone remedies are the approved wording")
    func newPhoneContent() {
        let verified = TrustRemedy.challenge.content(for: .newPhone, status: .verified, name: "Alex")
        #expect(verified.steps.last == "If there's no answer, meet Alex, then revoke and exchange keys in person. Before you revoke, open any files they sent that you haven't opened: afterwards they won't open. Once you've exchanged keys, send again anything you sent before, since it won't open on their new phone.")

        let afterExchange = "After you've exchanged keys, send again anything you sent before, and ask Alex to send again anything you couldn't open."
        #expect(TrustRemedy.meetInPerson.content(for: .newPhone, status: .unverified, name: "Alex").steps.last == afterExchange)
        #expect(TrustRemedy.meetInPerson.content(for: .newPhone, status: .pending, name: "Alex").steps.last == afterExchange)
    }

    @Test("The revoke confirmation is the approved wording")
    func revokeConfirmation() {
        #expect(RevokeConfirmationCopy.title(name: "Alex") == "Revoke Alex's key?")
        #expect(RevokeConfirmationCopy.message == "Occulta will stop accepting anything from their current phone, and you won't be able to message them until you meet and exchange keys again. Files they sent that you haven't opened yet won't open afterwards. This can't be undone.")
    }
}
