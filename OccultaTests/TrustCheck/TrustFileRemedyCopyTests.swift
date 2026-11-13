//
//  TrustFileRemedyCopyTests.swift
//  OccultaTests
//
//  The "A file won't open" scenario stays generic on purpose: the same "not addressed to you" alert appears
//  when a file arrives at a duress depth (forensic-trace-avoidance.md C2), so the explanation Trust Check gives
//  must be the alert's, reason for reason. Both read `FileNotOpenedCopy`.
//
//  Since 2026-11-07 there are four reasons, the fourth being a file sent from a phone a contact no longer uses.
//  A separate message for that case must not be added: it could only appear if the app searched old keys, and
//  its appearance would tell whoever delivers a file that such a contact exists at this depth.
//

import Testing
@testable import Occulta

@MainActor
@Suite("Trust Check — a file that won't open")
struct TrustFileRemedyCopyTests {

    /// Each reason as the remedy and the alert word it.
    private let reasons: [(name: String, remedy: String, alert: String)] = [
        ("damaged",                    "Damaged",                     "corrupted"),
        ("needs a newer app",          "needs a newer app",           "update the app"),
        ("not addressed to you",       "encrypted for someone else",  "not addressed to you"),
        ("a phone no longer in use",   "sent from a phone a contact no longer uses", "sent from a phone one of your contacts no longer uses"),
    ]

    @Test("The remedy gives all four reasons")
    func remedyGivesEveryReason() {
        for reason in self.reasons {
            #expect(FileNotOpenedCopy.remedy.contains(reason.remedy), "remedy lacks “\(reason.name)”")
        }
    }

    @Test("The alert gives all four reasons")
    func alertGivesEveryReason() {
        for reason in self.reasons {
            #expect(FileNotOpenedCopy.alert.contains(reason.alert), "alert lacks “\(reason.name)”")
        }
    }

    @Test("The alert is the approved wording")
    func alertIsTheApprovedWording() {
        #expect(FileNotOpenedCopy.alert == "Could not find this file's owner's public key. It is either corrupted and you need to update the app and try again, the message was not addressed to you, or it was sent from a phone one of your contacts no longer uses.")
    }

    @Test("The scenario's remedy screen shows the remedy text, whoever the contact is")
    func scenarioShowsTheRemedy() {
        let content = TrustRemedy.explain(.fileWontOpen).content(for: .fileWontOpen, status: .pending, name: nil)

        #expect(content.steps == [FileNotOpenedCopy.remedy])
        #expect(content.heading == "A file won't open")
    }

    @Test("The remedy tells a contact who changed phones to send again, and not to trust a same-way explanation")
    func remedyAdvice() {
        #expect(FileNotOpenedCopy.remedy.contains("ask them to send it again once you've exchanged keys"))
        #expect(FileNotOpenedCopy.remedy.contains("Don't trust an explanation that arrives the same way."))
    }
}
