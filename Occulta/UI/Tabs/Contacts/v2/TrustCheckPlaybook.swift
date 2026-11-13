//
//  TrustCheckPlaybook.swift
//  Occulta
//
//  What the Trust Check flow says, as plain values: eight scenarios, and for each one the remedy
//  that fits a contact's verification state. No view reads anything but these, so the whole table
//  in Docs/Features/Trust Check/trust-check-top-level.md is unit-testable without a SwiftUI hierarchy.
//
//  Everything here is shown at every depth, so none of it varies by depth, counts contacts, or
//  names Secure Mode, depths, trustees or shards. `TrustScenarioCopyTests` runs it all through the
//  same word list as `WhatsNewTests`.
//

import Foundation

// MARK: - Scenario

enum TrustScenario: CaseIterable, Hashable {
    case suspiciousMessage, lostPhone, newPhone, notVerified
    case strangerCard, fileWontOpen, signedText, other

    /// Whether the scenario is about one contact, so the flow asks which. The rest go straight to their remedy.
    var needsContact: Bool {
        switch self {
        case .suspiciousMessage, .lostPhone, .newPhone, .notVerified:
            true
        case .strangerCard, .fileWontOpen, .signedText, .other:
            false
        }
    }

    /// Whether the scenario is offered at all in this build. The signed-text scenario waits on the Verify tab,
    /// which varies by build, never by depth.
    var isOffered: Bool {
        self != .signedText || FeatureFlags.isEnabled(.signature)
    }

    /// Whether a contact in `status` is in this scenario's picker. Only Not verified narrows the list; the others
    /// list everyone and mark who they can't act on, because hiding a contact hides the advice they need most.
    func lists(status: VerificationStatus) -> Bool {
        self != .notVerified || status == .unverified
    }

    func lists(_ profile: Contact.Profile) -> Bool {
        self.lists(status: profile.verificationStatus)
    }

    /// `name` is the contact's name when the scenario is shown for one contact (contact detail, the remedy screen).
    func title(name: String? = nil) -> String {
        switch (self, name) {
        case (.suspiciousMessage, nil):       "Someone I know sent a suspicious call or message"
        case (.suspiciousMessage, let name?): "I got a suspicious call or message from \(name)"
        case (.lostPhone, nil):               "A contact's phone was lost or stolen"
        case (.lostPhone, let name?):         "\(name)'s phone was lost or stolen"
        case (.newPhone, nil):                "A contact says they have a new phone or number"
        case (.newPhone, let name?):          "\(name) says they have a new phone or number"
        case (.notVerified, nil):             "A contact shows Not verified"
        case (.notVerified, let name?):       "\(name) shows Not verified"
        case (.strangerCard, _):              "Someone I've never met sent me a card"
        case (.fileWontOpen, _):              "A file won't open"
        case (.signedText, _):                "Someone sent text they say a contact signed"
        case (.other, _):                     "Something else"
        }
    }

    var subtitle: String {
        switch self {
        case .suspiciousMessage: "Check it's really them"
        case .lostPhone:         "Stop trusting that phone's key"
        case .newPhone:          "Check the key you have first"
        case .notVerified:       "What it means and how to fix it"
        case .strangerCard:      "What a card lets them do"
        case .fileWontOpen:      "Why, and what not to trust"
        case .signedText:        "Check it against the keys on this phone"
        case .other:             "Someone wants money, access or details"
        }
    }

    /// The picker's heading.
    var pickerTitle: String {
        switch self {
        case .suspiciousMessage: "Who do they say they are?"
        case .lostPhone:         "Whose phone was lost or stolen?"
        case .newPhone:          "Who has a new phone or number?"
        case .notVerified:       "Which contact shows Not verified?"
        case .strangerCard, .fileWontOpen, .signedText, .other: self.title()
        }
    }

    /// What the picker says when no contact is listed. Read from visible contacts only.
    var emptyListText: String {
        self == .notVerified ? "No Not verified contacts" : "No contacts"
    }
}

// MARK: - Remedy

enum TrustRemedy: Equatable {
    case challenge, revoke, meetInPerson, alreadyVerified, explain(TrustScenario)

    /// The remedy for `scenario` when the contact's state is `status` and their key `canRevoke` (it hasn't already
    /// been revoked). Pure, so every cell of the table is a test.
    static func make(for scenario: TrustScenario, status: VerificationStatus, canRevoke: Bool) -> TrustRemedy {
        switch scenario {
        case .suspiciousMessage, .newPhone:
            status == .verified ? .challenge : .meetInPerson
        case .lostPhone:
            canRevoke ? .revoke : .meetInPerson
        case .notVerified:
            status == .verified ? .alreadyVerified : (canRevoke ? .revoke : .meetInPerson)
        case .strangerCard, .fileWontOpen, .signedText, .other:
            .explain(scenario)
        }
    }

    /// `profile` is nil when the scenario names no contact.
    static func make(for scenario: TrustScenario, profile: Contact.Profile?) -> TrustRemedy {
        guard scenario.needsContact, let profile else { return .explain(scenario) }

        return self.make(for: scenario, status: profile.verificationStatus, canRevoke: profile.trustCheckCanRevokeKey)
    }

    /// Whether the scenario's own action applies, so the row sorts above the divider.
    var actsOnContact: Bool { self == .challenge || self == .revoke }

    /// The picker row's line.
    func line(for scenario: TrustScenario, status: VerificationStatus) -> String {
        switch self {
        case .challenge:
            "Send a Challenge"
        case .revoke:
            "Revoke, then exchange in person"
        case .alreadyVerified:
            "Already verified in person"
        case .explain:
            ""
        case .meetInPerson:
            switch (scenario, status) {
            case (.suspiciousMessage, .pending): "Can't be challenged: no key yet"
            case (.suspiciousMessage, _):        "Can't be challenged: not verified in person"
            case (.newPhone, .pending):          "Exchange in person when you meet"
            case (.newPhone, _):                 "Meet and exchange in person"
            default:                             "Nothing to revoke. Exchange in person when you meet"
            }
        }
    }

    struct Content: Equatable {
        let heading: String
        /// One card each, numbered when there are several.
        let steps: [String]
        let footnote: String?
    }

    /// The remedy screen. `name` is the contact's name; nil for a scenario that names none.
    func content(for scenario: TrustScenario, status: VerificationStatus, name: String?) -> Content {
        let heading = scenario.title(name: name)
        let name = name ?? "them"

        switch self {
        case .explain(let scenario):
            return Content(heading: heading, steps: [scenario.explanation], footnote: nil)

        case .alreadyVerified:
            return Content(heading: heading, steps: ["\(name)'s key came from an in-person exchange. Nothing to do here."], footnote: nil)

        case .challenge:
            switch scenario {
            case .newPhone:
                return Content(heading: heading, steps: [
                    "Send \(name) a Challenge to the key you have. If it's approved, their old phone still works and the story is wrong.",
                    "If there's no answer, meet \(name), then revoke and exchange keys in person. Before you revoke, open any files they sent that you haven't opened: afterwards they won't open. Once you've exchanged keys, send again anything you sent before, since it won't open on their new phone.",
                ], footnote: nil)
            default:
                return Content(heading: heading, steps: ["Send \(name) a Challenge, through a different channel than the suspicious message."], footnote: nil)
            }

        case .revoke:
            switch scenario {
            case .notVerified:
                return Content(heading: heading, steps: ["Their key came by sharing or transfer. Revoke it here and exchange keys in person."], footnote: nil)
            default:
                return Content(heading: heading, steps: [
                    "Open any files \(name) sent you that you haven't opened yet. After you revoke, they won't open.",
                    "Revoke \(name)'s key. Occulta stops accepting anything from that phone, and you can't message each other until step 3.",
                    "Meet \(name) and exchange keys on their new phone. Then send again anything you sent before: it was made for their old phone and won't open on the new one.",
                ], footnote: "Anything you sent \(name) that they hadn't opened yet may still be readable on the lost phone by someone who can unlock it.")
            }

        case .meetInPerson:
            let afterExchange = "After you've exchanged keys, send again anything you sent before, and ask \(name) to send again anything you couldn't open."
            switch (scenario, status) {
            case (.suspiciousMessage, .pending):
                return Content(heading: heading, steps: ["There's no key to check against. Don't act on the request until you meet and exchange keys."], footnote: nil)
            case (.suspiciousMessage, _):
                return Content(heading: heading, steps: ["Occulta can't vouch for this key. Don't act on the request; meet \(name) in person."], footnote: nil)
            case (.newPhone, .pending):
                return Content(heading: heading, steps: ["Exchange keys in person when you meet.", afterExchange], footnote: nil)
            case (.newPhone, _):
                return Content(heading: heading, steps: ["Never accept a replacement key by message or card. Meet \(name) and exchange keys in person.", afterExchange], footnote: nil)
            case (.notVerified, _):
                return Content(heading: heading, steps: ["Nothing to revoke. Exchange keys in person when you meet \(name)."], footnote: nil)
            default:
                return Content(heading: heading, steps: [
                    "Nothing to revoke. Files \(name) sent from their old phone won't open. When you meet and exchange keys, send again anything you sent before, and ask \(name) to send again anything you couldn't open.",
                ], footnote: nil)
            }
        }
    }
}

extension TrustScenario {
    /// The remedy for a scenario that names no contact.
    fileprivate var explanation: String {
        switch self {
        case .strangerCard:
            "A card lets them write to you first. They stay Not verified until you meet in person."
        case .fileWontOpen:
            FileNotOpenedCopy.remedy
        case .signedText:
            "Verify checks it against the keys on this phone."
        case .other:
            "If anyone asks for money, access or personal details, check in person or send a Challenge first."
        case .suspiciousMessage, .lostPhone, .newPhone, .notVerified:
            ""
        }
    }
}

// MARK: - Revoke confirmation

nonisolated enum RevokeConfirmationCopy {
    static func title(name: String) -> String {
        "Revoke \(name)'s key?"
    }

    static let message = "Occulta will stop accepting anything from their current phone, and you won't be able to message them until you meet and exchange keys again. Files they sent that you haven't opened yet won't open afterwards. This can't be undone."

    static func button(name: String) -> String {
        "Revoke \(name)'s key"
    }
}

// MARK: - A file that won't open

/// Why a file doesn't open, said once. The alert `RootView` raises when no owner's key is found and the Trust Check
/// file remedy both read it, so the cover explanation can't drift from the message. The alert's text is the same for
/// any file addressed to nobody we hold a key for, which is why it reveals nothing about contacts at any depth: a
/// separate message for a file from a contact's old phone must not be added (`TrustFileRemedyCopyTests`).
nonisolated enum FileNotOpenedCopy {
    static let alert = "Could not find this file's owner's public key. It is either corrupted and you need to update the app and try again, the message was not addressed to you, or it was sent from a phone one of your contacts no longer uses."

    static let remedy = "Damaged, needs a newer app, encrypted for someone else, or sent from a phone a contact no longer uses. If a contact has changed phones, ask them to send it again once you've exchanged keys. Don't trust an explanation that arrives the same way."
}
