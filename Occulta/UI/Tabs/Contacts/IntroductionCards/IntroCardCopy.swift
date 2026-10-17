//
//  IntroCardCopy.swift
//  Occulta
//
//  Every user-facing string of the introduction card flow. The wording is the
//  draft copy in Docs/Features/Introduction Cards/FINDINGS.md, referenced by
//  its W-number.
//
//  Each string is a pure function of explicit inputs: the other person's name
//  and, where a deadline is shown, a date. Nothing here reads the current
//  depth or any app state, so the same card shows the same text at every depth
//  (Prekey Continuity DESIGN.md §7).
//

import Foundation

nonisolated enum IntroCardCopy {

    /// A label and a description, shown together and always visible.
    nonisolated struct Message: Equatable, Sendable {
        let label: String
        let text:  String
    }

    // MARK: - Names

    /// What copy calls the person before a contact exists for them, such as a new contact being created at import.
    static let unknownSender = "the sender"

    /// The first word of a contact's name, which is what copy uses ("Carol", not "Carol Reyes").
    static func firstName(of fullName: String) -> String {
        let trimmed = fullName.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.components(separatedBy: .whitespaces).first ?? trimmed
    }

    /// The name to put in copy: the typed name, or "the sender" while there is none.
    static func name(_ typed: String?) -> String {
        let trimmed = (typed ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? Self.unknownSender : trimmed
    }

    /// The deadline as the mocks show it, such as "Oct 17, 2026 at 3:41 PM".
    static func date(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .shortened)
    }

    // MARK: - Section and availability

    static let sectionTitle = "INTRODUCTION CARD"

    /// Q-06. Create card and importing both say this on iOS 18.6–25, and claim nothing more.
    static let unavailable = Message(
        label: "Not available",
        text:  "Introduction cards need iOS 26 or later."
    )

    // MARK: - Issuer: pending contact, no card

    /// The card section on a pending contact with no card.
    static func pendingContactCard(name: String) -> String {
        "Can't meet \(name) yet? Make a card \(name) can use to send you a message. \(name) will stay Not verified until you meet and exchange keys in person."
    }

    static let createCardButton = "Create card"

    // MARK: - Issuer: create (W-01)

    static func createTitle(name: String) -> String {
        "Card for \(name)"
    }

    /// W-01. Shown where the card is created.
    static func createWarning(name: String, deadline: Date) -> Message {
        Message(
            label: "Before you make it",
            text:  "Anyone who gets this card before \(name) can use it and pretend to be \(name). Share it only with \(name). \(name)'s first message must reach you by \(Self.date(deadline)), or the card stops working. Making a new card cancels this one."
        )
    }

    static let factWorksLabel = "WORKS"
    static let factWorks      = "For one person: whoever sends the first message"

    static let factDeadlineLabel = "DEADLINE"
    static func factDeadline(name: String, deadline: Date) -> String {
        "\(name)'s first message must reach you by \(Self.date(deadline))"
    }

    static let factHoldsLabel = "HOLDS"
    static let factHolds      = "No name, no photo, no identity key"

    // MARK: - Issuer: share (W-02)

    static func shareTitle(name: String) -> String {
        "Share the card with \(name)"
    }

    /// W-02. Shown before the share sheet.
    static func shareWarning(name: String) -> Message {
        Message(
            label: "The app you share through",
            text:  "The app you send this through keeps a copy, possibly in its backups, and that app or the account could be compromised. Anyone who can read that chat could use the card before \(name) does. Once the card is used or expired, a leftover copy is useless."
        )
    }

    /// W-02's deadline, shown with it. The issuer's side of the deadline.
    static func issuerDeadline(name: String, deadline: Date) -> Message {
        Message(
            label: "\(name)'s deadline",
            text:  "\(name)'s first message must reach you by \(Self.date(deadline)). After that the card stops working, and you'd need to make a new one."
        )
    }

    static let shareCardButton = "Share card…"

    // MARK: - Issuer: active card (W-09)

    /// W-09. The active card on the contact's details.
    static func activeCard(name: String, deadline: Date) -> Message {
        Message(
            label: "Not used yet",
            text:  "\(name)'s first message must reach you by \(Self.date(deadline)), and then the card stops working. Until then, anyone who has this card can use it. Cancel it if it might have reached the wrong person."
        )
    }

    /// The note under the active card's actions (W-01's last sentence).
    static let newCardCancelsThis = "Making a new card cancels this one."

    static let cancelCardButton = "Cancel card"

    static func cancelCardTitle(name: String) -> String {
        "Cancel the card for \(name)?"
    }

    static let cancelCardMessage = "It stops working right away. You can make a new one."

    // MARK: - Issuer: first message arrives (W-08) and reply

    /// W-08.
    static func firstMessage(name: String) -> Message {
        Message(
            label: "First message on your card for \(name)",
            text:  "Whoever used the card first wrote it. That's probably \(name), but you can't be sure until you verify in person."
        )
    }

    /// The first-message view's button (decided 2026-10-16).
    static func replyButton(name: String) -> String {
        "Reply to \(name)"
    }

    /// The note under the reply button.
    static func replyNote(name: String) -> String {
        "Your reply also gives \(name) your prekeys, so \(name)'s next messages are forward-secret."
    }

    // MARK: - Issuer: Wasn't {Name}? (W-15)

    /// The heading above W-15's text; shown uppercased.
    static func wasntHeading(name: String) -> String {
        "Wasn't \(name)?"
    }

    /// W-15. Always visible.
    static func wasntText(name: String) -> String {
        "If \(name) never sent the first message you got, someone else used your card before \(name) could, and that's who you've been talking to. Discard this conversation and make \(name) a new card."
    }

    static let discardButton = "Discard conversation"

    /// W-15's confirmation.
    static func discardTitle(name: String) -> String {
        "Discard the conversation with \(name)?"
    }

    static func discardMessage(name: String) -> String {
        "Whoever used your card is cut off. \(name) goes back to pending, and you can make a new card."
    }

    static let discardConfirmButton = "Discard"

    // MARK: - Recipient: import (W-05, W-16, W-17)

    static let importTitle = "Import introduction card"

    /// W-05. Shown where the card is imported.
    static func importWarning(name: String) -> Message {
        Message(
            label: "Not verified",
            text:  "You know whose card this is only from the chat it arrived in. If that app or account was compromised, the card could have been swapped, and your messages would go to whoever swapped it. Be careful what you send until you meet \(name) and exchange keys in person."
        )
    }

    /// W-05's deadline, shown with it, and on the card contact before the first send. The recipient's side of the deadline.
    static func recipientDeadline(name: String, deadline: Date) -> Message {
        Message(
            label: "Must reach \(name) by \(Self.date(deadline))",
            text:  "Your first message has to reach \(name) by then, or the card stops working. Send it early enough for \(name) to open it in time. After that, there's no time limit."
        )
    }

    /// The main button of the import sheet (decided 2026-10-16).
    static func importAndWriteButton(name: String) -> String {
        "Import and write to \(name)"
    }

    static let importOnlyButton = "Import only"

    static let refusedLabel = "Can't import"

    /// W-16. The import is refused.
    static func refusedAlreadyTalking(name: String) -> Message {
        Message(
            label: Self.refusedLabel,
            text:  "You're already talking with \(name) through a card. Meet \(name) to verify instead."
        )
    }

    /// W-17. The import is refused because the user's own card wins on key order.
    static func refusedOwnCardWins(name: String) -> Message {
        Message(
            label: Self.refusedLabel,
            text:  "You already sent \(name) a card. Wait for \(name)'s message. \(name) needs to import your card."
        )
    }

    /// W-18. The import is refused because the card is the user's own.
    static func refusedOwnCard() -> Message {
        Message(label: Self.refusedLabel, text: "This is your own card.")
    }

    // MARK: - Recipient: waiting (W-07)

    /// W-07. After the first send.
    static func waitingForReply(name: String) -> Message {
        Message(
            label: "Waiting for the first reply",
            text:  "If none comes, someone may have used this card before you. Ask \(name) for a new card. It replaces this one."
        )
    }

    // MARK: - Trust (W-06)

    /// The chip's text. The chip shows it uppercased with a leading "!".
    static let notVerifiedChip = "Not verified"

    /// W-06. The first item of the card section on a Not verified contact.
    static let trustLine = Message(
        label: "Not verified",
        text:  "You haven't met and exchanged keys in person yet. If the app the card traveled through was compromised, someone else could be reading this conversation. Be careful what you send until you meet."
    )

    /// The contact list's Not verified footer.
    static let notVerifiedListFooter = "You haven't met and exchanged keys with these contacts in person yet. If the app a card traveled through was compromised, someone else could be reading that conversation."

    // MARK: - Blocked features (W-10)

    /// W-10. `feature` is capitalised, such as "Vault trustee".
    static func blockedFeature(feature: String, name: String) -> String {
        "\(feature) needs a contact you've verified in person, because it relies on knowing this key really is \(name)'s. Meet \(name) and exchange keys to verify."
    }

    // MARK: - In-person check (W-11, W-12)

    /// W-11. Needs an explicit acknowledgment (Q-10).
    static func exchangeMismatch(name: String) -> Message {
        Message(
            label: "Your earlier conversation was intercepted",
            text:  "Before today, you weren't messaging \(name). Someone swapped the card on its way and could read everything you sent. You're now connected to \(name), verified in person, and whoever was on the other end has been cut off."
        )
    }

    static let acknowledgeButton = "I understand"

    /// W-12.
    static func exchangeMatch(name: String) -> Message {
        Message(
            label: "Verified in person",
            text:  "Your earlier messages with \(name) went to this person."
        )
    }

    /// The exchange button on a Not verified contact.
    static func meetToVerifyTitle(name: String) -> String {
        "Meet \(name) to verify"
    }

    static let meetToVerifySubtitle = "exchange keys in person"

    // MARK: - Countdown and list lines

    /// "23h 12m 05s". Zero once the deadline has passed.
    static func remainingClock(until expiresAt: Date, now: Date) -> String {
        let total = max(0, Int(expiresAt.timeIntervalSince(now)))
        return String(format: "%dh %02dm %02ds", total / 3600, (total % 3600) / 60, total % 60)
    }

    /// "Expires in 23h 12m 05s". Live wherever a card is pending (decided 2026-10-16).
    static func countdown(until expiresAt: Date, now: Date) -> String {
        guard expiresAt > now else { return "Expired" }
        return "Expires in \(Self.remainingClock(until: expiresAt, now: now))"
    }

    /// The pending contact's second line on the issuer's phone: "Card · 23h 12m 05s".
    static func issuedListLine(expiresAt: Date, now: Date) -> String {
        "Card · \(Self.listClock(until: expiresAt, now: now))"
    }

    /// The card contact's second line on the recipient's phone, until the first message is sent: "Send by · 23h 12m 05s".
    static func sendByListLine(expiresAt: Date, now: Date) -> String {
        "Send by · \(Self.listClock(until: expiresAt, now: now))"
    }

    /// The full clock, or "Expired" past the deadline (decided 2026-10-17: the timer at all times).
    private static func listClock(until expiresAt: Date, now: Date) -> String {
        expiresAt > now ? Self.remainingClock(until: expiresAt, now: now) : "Expired"
    }
}
