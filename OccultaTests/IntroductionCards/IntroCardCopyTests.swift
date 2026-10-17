//
//  IntroCardCopyTests.swift
//  OccultaTests
//
//  The card flow's wording (`Docs/Features/Introduction Cards/FINDINGS.md`, Draft copy). The rules: name the person, never
//  "them" or "they", and "the sender" when there is no name yet. Each string is a function of explicit inputs only.
//

import Testing
import Foundation

@testable import Occulta

@Suite("Introduction card copy — wording rules")
struct IntroCardCopyTests {

    private let deadline = Date(timeIntervalSince1970: 1_800_000_000)
    private let now      = Date(timeIntervalSince1970: 1_799_916_475) // 23h 12m 05s before the deadline

    private func joined(_ message: IntroCardCopy.Message) -> String { message.label + "\n" + message.text }

    /// Every string that takes a name, with the name and a deadline where it takes one. `(description, string)`.
    private func namedStrings(_ name: String) -> [(String, String)] {
        let deadline = self.deadline
        var result: [(String, String)] = []
            result.append(("pendingContactCard", IntroCardCopy.pendingContactCard(name: name)))
            result.append(("createTitle", IntroCardCopy.createTitle(name: name)))
            result.append(("createWarning", self.joined(IntroCardCopy.createWarning(name: name, deadline: deadline))))
            result.append(("factDeadline", IntroCardCopy.factDeadline(name: name, deadline: deadline)))
            result.append(("shareTitle", IntroCardCopy.shareTitle(name: name)))
            result.append(("shareWarning", self.joined(IntroCardCopy.shareWarning(name: name))))
            result.append(("issuerDeadline", self.joined(IntroCardCopy.issuerDeadline(name: name, deadline: deadline))))
            result.append(("activeCard", self.joined(IntroCardCopy.activeCard(name: name, deadline: deadline))))
            result.append(("cancelCardTitle", IntroCardCopy.cancelCardTitle(name: name)))
            result.append(("firstMessage", self.joined(IntroCardCopy.firstMessage(name: name))))
            result.append(("replyButton", IntroCardCopy.replyButton(name: name)))
            result.append(("replyNote", IntroCardCopy.replyNote(name: name)))
            result.append(("wasntHeading", IntroCardCopy.wasntHeading(name: name)))
            result.append(("wasntText", IntroCardCopy.wasntText(name: name)))
            result.append(("discardTitle", IntroCardCopy.discardTitle(name: name)))
            result.append(("discardMessage", IntroCardCopy.discardMessage(name: name)))
            result.append(("importWarning", self.joined(IntroCardCopy.importWarning(name: name))))
            result.append(("recipientDeadline", self.joined(IntroCardCopy.recipientDeadline(name: name, deadline: deadline))))
            result.append(("importAndWriteButton", IntroCardCopy.importAndWriteButton(name: name)))
            result.append(("refusedAlreadyTalking", self.joined(IntroCardCopy.refusedAlreadyTalking(name: name))))
            result.append(("refusedOwnCardWins", self.joined(IntroCardCopy.refusedOwnCardWins(name: name))))
            result.append(("waitingForReply", self.joined(IntroCardCopy.waitingForReply(name: name))))
            result.append(("blockedFeature", IntroCardCopy.blockedFeature(feature: "Vault trustee", name: name)))
            result.append(("exchangeMismatch", self.joined(IntroCardCopy.exchangeMismatch(name: name))))
            result.append(("exchangeMatch", self.joined(IntroCardCopy.exchangeMatch(name: name))))
            result.append(("meetToVerifyTitle", IntroCardCopy.meetToVerifyTitle(name: name)))
            result.append(("refusedExpired", self.joined(IntroCardCopy.refusedExpired(name: name))))
            // Compose's secrecy line, shown for every contact: names in place of "they" too (decided 2026-10-17).
            for secrecy in [NextSendSecrecy.forwardSecret, .temporaryKey, .longTerm] {
                result.append(("secrecy \(secrecy)", SecrecyIndicator.description(secrecy, name: name)))
            }
        return result
    }

    /// Every string that takes no name.
    private var fixedStrings: [(String, String)] {
        var result: [(String, String)] = []
            result.append(("unknownSender", IntroCardCopy.unknownSender))
            result.append(("sectionTitle", IntroCardCopy.sectionTitle))
            result.append(("unavailable", self.joined(IntroCardCopy.unavailable)))
            result.append(("createCardButton", IntroCardCopy.createCardButton))
            result.append(("factWorksLabel", IntroCardCopy.factWorksLabel))
            result.append(("factWorks", IntroCardCopy.factWorks))
            result.append(("factDeadlineLabel", IntroCardCopy.factDeadlineLabel))
            result.append(("factHoldsLabel", IntroCardCopy.factHoldsLabel))
            result.append(("factHolds", IntroCardCopy.factHolds))
            result.append(("shareCardButton", IntroCardCopy.shareCardButton))
            result.append(("newCardCancelsThis", IntroCardCopy.newCardCancelsThis))
            result.append(("cancelCardButton", IntroCardCopy.cancelCardButton))
            result.append(("cancelCardMessage", IntroCardCopy.cancelCardMessage))
            result.append(("discardButton", IntroCardCopy.discardButton))
            result.append(("discardConfirmButton", IntroCardCopy.discardConfirmButton))
            result.append(("importTitle", IntroCardCopy.importTitle))
            result.append(("importOnlyButton", IntroCardCopy.importOnlyButton))
            result.append(("refusedLabel", IntroCardCopy.refusedLabel))
            result.append(("refusedOwnCard", self.joined(IntroCardCopy.refusedOwnCard())))
            result.append(("notACard", self.joined(IntroCardCopy.notACard)))
            result.append(("createFailed", self.joined(IntroCardCopy.createFailed)))
            result.append(("cancelFailed", self.joined(IntroCardCopy.cancelFailed)))
            result.append(("discardFailed", self.joined(IntroCardCopy.discardFailed)))
            result.append(("shareFailed", self.joined(IntroCardCopy.shareFailed)))
            result.append(("importFailed", self.joined(IntroCardCopy.importFailed)))
            result.append(("standardEncryptionLabel", IntroCardCopy.standardEncryptionLabel))
            result.append(("notVerifiedChip", IntroCardCopy.notVerifiedChip))
            result.append(("trustLine", self.joined(IntroCardCopy.trustLine)))
            result.append(("notVerifiedListFooter", IntroCardCopy.notVerifiedListFooter))
            result.append(("acknowledgeButton", IntroCardCopy.acknowledgeButton))
            result.append(("meetToVerifySubtitle", IntroCardCopy.meetToVerifySubtitle))
            result.append(("remainingClock", IntroCardCopy.remainingClock(until: self.deadline, now: self.now)))
            result.append(("countdown", IntroCardCopy.countdown(until: self.deadline, now: self.now)))
            result.append(("countdown, expired", IntroCardCopy.countdown(until: self.deadline, now: self.deadline)))
            result.append(("issuedListLine", IntroCardCopy.issuedListLine(expiresAt: self.deadline, now: self.now)))
            result.append(("sendByListLine", IntroCardCopy.sendByListLine(expiresAt: self.deadline, now: self.now)))
            result.append(("date", IntroCardCopy.date(self.deadline)))
        return result
    }

    // MARK: - The pronoun rule

    @Test("No string says them, they, their or theirs", arguments: ["Carol", "Carol Reyes", "the sender"])
    func noThirdPersonPlural(name: String) throws {
        let banned = try Regex(#"(?:^|[^A-Za-z])(?:them|they|their|theirs)(?:$|[^A-Za-z])"#).ignoresCase()
        let strings = self.namedStrings(name) + self.fixedStrings

        var offenders: [String] = []
        for (description, string) in strings where string.contains(banned) { offenders.append("\(description): \(string)") }
        #expect(offenders.isEmpty, "\(offenders)")
        #expect(strings.count > 50, "control: the list covers the strings")
    }

    @Test("Compose's secrecy line stands in a phrase for a contact with no given name")
    func secrecyWithoutName() {
        for secrecy in [NextSendSecrecy.forwardSecret, .temporaryKey, .longTerm] {
            #expect(SecrecyIndicator.description(secrecy, name: "").contains("the recipient"))
        }
    }

    @Test("The check can fail: the same expression finds the banned words")
    func pronounCheckDetects() throws {
        let banned = try Regex(#"(?:^|[^A-Za-z])(?:them|they|their|theirs)(?:$|[^A-Za-z])"#).ignoresCase()
        for sample in ["Tell them", "They said", "their card", "That is theirs.", "THEM", "they're here"] {
            #expect(sample.contains(banned), "\(sample)")
        }
        for sample in ["these contacts", "Carol's", "another", "theme", "other"] {
            #expect(!sample.contains(banned), "\(sample)")
        }
    }

    // MARK: - Names and dates

    @Test("Every function that takes a name includes it")
    func everyNamedStringIncludesTheName() {
        for (description, string) in self.namedStrings("Carol") {
            #expect(string.contains("Carol"), "\(description) doesn't name the person: \(string)")
        }
    }

    @Test("Where a name is given, no string falls back to the sender")
    func nameReplacesTheFallback() {
        for (description, string) in self.namedStrings("Carol") where string.contains("the sender") {
            Issue.record("\(description) says \"the sender\" for a named contact: \(string)")
        }
    }

    @Test("A different name changes the text, so the name is a parameter rather than a constant")
    func nameIsSubstituted() {
        let carol = self.namedStrings("Carol"), dave = self.namedStrings("Dave")
        for ((description, forCarol), (_, forDave)) in zip(carol, dave) {
            #expect(forCarol != forDave, "\(description)")
            #expect(forCarol.replacingOccurrences(of: "Carol", with: "Dave") == forDave, "\(description) differs by more than the name")
        }
    }

    @Test("Strings with a deadline show the same date and time the date helper gives")
    func deadlinesAreShown() {
        let shown = IntroCardCopy.date(self.deadline)
        #expect(IntroCardCopy.createWarning(name: "Carol", deadline: self.deadline).text.contains(shown))
        #expect(IntroCardCopy.factDeadline(name: "Carol", deadline: self.deadline).contains(shown))
        #expect(IntroCardCopy.issuerDeadline(name: "Carol", deadline: self.deadline).text.contains(shown))
        #expect(IntroCardCopy.activeCard(name: "Carol", deadline: self.deadline).text.contains(shown))
        #expect(IntroCardCopy.recipientDeadline(name: "Carol", deadline: self.deadline).label.contains(shown))
        #expect(!shown.isEmpty)
    }

    @Test("name(_:) gives the typed name, trimmed, or the sender when there is none")
    func nameFallback() {
        #expect(IntroCardCopy.name("") == "the sender")
        #expect(IntroCardCopy.name("   ") == "the sender")
        #expect(IntroCardCopy.name("\n\t ") == "the sender")
        #expect(IntroCardCopy.name(nil) == "the sender")
        #expect(IntroCardCopy.name("Carol") == "Carol")
        #expect(IntroCardCopy.name("  Carol Reyes \n") == "Carol Reyes")
        #expect(IntroCardCopy.unknownSender == "the sender")
    }

    @Test("firstName(of:) is the first word, trimmed")
    func firstName() {
        #expect(IntroCardCopy.firstName(of: "Carol Reyes") == "Carol")
        #expect(IntroCardCopy.firstName(of: "  Carol  ") == "Carol")
        #expect(IntroCardCopy.firstName(of: "Carol") == "Carol")
        #expect(IntroCardCopy.firstName(of: "") == "")
    }

    // MARK: - Same text at every depth

    @Test("The same inputs give the same text: copy reads no state")
    func copyIsAPureFunction() {
        let first = self.namedStrings("Carol").map(\.1), second = self.namedStrings("Carol").map(\.1)
        #expect(first == second)
    }

    // MARK: - Countdown

    @Test("The countdown reads Expires in h m s, and Expired at and after the deadline")
    func countdown() {
        #expect(IntroCardCopy.remainingClock(until: self.deadline, now: self.now) == "23h 12m 05s")
        #expect(IntroCardCopy.countdown(until: self.deadline, now: self.now) == "Expires in 23h 12m 05s")
        #expect(IntroCardCopy.countdown(until: self.deadline, now: self.deadline) == "Expired")
        #expect(IntroCardCopy.countdown(until: self.deadline, now: self.deadline.addingTimeInterval(60)) == "Expired")
        #expect(IntroCardCopy.remainingClock(until: self.deadline, now: self.deadline.addingTimeInterval(60)) == "0h 00m 00s")
        #expect(IntroCardCopy.remainingClock(until: self.deadline, now: self.deadline.addingTimeInterval(-59)) == "0h 00m 59s")
    }

    @Test("List lines show the full live clock, and Expired at and after the deadline")
    func listLines() {
        let at = { (seconds: TimeInterval) in self.deadline.addingTimeInterval(-seconds) }
        #expect(IntroCardCopy.issuedListLine(expiresAt: self.deadline, now: self.now) == "Card · 23h 12m 05s")
        #expect(IntroCardCopy.issuedListLine(expiresAt: self.deadline, now: at(45 * 60)) == "Card · 0h 45m 00s")
        #expect(IntroCardCopy.issuedListLine(expiresAt: self.deadline, now: at(30)) == "Card · 0h 00m 30s")
        #expect(IntroCardCopy.issuedListLine(expiresAt: self.deadline, now: self.deadline) == "Card · Expired")
        #expect(IntroCardCopy.issuedListLine(expiresAt: self.deadline, now: at(-60)) == "Card · Expired")
        #expect(IntroCardCopy.sendByListLine(expiresAt: self.deadline, now: self.now) == "Send by · 23h 12m 05s")
        #expect(IntroCardCopy.sendByListLine(expiresAt: self.deadline, now: at(3_600)) == "Send by · 1h 00m 00s")
        #expect(IntroCardCopy.sendByListLine(expiresAt: self.deadline, now: at(3_599)) == "Send by · 0h 59m 59s")
        #expect(IntroCardCopy.sendByListLine(expiresAt: self.deadline, now: self.deadline) == "Send by · Expired")
        #expect(IntroCardCopy.sendByListLine(expiresAt: self.deadline, now: at(-60)) == "Send by · Expired")
        #expect(!IntroCardCopy.issuedListLine(expiresAt: self.deadline, now: self.now).contains("left"))
        #expect(!IntroCardCopy.sendByListLine(expiresAt: self.deadline, now: self.now).contains("left"))
    }

    @Test("W-18: importing the user's own card is refused with the FINDINGS wording")
    func ownCardRefusal() {
        let message = IntroCardCopy.refusedOwnCard()
        #expect(message.label == "Can't import")
        #expect(message.label == IntroCardCopy.refusedLabel)
        #expect(message.text == "This is your own card.")
    }

    // MARK: - FINDINGS' draft copy

    @Test("The warnings read as FINDINGS' Draft copy table has them (W-01 to W-17)")
    func draftCopyIsPinned() {
        let date = IntroCardCopy.date(self.deadline)

        #expect(IntroCardCopy.createWarning(name: "Carol", deadline: self.deadline).text
                == "Anyone who gets this card before Carol can use it and pretend to be Carol. Share it only with Carol. Carol's first message must reach you by \(date), or the card stops working. Making a new card cancels this one.")
        #expect(IntroCardCopy.shareWarning(name: "Carol").text
                == "The app you send this through keeps a copy, possibly in its backups, and that app or the account could be compromised. Anyone who can read that chat could use the card before Carol does. Once the card is used or expired, a leftover copy is useless.")
        #expect(IntroCardCopy.issuerDeadline(name: "Carol", deadline: self.deadline).text
                == "Carol's first message must reach you by \(date). After that the card stops working, and you'd need to make a new one.")
        #expect(IntroCardCopy.importWarning(name: "Carol").label == "Not verified")
        #expect(IntroCardCopy.importWarning(name: "Carol").text
                == "You know whose card this is only from the chat it arrived in. If that app or account was compromised, the card could have been swapped, and your messages would go to whoever swapped it. Be careful what you send until you meet Carol and exchange keys in person.")
        #expect(IntroCardCopy.recipientDeadline(name: "Carol", deadline: self.deadline).label == "Must reach Carol by \(date)")
        #expect(IntroCardCopy.recipientDeadline(name: "Carol", deadline: self.deadline).text
                == "Your first message has to reach Carol by then, or the card stops working. Send it early enough for Carol to open it in time. After that, there's no time limit.")
        #expect(IntroCardCopy.trustLine.label == "Not verified")
        #expect(IntroCardCopy.trustLine.text
                == "You haven't met and exchanged keys in person yet. If the app the card traveled through was compromised, someone else could be reading this conversation. Be careful what you send until you meet.")
        #expect(IntroCardCopy.waitingForReply(name: "Carol").label == "Waiting for the first reply")
        #expect(IntroCardCopy.waitingForReply(name: "Carol").text
                == "If none comes, someone may have used this card before you. Ask Carol for a new card. It replaces this one.")
        #expect(IntroCardCopy.firstMessage(name: "Carol").label == "First message on your card for Carol")
        #expect(IntroCardCopy.firstMessage(name: "Carol").text
                == "Whoever used the card first wrote it. That's probably Carol, but you can't be sure until you verify in person.")
        #expect(IntroCardCopy.activeCard(name: "Carol", deadline: self.deadline).label == "Not used yet")
        #expect(IntroCardCopy.activeCard(name: "Carol", deadline: self.deadline).text
                == "Carol's first message must reach you by \(date), and then the card stops working. Until then, anyone who has this card can use it. Cancel it if it might have reached the wrong person.")
        #expect(IntroCardCopy.blockedFeature(feature: "Vault trustee", name: "Carol")
                == "Vault trustee needs a contact you've verified in person, because it relies on knowing this key really is Carol's. Meet Carol and exchange keys to verify.")
        #expect(IntroCardCopy.exchangeMismatch(name: "Carol").text
                == "Before today, you weren't messaging Carol. Someone swapped the card on its way and could read everything you sent. You're now connected to Carol, verified in person, and whoever was on the other end has been cut off.")
        #expect(IntroCardCopy.exchangeMatch(name: "Carol").label == "Verified in person")
        #expect(IntroCardCopy.exchangeMatch(name: "Carol").text == "Your earlier messages with Carol went to this person.")
        #expect(IntroCardCopy.wasntText(name: "Carol")
                == "If Carol never sent the first message you got, someone else used your card before Carol could, and that's who you've been talking to. Discard this conversation and make Carol a new card.")
        #expect(IntroCardCopy.discardTitle(name: "Carol") == "Discard the conversation with Carol?")
        #expect(IntroCardCopy.discardMessage(name: "Carol") == "Whoever used your card is cut off. Carol goes back to pending, and you can make a new card.")
        #expect(IntroCardCopy.refusedAlreadyTalking(name: "Carol").text
                == "You're already talking with Carol through a card. Meet Carol to verify instead.")
        #expect(IntroCardCopy.refusedOwnCardWins(name: "Carol").text
                == "You already sent Carol a card. Wait for Carol's message. Carol needs to import your card.")
    }
}
