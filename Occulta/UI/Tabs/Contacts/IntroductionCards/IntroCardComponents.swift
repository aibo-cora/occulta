//
//  IntroCardComponents.swift
//  Occulta
//
//  The pieces every introduction card screen is built from. They take plain
//  values, so they don't depend on the card engine's types. Strings come from
//  `IntroCardCopy`.
//
//  Nothing about a Not verified contact is green (Q-09): the chip and the
//  trust line are amber, and `.verified` is only for the in-person result (W-12).
//

import SwiftUI

// MARK: - Not verified chip

/// The one badge for every route (Q-07). Amber, never green, no checkmark (Q-09).
struct NotVerifiedChip: View {
    var body: some View {
        Text("! \(IntroCardCopy.notVerifiedChip.uppercased())")
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .tracking(1.2)
            .foregroundStyle(.white)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(RoundedRectangle(cornerRadius: 4).fill(Color.occultaWarn))
    }
}

// MARK: - Notice

/// A label and a description, always visible: the `SecrecyIndicator` model the
/// warning rules require. Never behind a tap, never dismissible.
struct CardNotice: View {
    enum Tone {
        case warn, danger, neutral, verified

        var color: Color {
            switch self {
            case .warn:     .occultaWarn
            case .danger:   .occultaDanger
            case .neutral:  .secondary
            case .verified: .occultaVerified
            }
        }
    }

    let tone:  Tone
    let label: String
    let text:  String

    init(tone: Tone, label: String, text: String) {
        self.tone  = tone
        self.label = label
        self.text  = text
    }

    init(tone: Tone, _ message: IntroCardCopy.Message) {
        self.init(tone: tone, label: message.label, text: message.text)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Circle().fill(self.tone.color).frame(width: 6, height: 6)
                Text(self.label.uppercased())
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .tracking(1.2)
                    .foregroundStyle(self.tone.color)
            }
            Text(self.text)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(self.tone.color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Section

/// Everything about the card on one contact, in one box: status, deadline,
/// actions. Card content is never split across the screen.
struct CardSection<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(IntroCardCopy.sectionTitle)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .tracking(1.6)
                .padding(.leading, 4)

            VStack(alignment: .leading, spacing: 12) {
                self.content
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
    }
}

// MARK: - Countdown

/// Live countdown to the card's deadline, ticking every second (decided 2026-10-16).
struct CardCountdown: View {
    let expiresAt: Date

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            HStack(spacing: 8) {
                Image(systemName: "timer")
                Text(IntroCardCopy.countdown(until: self.expiresAt, now: context.date))
                    .monospacedDigit()
            }
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(Color.occultaWarn)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityAddTraits(.updatesFrequently)
    }
}

// MARK: - Previews

#Preview("Not verified card contact") {
    let deadline = Date.now.addingTimeInterval(23 * 3600 + 12 * 60)

    ScrollView {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Bob Lin").font(.system(size: 19, weight: .bold))
                Spacer()
                NotVerifiedChip()
            }

            CardSection {
                CardNotice(tone: .warn, IntroCardCopy.trustLine)
                CardCountdown(expiresAt: deadline)
                CardNotice(tone: .warn, IntroCardCopy.recipientDeadline(name: "Bob", deadline: deadline))
            }

            CardSection {
                CardNotice(tone: .warn, IntroCardCopy.trustLine)
                CardNotice(tone: .neutral, IntroCardCopy.waitingForReply(name: "Bob"))
            }
        }
        .padding(16)
    }
    .background(Color(.systemGroupedBackground))
}

#Preview("Issuer") {
    let deadline = Date.now.addingTimeInterval(23 * 3600 + 12 * 60)

    ScrollView {
        VStack(alignment: .leading, spacing: 16) {
            CardSection {
                Text(IntroCardCopy.pendingContactCard(name: "Carol"))
                    .font(.footnote)
            }

            CardSection {
                CardCountdown(expiresAt: deadline)
                CardNotice(tone: .warn, IntroCardCopy.activeCard(name: "Carol", deadline: deadline))
                Text(IntroCardCopy.newCardCancelsThis)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            CardNotice(tone: .warn, IntroCardCopy.createWarning(name: "Carol", deadline: deadline))
            CardNotice(tone: .warn, IntroCardCopy.shareWarning(name: "Carol"))
            CardNotice(tone: .neutral, IntroCardCopy.issuerDeadline(name: "Carol", deadline: deadline))
            CardNotice(tone: .warn, IntroCardCopy.firstMessage(name: "Carol"))
            CardNotice(tone: .neutral, IntroCardCopy.unavailable)
        }
        .padding(16)
    }
    .background(Color(.systemGroupedBackground))
}

#Preview("Import and results") {
    let deadline = Date.now.addingTimeInterval(23 * 3600 + 12 * 60)

    ScrollView {
        VStack(alignment: .leading, spacing: 16) {
            CardNotice(tone: .warn, IntroCardCopy.importWarning(name: IntroCardCopy.unknownSender))
            CardNotice(tone: .danger, IntroCardCopy.refusedAlreadyTalking(name: "Bob"))
            CardNotice(tone: .danger, IntroCardCopy.refusedOwnCardWins(name: "Bob"))
            CardNotice(tone: .danger, IntroCardCopy.exchangeMismatch(name: "Carol"))
            CardNotice(tone: .verified, IntroCardCopy.exchangeMatch(name: "Carol"))

            Text(IntroCardCopy.issuedListLine(expiresAt: deadline, now: .now))
            Text(IntroCardCopy.sendByListLine(expiresAt: deadline, now: .now))
        }
        .padding(16)
    }
    .background(Color(.systemGroupedBackground))
}
