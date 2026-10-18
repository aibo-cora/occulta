//
//  ContactCardSection.swift
//  Occulta
//
//  Everything about the card on one contact's details, in one box (FINDINGS §3, decided 2026-10-16):
//  status, deadline and actions, never split across the screen. What it shows comes only from the card
//  state, never from the depth (Prekey Continuity DESIGN.md §7).
//

import SwiftUI
import OccultaFormats

struct ContactCardSection: View {
    let profile: Contact.Profile
    let state:   CardState
    /// The contact's first name, which is what copy uses.
    let name: String

    @Environment(ContactManager.self) private var contactManager

    @State private var creating            = false
    @State private var sharing             = false
    @State private var confirmingCancel    = false
    @State private var confirmingDiscard   = false
    @State private var failure: IntroCardCopy.Message?

    var body: some View {
        CardSection {
            switch self.state {
            case .empty:
                self.pendingContent
            case .issued(_, _, _, _, let expiresAt):
                // An expired card is no card the moment the clock passes its deadline, not at the next unlock's
                // sweep: nothing on it can be shared, and a new one can be made.
                // Ticks every second, as the countdown does: an explicit schedule of `[expiresAt]` alone renders its
                // first frame at that date, which showed a fresh card as expired.
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    VStack(alignment: .leading, spacing: 12) {
                        if context.date < expiresAt {
                            self.issuedContent(expiresAt: expiresAt)
                        } else {
                            self.pendingContent
                        }
                    }
                }
            case .imported(_, _, _, _, _, _, let expiresAt, let sentFirstMessage):
                self.importedContent(expiresAt: expiresAt, sentFirstMessage: sentFirstMessage)
            case .conversation(_, _, _, _, _, _, let isIssuer):
                self.conversationContent(isIssuer: isIssuer)
            }

            if let failure = self.failure {
                CardNotice(tone: .danger, failure)
            }
        }
        .sheet(isPresented: self.$creating) {
            CardCreateSheet(profile: self.profile, name: self.name)
        }
        .sheet(isPresented: self.$sharing) {
            if case .issued(_, _, _, _, let expiresAt) = self.state {
                NavigationStack {
                    CardShareSheet(profile: self.profile, name: self.name, expiresAt: expiresAt)
                }
            }
        }
        .confirmationDialog(
            IntroCardCopy.cancelCardTitle(name: self.name),
            isPresented: self.$confirmingCancel, titleVisibility: .visible
        ) {
            Button(IntroCardCopy.cancelCardButton, role: .destructive) { self.cancelCard() }
        } message: {
            Text(IntroCardCopy.cancelCardMessage)
        }
        .confirmationDialog(
            IntroCardCopy.discardTitle(name: self.name),
            isPresented: self.$confirmingDiscard, titleVisibility: .visible
        ) {
            Button(IntroCardCopy.discardConfirmButton, role: .destructive) { self.discardConversation() }
        } message: {
            Text(IntroCardCopy.discardMessage(name: self.name))
        }
    }

    // MARK: - States

    /// A pending contact with no card.
    @ViewBuilder
    private var pendingContent: some View {
        Text(IntroCardCopy.pendingContactCard(name: self.name))
            .font(.footnote)
            .fixedSize(horizontal: false, vertical: true)

        if #available(iOS 26, *) {
            CardPrimaryButton(title: IntroCardCopy.createCardButton) { self.creating = true }
        } else {
            CardPrimaryButton(title: IntroCardCopy.createCardButton, enabled: false)
            CardNotice(tone: .neutral, IntroCardCopy.unavailable)
        }
    }

    /// Bob: a card out and unused (W-09).
    @ViewBuilder
    private func issuedContent(expiresAt: Date) -> some View {
        CardCountdown(expiresAt: expiresAt)
        CardNotice(tone: .warn, IntroCardCopy.activeCard(name: self.name, deadline: expiresAt))

        HStack(spacing: 12) {
            Button(IntroCardCopy.shareCardButton) { self.sharing = true }
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Color.occultaAccent)
            Spacer()
            Button(IntroCardCopy.cancelCardButton, role: .destructive) { self.confirmingCancel = true }
                .font(.system(size: 14, weight: .semibold))
        }

        Text(IntroCardCopy.newCardCancelsThis)
            .font(.system(size: 10, weight: .regular, design: .monospaced))
            .foregroundStyle(.secondary)
    }

    /// Carol: until she opens Bob's first message (W-06, W-05's deadline, W-07).
    @ViewBuilder
    private func importedContent(expiresAt: Date, sentFirstMessage: Bool) -> some View {
        CardNotice(tone: .warn, IntroCardCopy.trustLine)

        if sentFirstMessage {
            CardNotice(tone: .neutral, IntroCardCopy.waitingForReply(name: self.name))
        } else {
            CardCountdown(expiresAt: expiresAt)
            CardNotice(tone: .warn, IntroCardCopy.recipientDeadline(name: self.name, deadline: expiresAt))
        }
    }

    /// Both sides, until the meeting. "Wasn't {Name}?" is Bob's (W-15): only he made the card, and only his
    /// field holds Carol's introduction.
    @ViewBuilder
    private func conversationContent(isIssuer: Bool) -> some View {
        CardNotice(tone: .warn, IntroCardCopy.trustLine)

        if isIssuer {
            Text(IntroCardCopy.wasntHeading(name: self.name).uppercased())
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .tracking(1.6)

            Text(IntroCardCopy.wasntText(name: self.name))
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)

            Button(role: .destructive) { self.confirmingDiscard = true } label: {
                Text(IntroCardCopy.discardButton)
                    .font(.system(size: 14, weight: .semibold))
            }
        }
    }

    // MARK: - Actions

    private func cancelCard() {
        do {
            try self.contactManager.cancelCard(for: self.profile)
            self.failure = nil
        } catch {
            self.failure = IntroCardCopy.cancelFailed
        }
    }

    private func discardConversation() {
        do {
            try self.contactManager.discardCardConversation(for: self.profile)
            self.failure = nil
        } catch {
            self.failure = IntroCardCopy.discardFailed
        }
    }
}

// MARK: - Create (W-01)

/// Bob: makes the card, then goes straight to the share step.
struct CardCreateSheet: View {
    let profile: Contact.Profile
    let name:    String

    @Environment(\.dismiss)           private var dismiss
    @Environment(ContactManager.self) private var contactManager

    /// The card's real deadline, once it exists. Before that the warning shows the deadline a card made now would have.
    @State private var expiresAt: Date?
    @State private var failure: IntroCardCopy.Message?

    var body: some View {
        NavigationStack {
            if let expiresAt = self.expiresAt {
                CardShareSheet(profile: self.profile, name: self.name, expiresAt: expiresAt)
            } else {
                self.createStep
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { self.dismiss() } } }
            }
        }
    }

    private var createStep: some View {
        // The deadline the card would get if made now, kept current while the screen is open.
        TimelineView(.periodic(from: .now, by: 1)) { context in
            self.createContent(deadline: context.date.addingTimeInterval(ContactManager.cardLifetime))
        }
        .navigationTitle("Introduction card")
    }

    private func createContent(deadline: Date) -> some View {
        CardScreen {
            Text(IntroCardCopy.createTitle(name: self.name))
                .font(.title3.bold())

            CardNotice(tone: .warn, IntroCardCopy.createWarning(name: self.name, deadline: deadline))

            VStack(spacing: 0) {
                CardFactRow(label: IntroCardCopy.factWorksLabel, value: IntroCardCopy.factWorks)
                Divider().padding(.leading, 76)
                CardFactRow(label: IntroCardCopy.factDeadlineLabel, value: IntroCardCopy.factDeadline(name: self.name, deadline: deadline))
                Divider().padding(.leading, 76)
                CardFactRow(label: IntroCardCopy.factHoldsLabel, value: IntroCardCopy.factHolds)
            }
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            if let failure = self.failure {
                CardNotice(tone: .danger, failure)
            }

            CardPrimaryButton(title: IntroCardCopy.createCardButton) { self.create() }
        }
    }

    private func create() {
        do {
            self.expiresAt = try self.contactManager.createCard(for: self.profile).expiresAt
            self.failure = nil
        } catch ContactManager.CardError.unsupported {
            self.failure = IntroCardCopy.unavailable
        } catch {
            self.failure = IntroCardCopy.createFailed
        }
    }
}

// MARK: - Share (W-02)

/// Shown before the share sheet. The shared file is unbranded: no extension, no file type, a random name (Q-04).
struct CardShareSheet: View {
    let profile:   Contact.Profile
    let name:      String
    let expiresAt: Date

    @Environment(\.dismiss)           private var dismiss
    @Environment(ContactManager.self) private var contactManager

    /// The temporary file being shared; deleted when the share sheet closes, and again when this view goes.
    @State private var shareFile: ShareFile?
    @State private var failure: IntroCardCopy.Message?

    private struct ShareFile: Identifiable {
        let id  = UUID()
        let url: URL
    }

    var body: some View {
        CardScreen {
            Text(IntroCardCopy.shareTitle(name: self.name))
                .font(.title3.bold())

            CardNotice(tone: .warn, IntroCardCopy.shareWarning(name: self.name))
            CardNotice(tone: .neutral, IntroCardCopy.issuerDeadline(name: self.name, deadline: self.expiresAt))

            if let failure = self.failure {
                CardNotice(tone: .danger, failure)
            }

            CardPrimaryButton(title: IntroCardCopy.shareCardButton) { self.share() }
        }
        .navigationTitle("Introduction card")
        .toolbar {
            // Dismissal for the sheet this is shown in on its own; `CardCreateSheet` adds its own button.
            ToolbarItem(placement: .cancellationAction) { Button("Close") { self.dismiss() } }
        }
        .sheet(item: self.$shareFile) { file in
            ActivityView(activityItems: [file.url], onComplete: { _ in
                try? FileManager.default.removeItem(at: file.url)
            })
            .onDisappear { try? FileManager.default.removeItem(at: file.url) }
        }
        // The card stops being shareable when it expires: the screen closes, and the share sheet with it.
        .task {
            try? await Task.sleep(for: .seconds(max(0, self.expiresAt.timeIntervalSinceNow)))
            if !Task.isCancelled { self.dismiss() }
        }
    }

    private func share() {
        do {
            self.shareFile = ShareFile(url: try self.contactManager.cardShareFile(for: self.profile))
            self.failure = nil
        } catch {
            self.failure = IntroCardCopy.shareFailed
        }
    }
}
