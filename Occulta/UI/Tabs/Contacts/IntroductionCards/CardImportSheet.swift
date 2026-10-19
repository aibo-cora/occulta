//
//  CardImportSheet.swift
//  Occulta
//
//  Carol imports Bob's card (`Docs/Features/Introduction Cards/SPEC.md` §6.3). Reached when a file the app
//  recognises as a card arrives, from the share extension or the Import card button; a card is never opened
//  from a chat (Q-04). What it shows comes from the card and the contacts' card states, never from the depth.
//

import SwiftUI
import SwiftData
import OccultaFormats

/// Where the screen goes after an import: the contact's details, with the cursor in compose.
struct ContactOpenRequest: Identifiable, Equatable {
    let id = UUID()
    let identifier: String
    let focusCompose: Bool
}

struct CardImportSheet: View {
    /// The card's bytes, already shown to be a card by the router. Checked again here: the sheet trusts nothing.
    let data: Data
    /// Called once, when the sheet is done: with where to go next, or nil to just close.
    let onFinish: (ContactOpenRequest?) -> Void

    @Environment(ContactManager.self)   private var contactManager
    @Environment(Manager.Security.self) private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]

    /// A contact the card can be attached to, with what the sheet needs to decide, read once.
    private struct Entry: Identifiable {
        let profile:  Contact.Profile
        let fullName: String
        let state:    CardState

        var id: String { self.profile.identifier }
    }

    @State private var card: IntroductionCard?
    @State private var entries: [Entry] = []
    @State private var ownIssuedKeys = Set<Data>()
    @State private var loaded = false

    @State private var attachToExisting = true
    @State private var selectedID: String?
    @State private var newName = ""
    @State private var failure: IntroCardCopy.Message?

    // MARK: - Derived

    /// With nobody to attach to, the only choice is a new contact.
    private var attachesToExisting: Bool { self.attachToExisting && !self.entries.isEmpty }

    private var selectedEntry: Entry? {
        self.entries.first { $0.id == self.selectedID }
    }

    /// The name copy uses: the contact's first name, the typed one, or "the sender" while there is none.
    private var chosenName: String {
        if self.attachesToExisting {
            return IntroCardCopy.firstName(of: self.selectedEntry?.fullName ?? "")
        }
        let typed = IntroCardCopy.name(self.newName)
        return typed == IntroCardCopy.unknownSender ? typed : IntroCardCopy.firstName(of: typed)
    }

    /// What importing into the current choice would do, decided by the same rule the import uses.
    private var refusal: CardImportDecision.Refusal? {
        guard let card = self.card else { return nil }
        let current = self.attachesToExisting ? (self.selectedEntry?.state ?? .empty) : CardState.empty
        if case .refuse(let reason) = CardRules.importDecision(
            current: current, incoming: card, now: .now, ownIssuedAgreementKeys: self.ownIssuedKeys
        ) { return reason }
        return nil
    }

    private var canImport: Bool {
        if self.attachesToExisting { return self.selectedEntry != nil }
        return !self.newName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    // MARK: - Body

    var body: some View {
        NavigationStack {
            CardScreen {
                Text(IntroCardCopy.importTitle)
                    .font(.title3.bold())

                if !self.loaded {
                    ProgressView().frame(maxWidth: .infinity)
                } else if self.card == nil {
                    CardNotice(tone: .danger, IntroCardCopy.notACard)
                } else if #available(iOS 26, *) {
                    self.importContent
                } else {
                    CardNotice(tone: .neutral, IntroCardCopy.unavailable)
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { self.onFinish(nil) }
                }
            }
        }
        .task { self.load() }
    }

    @ViewBuilder
    private var importContent: some View {
        CardNotice(tone: .warn, IntroCardCopy.importWarning(name: self.chosenName))

        if !self.entries.isEmpty {
            Picker("", selection: self.$attachToExisting) {
                Text("Existing contact").tag(true)
                Text("New contact").tag(false)
            }
            .pickerStyle(.segmented)
        }

        if self.attachesToExisting {
            self.contactPicker
        } else {
            TextField("Name", text: self.$newName)
                .autocorrectionDisabled()
                .padding(14)
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
        }

        if let refusal = self.refusal {
            CardNotice(tone: .danger, self.message(for: refusal))
        } else if let card = self.card {
            // The deadline the import will keep (`CardRules.recipientDeadline`), not a far-future one a card may claim.
            let deadline = CardRules.recipientDeadline(of: card, now: .now)
            CardCountdown(expiresAt: deadline)
            CardNotice(tone: .warn, IntroCardCopy.recipientDeadline(name: self.chosenName, deadline: deadline))
        }

        if let failure = self.failure {
            CardNotice(tone: .danger, failure)
        }

        if self.refusal == nil {
            CardPrimaryButton(title: IntroCardCopy.importAndWriteButton(name: self.chosenName), enabled: self.canImport) {
                self.runImport(thenWrite: true)
            }

            Button(IntroCardCopy.importOnlyButton) { self.runImport(thenWrite: false) }
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(self.canImport ? Color.occultaAccent : Color.secondary)
                .frame(maxWidth: .infinity)
                .disabled(!self.canImport)
        }
    }

    private var contactPicker: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("ATTACH TO")
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .tracking(1.6)
                .padding(.leading, 4)

            VStack(spacing: 0) {
                ForEach(self.entries) { entry in
                    Button { self.selectedID = entry.id } label: {
                        HStack {
                            Text(entry.fullName).foregroundStyle(.primary)
                            Spacer()
                            Image(systemName: self.selectedID == entry.id ? "circle.inset.filled" : "circle")
                                .foregroundStyle(self.selectedID == entry.id ? Color.occultaAccent : Color.secondary)
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 12)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if entry.id != self.entries.last?.id {
                        Divider().padding(.leading, 14)
                    }
                }
            }
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    // MARK: - Actions

    /// Reads the card, the contacts it can attach to and the cards already issued, once.
    ///
    /// Only pending contacts and contacts waiting on a card are offered: never a verified contact, one in a card
    /// conversation, or one whose keys came from elsewhere. Each contact's status and card are read together, so
    /// the card field is decrypted once.
    private func load() {
        guard !self.loaded else { return }

        self.card = IntroductionCard.recognize(self.data)

        let visible = ContactListFilter.sortedContacts(
            ContactListFilter.visibleContacts(self.contacts, atDepth: self.security.currentDepth), matching: ""
        )
        // The same card again: open the contact it's already on, and change nothing (`CardRules.holds`).
        if let card = self.card, let holder = visible.first(where: { CardRules.holds($0.cardState, card: card) }) {
            self.loaded = true
            self.onFinish(ContactOpenRequest(identifier: holder.identifier, focusCompose: false))
            return
        }
        self.entries = visible.compactMap { profile in
            let (status, card) = profile.statusAndCard
            let state = card ?? .empty
            switch (status, state) {
            case (.pending, _), (.unverified, .imported):
                let name = [profile.givenName.decrypt(), profile.familyName.decrypt()]
                    .filter { !$0.isEmpty }.joined(separator: " ")
                return Entry(profile: profile, fullName: name, state: state)
            default:
                return nil
            }
        }
        self.selectedID    = self.entries.first?.id
        self.ownIssuedKeys = (try? self.contactManager.ownIssuedAgreementKeys()) ?? []
        self.loaded        = true
    }

    private func runImport(thenWrite: Bool) {
        let target = self.attachesToExisting ? self.selectedEntry?.profile : nil
        do {
            switch try self.contactManager.importCard(
                self.data, into: target, newContactName: self.attachesToExisting ? nil : self.newName
            ) {
            case .imported(let identifier):
                self.onFinish(thenWrite ? ContactOpenRequest(identifier: identifier, focusCompose: true) : nil)
            case .refused(let reason):
                self.failure = self.message(for: reason)
            case .notACard:
                self.failure = IntroCardCopy.notACard
            case .unsupported:
                self.failure = IntroCardCopy.unavailable
            }
        } catch {
            self.failure = IntroCardCopy.importFailed
        }
    }

    private func message(for refusal: CardImportDecision.Refusal) -> IntroCardCopy.Message {
        switch refusal {
        case .alreadyTalking: IntroCardCopy.refusedAlreadyTalking(name: self.chosenName)
        case .ownCardWins:    IntroCardCopy.refusedOwnCardWins(name: self.chosenName)
        case .ownCard:        IntroCardCopy.refusedOwnCard()
        case .expired:        IntroCardCopy.refusedExpired(name: self.chosenName)
        }
    }
}
