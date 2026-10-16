//
//  IntroCardMock+Recipient.swift
//  Occulta
//
//  Carol's screens: she imports Bob's card and messages him before they meet.
//

#if DEBUG
import SwiftUI

// MARK: - Import (W-05)

extension IntroCardMock {
    /// Reached through the share extension or an Import card button; there is
    /// no "Open in Occulta" from a chat (Q-04).
    struct ImportCard: View {
        var isCardSupported = true

        @State private var attachToExisting = true
        @State private var selectedID       = IntroCardMock.bobID
        @State private var newName          = ""

        private let pendingContacts = [
            (id: IntroCardMock.bobID, name: IntroCardMock.bobName),
            (id: "mock-dana",         name: "Dana Park")
        ]

        /// The name the card is being attached to; copy names the person, never "them".
        private var chosenName: String {
            if self.attachToExisting {
                let full = self.pendingContacts.first { $0.id == self.selectedID }?.name ?? ""
                return full.components(separatedBy: " ").first ?? full
            }
            let typed = self.newName.trimmingCharacters(in: .whitespaces)
            return typed.isEmpty ? "the sender" : typed
        }

        var body: some View {
            Screen {
                Text("Import introduction card")
                    .font(.title3.bold())

                if !self.isCardSupported {
                    Notice(tone: .neutral, label: "Not available", text: "Introduction cards need iOS 26 or later.")
                } else {
                    Notice(
                        tone:  .warn,
                        label: "Not verified",
                        text:  "You know whose card this is only from the chat it arrived in. If that app or account was compromised, the card could have been swapped, and your messages would go to whoever swapped it. Be careful what you send until you meet \(self.chosenName) and exchange keys in person."
                    )

                    Picker("", selection: self.$attachToExisting) {
                        Text("Existing contact").tag(true)
                        Text("New contact").tag(false)
                    }
                    .pickerStyle(.segmented)

                    if self.attachToExisting {
                        SectionLabel(text: "PENDING CONTACTS")
                        VStack(spacing: 0) {
                            ForEach(self.pendingContacts, id: \.id) { contact in
                                Button { self.selectedID = contact.id } label: {
                                    HStack {
                                        Text(contact.name).foregroundStyle(.primary)
                                        Spacer()
                                        if self.selectedID == contact.id {
                                            Image(systemName: "circle.inset.filled").foregroundStyle(Color.occultaAccent)
                                        } else {
                                            Image(systemName: "circle").foregroundStyle(.secondary)
                                        }
                                    }
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 12)
                                }
                                .buttonStyle(.plain)
                                if contact.id != self.pendingContacts.last?.id {
                                    Divider().padding(.leading, 14)
                                }
                            }
                        }
                        .background(Color(.secondarySystemGroupedBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    } else {
                        TextField("Name", text: self.$newName)
                            .autocorrectionDisabled()
                            .padding(14)
                            .background(Color(.secondarySystemGroupedBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }

                    Notice(
                        tone:  .warn,
                        label: "Must reach \(self.chosenName) by \(IntroCardMock.expiryLabel)",
                        text:  "Your first message has to reach \(self.chosenName) by then, or the card stops working. Send it early enough for \(self.chosenName) to open it in time. After that, there's no time limit."
                    )

                    PrimaryButton(title: "Import")
                }
            }
        }
    }
}

// MARK: - Card contact, before the first message

extension IntroCardMock {
    struct RecipientBeforeFirstSend: View {
        var body: some View {
            Screen {
                Identity(id: IntroCardMock.bobID, name: IntroCardMock.bobName) {
                    NotVerifiedChip()
                }

                TrustLine()

                Notice(
                    tone:  .warn,
                    label: "Must reach Bob by \(IntroCardMock.expiryLabel)",
                    text:  "Your first message has to reach Bob by then, or Bob's card stops working. Send it early enough for Bob to open it in time. After that, there's no time limit."
                )

                Compose(recipientFirstName: "Bob")

                ExchangeHero(title: "Meet Bob to verify", subtitle: "exchange keys in person")
            }
        }
    }
}

// MARK: - Card contact, waiting for the first reply (W-07)

extension IntroCardMock {
    /// Carol can keep writing: the card's prekey batch covers her until Bob replies.
    struct RecipientWaitingForReply: View {
        var body: some View {
            Screen {
                Identity(id: IntroCardMock.bobID, name: IntroCardMock.bobName) {
                    NotVerifiedChip()
                }

                TrustLine()

                Notice(
                    tone:  .neutral,
                    label: "Waiting for the first reply",
                    text:  "If none comes, someone may have used this card before you. Ask Bob for a new one, in person or through someone you trust."
                )

                Compose(recipientFirstName: "Bob")

                ExchangeHero(title: "Meet Bob to verify", subtitle: "exchange keys in person")
            }
        }
    }
}
#endif
