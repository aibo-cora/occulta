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
        /// Imports the picker refuses (SPEC §6.3).
        enum Refusal { case none, alreadyTalking, ownCardOut }

        var isCardSupported = true
        var refusal: Refusal = .none

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
                        SectionLabel(text: "ATTACH TO")
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

                    switch self.refusal {
                    case .alreadyTalking:
                        Notice(
                            tone:  .danger,
                            label: "Can't import",
                            text:  "You're already talking with \(self.chosenName) through a card. Meet \(self.chosenName) to verify instead."
                        )
                    case .ownCardOut:
                        Notice(
                            tone:  .danger,
                            label: "Can't import",
                            text:  "You already sent \(self.chosenName) a card. Wait for \(self.chosenName)'s message. \(self.chosenName) needs to import your card."
                        )
                    case .none:
                        Countdown()

                        Notice(
                            tone:  .warn,
                            label: "Must reach \(self.chosenName) by \(IntroCardMock.expiryLabel)",
                            text:  "Your first message has to reach \(self.chosenName) by then, or the card stops working. Send it early enough for \(self.chosenName) to open it in time. After that, there's no time limit."
                        )

                        NavigationLink {
                            RecipientBeforeFirstSend()
                        } label: {
                            Text("Import and write to \(self.chosenName)")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundStyle(.white)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                                .background(Color.occultaAccent)
                                .clipShape(RoundedRectangle(cornerRadius: 14))
                        }

                        Button("Import only") {}
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(Color.occultaAccent)
                            .frame(maxWidth: .infinity)
                    }
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

                CardSection {
                    TrustLine()

                    Countdown()

                    Notice(
                        tone:  .warn,
                        label: "Must reach Bob by \(IntroCardMock.expiryLabel)",
                        text:  "Your first message has to reach Bob by then, or Bob's card stops working. Send it early enough for Bob to open it in time. After that, there's no time limit."
                    )
                }

                Compose(recipientFirstName: "Bob", isForwardSecret: false)

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

                CardSection {
                    TrustLine()

                    Notice(
                        tone:  .neutral,
                        label: "Waiting for the first reply",
                        text:  "If none comes, someone may have used this card before you. Ask Bob for a new one, in person or through someone you trust."
                    )
                }

                Compose(recipientFirstName: "Bob", isForwardSecret: false)

                ExchangeHero(title: "Meet Bob to verify", subtitle: "exchange keys in person")
            }
        }
    }
}
#endif
