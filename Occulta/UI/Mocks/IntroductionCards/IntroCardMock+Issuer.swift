//
//  IntroCardMock+Issuer.swift
//  Occulta
//
//  Bob's screens: he issues a card to Carol, a pending contact he hasn't met.
//

#if DEBUG
import SwiftUI

// MARK: - Pending contact, no card

extension IntroCardMock {
    struct IssuerPendingNoCard: View {
        var isCardSupported = true

        @State private var creating = false

        var body: some View {
            Screen {
                Identity(id: IntroCardMock.carolID, name: IntroCardMock.carolName) {
                    StatusChipV3(status: .pending)
                }

                ExchangeHero(title: "No key yet", subtitle: "exchange to encrypt messages")

                SectionLabel(text: "INTRODUCTION CARD")
                VStack(alignment: .leading, spacing: 12) {
                    Text("Can't meet Carol yet? Make a card Carol can use to send you a message. Carol will stay Not verified until you meet and exchange keys in person.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)

                    if self.isCardSupported {
                        PrimaryButton(title: "Create card") { self.creating = true }
                    } else {
                        PrimaryButton(title: "Create card", enabled: false)
                        Notice(tone: .neutral, label: "Not available", text: "Introduction cards need iOS 26 or later.")
                    }
                }
                .padding(14)
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .sheet(isPresented: self.$creating) {
                NavigationStack { CreateCard() }
            }
        }
    }
}

// MARK: - Create card (W-01)

extension IntroCardMock {
    struct CreateCard: View {
        @State private var created = false

        var body: some View {
            Screen {
                if self.created {
                    ShareCardStep()
                } else {
                    Text("Card for Carol")
                        .font(.title3.bold())

                    Notice(
                        tone:  .warn,
                        label: "Before you make it",
                        text:  "Anyone who gets this card before Carol can use it and pretend to be Carol. Share it only with Carol. Carol must send you a first message by \(IntroCardMock.expiryLabel), or the card stops working. Making a new card cancels this one."
                    )

                    VStack(spacing: 0) {
                        FactRow(label: "WORKS",   value: "For one person: whoever sends the first message")
                        Divider().padding(.leading, 76)
                        FactRow(label: "DEADLINE", value: "Carol's first message by \(IntroCardMock.expiryLabel)")
                        Divider().padding(.leading, 76)
                        FactRow(label: "HOLDS",   value: "No name, no photo, no identity key")
                    }
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))

                    PrimaryButton(title: "Create card") { self.created = true }
                }
            }
            .navigationTitle("Introduction card")
        }
    }

    struct FactRow: View {
        let label: String
        let value: String

        var body: some View {
            HStack(alignment: .top, spacing: 12) {
                Text(self.label)
                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .frame(minWidth: 50, alignment: .leading)
                Text(self.value)
                    .font(.system(size: 13))
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
    }
}

// MARK: - Share (W-02)

extension IntroCardMock {
    /// Shown before the share sheet. The file is unbranded: no extension,
    /// no file type, a generic name (Q-04).
    struct ShareCardStep: View {
        var body: some View {
            Text("Share the card with Carol")
                .font(.title3.bold())

            Notice(
                tone:  .warn,
                label: "The app you share through",
                text:  "The app you send this through keeps a copy, possibly in its backups, and that app or the account could be compromised. Anyone who can read that chat could use the card before Carol does. Once the card is used or expired, a leftover copy is useless."
            )

            Notice(
                tone:  .neutral,
                label: "Carol's deadline",
                text:  "Carol must send you a first message by \(IntroCardMock.expiryLabel). After that the card stops working, and you'd need to make a new one."
            )

            HStack(spacing: 12) {
                Image(systemName: "doc")
                    .font(.system(size: 20))
                    .foregroundStyle(.secondary)
                    .frame(width: 36, height: 36)
                    .background(Color(.tertiarySystemFill))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text("c3f9a1e07b2d")
                        .font(.system(size: 13, weight: .regular, design: .monospaced))
                    Text("3 KB")
                        .font(.system(size: 11, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(14)
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            PrimaryButton(title: "Share card…")
        }
    }
}

// MARK: - Pending contact, active card (W-09)

extension IntroCardMock {
    struct IssuerPendingActiveCard: View {
        @State private var confirmingCancel = false

        var body: some View {
            Screen {
                Identity(id: IntroCardMock.carolID, name: IntroCardMock.carolName) {
                    StatusChipV3(status: .pending)
                }

                ExchangeHero(title: "No key yet", subtitle: "exchange to encrypt messages")

                SectionLabel(text: "INTRODUCTION CARD")
                VStack(alignment: .leading, spacing: 12) {
                    Notice(
                        tone:  .warn,
                        label: "Not used yet",
                        text:  "Carol has until \(IntroCardMock.expiryLabel) to send you a first message, and then the card stops working. Until then, anyone who has this card can use it. Cancel it if it might have reached the wrong person."
                    )

                    HStack(spacing: 12) {
                        Button("Share card…") {}
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(Color.occultaAccent)
                        Spacer()
                        Button("Cancel card", role: .destructive) { self.confirmingCancel = true }
                            .font(.system(size: 14, weight: .semibold))
                    }

                    Text("Making a new card cancels this one.")
                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .padding(14)
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .confirmationDialog("Cancel the card for Carol?", isPresented: self.$confirmingCancel, titleVisibility: .visible) {
                Button("Cancel card", role: .destructive) {}
            } message: {
                Text("It stops working right away. You can make a new one.")
            }
        }
    }
}

// MARK: - First message arrives (W-08)

extension IntroCardMock {
    struct IssuerFirstMessage: View {
        var body: some View {
            Screen {
                Notice(
                    tone:  .warn,
                    label: "First message on your card for Carol",
                    text:  "Whoever used the card first wrote it. That's probably Carol, but you can't be sure until you verify in person."
                )

                VStack(alignment: .leading, spacing: 8) {
                    Text("FROM CAROL REYES")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .tracking(1.6)
                    Text("Hi Bob, it's Carol. Thanks for the card.")
                        .font(.body)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 14))

                TrustLine()
            }
            .navigationTitle("Message")
        }
    }
}

// MARK: - Card contact (W-06, W-15)

extension IntroCardMock {
    /// Carol after the first message: Not verified, no fingerprint (Q-08).
    /// The bottom section covers the case W-15 exists for: someone other than
    /// Carol used the card first, and Carol finds out the message never arrived.
    struct IssuerCardContact: View {
        @State private var confirmingDiscard = false

        var body: some View {
            Screen {
                Identity(id: IntroCardMock.carolID, name: IntroCardMock.carolName) {
                    NotVerifiedChip()
                }

                TrustLine()

                Compose(recipientFirstName: "Carol")

                ExchangeHero(title: "Meet Carol to verify", subtitle: "exchange keys in person")

                SectionLabel(text: "WASN'T CAROL?")
                VStack(alignment: .leading, spacing: 12) {
                    Text("If Carol never sent the first message you got, someone else used your card before Carol could, and that's who you've been talking to. Discard this conversation and make Carol a new card.")
                        .font(.footnote)
                        .fixedSize(horizontal: false, vertical: true)

                    Button(role: .destructive) { self.confirmingDiscard = true } label: {
                        Text("Discard conversation")
                            .font(.system(size: 14, weight: .semibold))
                    }
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .confirmationDialog("Discard the conversation with Carol?", isPresented: self.$confirmingDiscard, titleVisibility: .visible) {
                Button("Discard", role: .destructive) {}
            } message: {
                Text("Whoever used your card is cut off. Carol goes back to pending, and you can make a new card.")
            }
        }
    }
}
#endif
