//
//  IntroCardMock+Shared.swift
//  Occulta
//
//  Screens both sides see: the contact list, a blocked feature, and the
//  result of the in-person exchange.
//

#if DEBUG
import SwiftUI

// MARK: - Contact list (W-06)

extension IntroCardMock {
    /// One Not verified section; the old UNVERIFIED section is folded into it
    /// (Q-14). No route is shown, and no fingerprint (Q-07, Q-08).
    struct ContactsList: View {
        private struct Row: Identifiable {
            let id:    String
            let name:  String
            let color: Color
        }

        private let verified    = [Row(id: "mock-alice", name: "Alice Moreau", color: .occultaVerified)]
        private let notVerified = [Row(id: IntroCardMock.carolID, name: IntroCardMock.carolName, color: .occultaWarn)]
        private let pending     = [Row(id: "mock-dana", name: "Dana Park", color: .secondary)]

        var body: some View {
            List {
                Section { self.rows(self.verified) } header: { SectionHeaderV2(status: .verified) }
                Section {
                    self.rows(self.notVerified)
                } header: {
                    SectionHeaderV2(label: "NOT VERIFIED", color: .occultaWarn)
                } footer: {
                    Text("You haven't met and exchanged keys with these contacts in person yet. If the app a card traveled through was compromised, someone else could be reading that conversation.")
                }
                Section { self.rows(self.pending) } header: { SectionHeaderV2(status: .pending) }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Contacts")
        }

        @ViewBuilder
        private func rows(_ rows: [Row]) -> some View {
            ForEach(rows) { row in
                HStack(spacing: 14) {
                    ZStack {
                        avatarGradientV2(for: row.id)
                        Text(row.name.initials)
                            .font(.system(size: 15, weight: .semibold, design: .rounded))
                            .foregroundStyle(.white)
                    }
                    .frame(width: 44, height: 44)
                    .clipShape(Circle())

                    VStack(alignment: .leading, spacing: 4) {
                        Text(row.name).font(.body)
                        Circle().fill(row.color).frame(width: 6, height: 6)
                    }
                    Spacer()
                }
                .padding(.vertical, 3)
            }
        }
    }
}

// MARK: - Blocked feature (W-10)

extension IntroCardMock {
    struct BlockedFeature: View {
        var body: some View {
            Screen {
                Text("Choose trustees")
                    .font(.title3.bold())

                VStack(spacing: 0) {
                    HStack {
                        Text("Alice Moreau")
                        Spacer()
                        Image(systemName: "circle").foregroundStyle(.secondary)
                    }
                    .padding(14)

                    Divider().padding(.leading, 14)

                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(IntroCardMock.carolName).foregroundStyle(.secondary)
                            Spacer()
                            NotVerifiedChip()
                        }
                        Text("Vault trustee needs a contact you've verified in person, because it relies on knowing this key really is Carol's. Meet Carol and exchange keys to verify.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(14)
                }
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }
}

// MARK: - Exchange result

extension IntroCardMock {
    /// W-12. The exchange always completes; this reports what the check found (§5).
    struct ExchangeMatch: View {
        var body: some View {
            Screen {
                Identity(id: IntroCardMock.carolID, name: IntroCardMock.carolName) {
                    StatusChipV3(status: .verified)
                }

                Notice(
                    tone:  .verified,
                    label: "Verified in person",
                    text:  "Your earlier messages with Carol went to this person."
                )
            }
        }
    }

    /// W-11. Needs an explicit acknowledgment and can't be swiped away; nothing
    /// is stored once it's acknowledged (Q-10).
    struct ExchangeMismatch: View {
        @Environment(\.dismiss) private var dismiss

        var body: some View {
            Screen {
                Identity(id: IntroCardMock.carolID, name: IntroCardMock.carolName) {
                    StatusChipV3(status: .verified)
                }

                Notice(
                    tone:  .danger,
                    label: "Your earlier conversation was intercepted",
                    text:  "Before today, you weren't messaging Carol. Someone swapped the card on its way and could read everything you sent. You're now connected to Carol, verified in person, and whoever was on the other end has been cut off."
                )

                PrimaryButton(title: "I understand") { self.dismiss() }
            }
            .interactiveDismissDisabled()
            .navigationBarBackButtonHidden()
        }
    }
}
#endif
