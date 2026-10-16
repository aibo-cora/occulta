//
//  IntroCardMock+Components.swift
//  Occulta
//
//  Mock screens for introduction cards v1 — placeholder data, no wiring.
//  Design: Docs/Features/Introduction Cards/FINDINGS.md. Warning copy is
//  the draft copy there, referenced by its W-number.
//

#if DEBUG
import SwiftUI

enum IntroCardMock {
    /// Bob's view of the person he's introducing himself to.
    static let carolID   = "mock-carol"
    static let carolName = "Carol Reyes"

    /// Carol's view of the card's issuer.
    static let bobID   = "mock-bob"
    static let bobName = "Bob Lin"

    /// Cards expire a fixed day after creation (Q-05).
    static var expiryLabel: String {
        Date.now.addingTimeInterval(24 * 60 * 60).formatted(date: .abbreviated, time: .shortened)
    }
}

// MARK: - Identity

extension IntroCardMock {
    struct Identity<Chip: View>: View {
        let id:   String
        let name: String
        @ViewBuilder let chip: Chip

        var body: some View {
            HStack(spacing: 14) {
                ZStack {
                    avatarGradientV2(for: self.id)
                    Text(self.name.initials)
                        .font(.system(size: 18, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .frame(width: 52, height: 52)
                .clipShape(Circle())

                Text(self.name)
                    .font(.system(size: 19, weight: .bold))
                    .tracking(-0.4)
                    .lineLimit(1)

                Spacer()

                self.chip
            }
        }
    }

    /// The one badge for every route (Q-07). Amber, never green, no checkmark (Q-09).
    struct NotVerifiedChip: View {
        var body: some View {
            Text("! NOT VERIFIED")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .tracking(1.2)
                .foregroundStyle(.white)
                .padding(.horizontal, 9)
                .padding(.vertical, 4)
                .background(RoundedRectangle(cornerRadius: 4).fill(Color.occultaWarn))
        }
    }
}

// MARK: - Notice

extension IntroCardMock {
    /// A label and a description, always visible — the `SecrecyIndicator` model
    /// the warning rules require. Never behind a tap.
    struct Notice: View {
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
        }
    }

    /// W-06 — on the contact screen, at compose and at send. The copy names no
    /// route, so it fits any key that didn't come from an in-person exchange (Q-14).
    struct TrustLine: View {
        var body: some View {
            Notice(
                tone:  .warn,
                label: "Not verified",
                text:  "You haven't met and exchanged keys in person yet. If the app the card traveled through was compromised, someone else could be reading this conversation. Be careful what you send until you meet."
            )
        }
    }
}

// MARK: - Compose

extension IntroCardMock {
    /// Compose for a Not verified contact: the trust line sits above the
    /// secrecy state, and forward secrecy isn't green (Q-09). Carol's messages
    /// before she holds Bob's batch are sealed to his card key, so they show
    /// Standard Encryption (SPEC §6.5).
    struct Compose: View {
        let recipientFirstName: String
        var isForwardSecret = true

        var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("Encrypt a message").font(.body.bold())
                    Spacer()
                    Text("→ TO \(self.recipientFirstName.uppercased())")
                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .padding(.bottom, 10)

                HStack(spacing: 6) {
                    Circle().fill(Color.occultaWarn).frame(width: 6, height: 6)
                    Text("Not verified")
                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                Text("")
                    .frame(maxWidth: .infinity, minHeight: 80, alignment: .topLeading)

                Divider()

                HStack {
                    ZStack {
                        Circle()
                            .fill(Color(.tertiarySystemFill))
                            .overlay(Circle().strokeBorder(Color(.separator), lineWidth: 0.5))
                            .frame(width: 30, height: 30)
                        Image(systemName: "plus")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(.secondary)
                    }

                    HStack(spacing: 6) {
                        Circle()
                            .fill(self.isForwardSecret ? Color.secondary : Color.occultaWarn)
                            .frame(width: 6, height: 6)
                        Text(self.isForwardSecret ? "Forward Secret" : "Standard Encryption")
                            .font(.system(size: 10, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Text("Encrypt")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 7)
                        .background(Capsule().fill(Color(.tertiarySystemFill)))
                }
                .padding(.top, 10)
            }
            .padding(14)
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
    }
}

// MARK: - Exchange

extension IntroCardMock {
    /// Mirrors `ExchangeHeroV2`, which is private to `ContactDetailV2`.
    struct ExchangeHero: View {
        let title:    String
        let subtitle: String

        var body: some View {
            VStack(spacing: 16) {
                HStack(spacing: 14) {
                    RoundedRectangle(cornerRadius: 4)
                        .strokeBorder(.white.opacity(0.6), lineWidth: 1.5)
                        .frame(width: 40, height: 40)
                        .overlay(Image(systemName: "key.horizontal.fill").foregroundStyle(.white.opacity(0.9)))

                    VStack(alignment: .leading, spacing: 3) {
                        Text(self.title)
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(.white)
                        Text(self.subtitle)
                            .font(.system(size: 11, weight: .regular, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.7))
                    }
                    Spacer()
                }

                Text("Go to Exchange")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Color.occultaAccent)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Capsule().fill(.white))
            }
            .padding(14)
            .background(Color.occultaAccent)
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
    }
}

// MARK: - Layout

extension IntroCardMock {
    struct SectionLabel: View {
        let text: String

        var body: some View {
            Text(self.text)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .tracking(1.6)
                .padding(.leading, 4)
        }
    }

    struct PrimaryButton: View {
        let title: String
        var enabled = true
        var action: () -> Void = {}

        var body: some View {
            Button(action: self.action) {
                Text(self.title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(self.enabled ? .white : .secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(self.enabled ? Color.occultaAccent : Color(.tertiarySystemFill))
                    .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .buttonStyle(.plain)
            .disabled(!self.enabled)
        }
    }

    struct Screen<Content: View>: View {
        @ViewBuilder let content: Content

        var body: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    self.content
                }
                .padding(16)
            }
            .background(Color(.systemGroupedBackground))
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
#endif
