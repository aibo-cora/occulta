//
//  Vault+FirstEntry+Sheet.swift
//  Occulta
//
//  Shown once, automatically, after the user creates their first vault entry.
//  Introduces Secret Sharing — what it does, what it doesn't protect, and the
//  trust/collusion risk — then offers a direct path into shard setup.
//
//  Triggered by VaultTab when entries.count transitions 0 → 1 and
//  vault.sss.firstEntryPromptShown is false. Flag is set on either CTA.
//

import SwiftUI

struct VaultFirstEntrySheet: View {

    /// Label of the first entry — used in the header copy.
    let entryLabel: String
    /// Tapped "Set Up Recovery" — caller dismisses sheet, then navigates to VaultShardSetup.
    let onSetupNow: () -> Void
    /// Tapped "Later" — caller dismisses sheet, no navigation.
    let onLater: () -> Void

    @Environment(\.dismiss) private var dismiss

    private static let purple = VaultEntryType.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF))
    private static let amber  = VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66))
    private static let red    = Color(red: 1, green: 0.42, blue: 0.42)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    self.headerCard
                    self.infoSection(
                        icon: "key.fill",
                        color: Self.purple,
                        title: "What it does",
                        body: "Splits this entry's encryption key into mathematical shards using Shamir's Secret Sharing over GF(2⁸). Each shard goes to a different trusted contact. No single shard reveals anything about your key."
                    )
                    self.infoSection(
                        icon: "person.2.fill",
                        color: Self.purple,
                        title: "Threshold reconstruction",
                        body: "You choose k. Any k of your n trustees can reconstruct your key in any combination. Fewer than k shards reveal zero information — by mathematical guarantee, not computational hardness."
                    )
                    self.infoSection(
                        icon: "exclamationmark.triangle.fill",
                        color: Self.amber,
                        title: "Keys only — not content",
                        body: "Shards protect your encryption key, not the entry content. Export a separate vault backup to protect against full device loss."
                    )
                    self.infoSection(
                        icon: "person.badge.key.fill",
                        color: Self.red,
                        title: "Choose trustees carefully",
                        body: "Any k of your trustees together can reconstruct your key. Pick people who are deeply trusted and independent of each other — k colluding trustees gain key access."
                    )
                }
                .padding(20)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Protect Your Entry")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Later") {
                        self.dismiss()
                        self.onLater()
                    }
                    .foregroundStyle(.secondary)
                }
            }
            .safeAreaInset(edge: .bottom) { self.ctaBar }
        }
    }

    // MARK: - Header

    private var headerCard: some View {
        HStack(spacing: 14) {
            Text("🔮")
                .font(.system(size: 36))
            VStack(alignment: .leading, spacing: 4) {
                Text("\u{201C}\(entryLabel)\u{201D} is ready.")
                    .font(.system(size: 17, weight: .semibold))
                    .lineLimit(1)
                Text("Set up key recovery so trustees can help reconstruct it if you lose this device.")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    // MARK: - Info sections

    private func infoSection(icon: String, color: Color, title: String, body: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundStyle(color)
                .frame(width: 20)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(color)
                Text(body)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .lineSpacing(3)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - CTA bar

    private var ctaBar: some View {
        VStack(spacing: 8) {
            Button {
                self.dismiss()
                self.onSetupNow()
            } label: {
                Text("Set Up Recovery")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                    .background(Color.occultaAccent)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .shadow(color: Color.occultaAccent.opacity(0.3), radius: 10, y: 4)
            }
            .buttonStyle(.plain)

            Text("Only contacts with ML-KEM keys (exchanged via proximity) are eligible as trustees.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(Color.secondary.opacity(0.6))
                .multilineTextAlignment(.center)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(.bar)
    }
}
