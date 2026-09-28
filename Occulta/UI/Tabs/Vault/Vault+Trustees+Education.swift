//
//  Vault+Trustees+Education.swift
//  Occulta
//
//  Shown before a depth's first backup-key distribution, from the Backup Recovery screen's
//  "Queue for Distribution". The continue button is locked until the reader has scrolled to
//  the end — detected via onAppear on a 1-pt anchor view after the content.
//
//  Whether to show it comes from existing state (this depth has no distribution yet), never
//  from a stored "seen it" flag, which would be a per-depth trace of the layer having been
//  set up. It replaces `VaultSSSEducationSheet`, which described per-entry splitting and was
//  never presented (`decisions.md`, "Retire per-entry splitting").
//
//  Both callbacks are called on the main thread; the sheet dismisses itself first.
//

import SwiftUI

struct BackupTrusteesEducationSheet: View {

    /// Pieces needed to rebuild the key (k).
    let threshold: Int
    /// Trustees receiving a piece (n).
    let trusteeCount: Int
    let onContinue: () -> Void
    let onCancel: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var hasScrolledToBottom = false

    private static let violet = VaultEntryType.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF))
    private static let amber  = VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66))
    private static let green  = VaultEntryType.cat(light: (0x1A, 0x6D, 0x4A), dark: (0x6E, 0xC9, 0x7E))

    var body: some View {
        let k = self.threshold
        let n = self.trusteeCount

        return NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    self.headerBlock
                    self.section(
                        icon: "key.fill", color: Self.violet,
                        title: "What your backup key does",
                        body: "Your backup file is sealed with a backup key that stays on this phone. Occulta splits that key into pieces, one for each trustee, using Shamir's Secret Sharing. A single piece reveals nothing about the key."
                    )
                    self.section(
                        icon: "person.2.fill", color: Self.violet,
                        title: "Any \(k) of \(n)",
                        body: "After you lose this phone, any \(k) of your \(n) trustees, in any combination, can rebuild the key. Fewer than \(k) learn nothing about it. That's a mathematical guarantee, not a question of how hard it is to compute."
                    )
                    self.section(
                        icon: "archivebox.fill", color: Self.amber,
                        title: "Pieces rebuild the key, not your vault",
                        body: "Trustees never hold your entries. To restore, you also need an exported backup file. Export one once \(k) trustees have confirmed, and again after you add entries."
                    )
                    self.section(
                        icon: "person.badge.key.fill", color: Self.amber,
                        title: "Who can be a trustee",
                        body: "Only contacts you've exchanged keys with in person, who have post-quantum (ML-KEM) keys. Each piece goes out with your next direct message to them, and they confirm the next time they message you directly. Group messages don't count."
                    )
                    self.section(
                        icon: "shield.lefthalf.filled", color: Self.green,
                        title: "Trust carefully",
                        body: "Any \(k) of your trustees who get hold of your backup file can read every entry in it. Choose people who are independent of each other, and keep the file somewhere none of them can reach."
                    )
                    self.section(
                        icon: "arrow.triangle.2.circlepath", color: Self.green,
                        title: "Changing trustees",
                        body: "Adding a trustee keeps the key as it is. Removing one replaces the key, so backup files you've already exported stop working and you'll need to export again."
                    )

                    // Scroll anchor — the continue button unlocks when this becomes visible.
                    Color.clear
                        .frame(height: 1)
                        .onAppear { self.hasScrolledToBottom = true }
                }
                .padding(20)
            }
            .navigationTitle("Backup Key Recovery")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        self.dismiss()
                        self.onCancel()
                    }
                }
            }
            .safeAreaInset(edge: .bottom) { self.ctaBar }
        }
    }

    // MARK: - Header

    private var headerBlock: some View {
        HStack(spacing: 14) {
            Text("🔮")
                .font(.system(size: 36))
            VStack(alignment: .leading, spacing: 4) {
                Text("Before you choose trustees")
                    .font(.system(size: 20, weight: .bold))
                Text("Read to the end to continue.")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    // MARK: - Content section

    private func section(icon: String, color: Color, title: String, body: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundStyle(color)
                .frame(width: 20)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 6) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                Text(body)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .lineSpacing(3)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Continue bar

    private var ctaBar: some View {
        VStack(spacing: 6) {
            Button {
                self.dismiss()
                self.onContinue()
            } label: {
                Text("I understand — Queue for Distribution")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(self.hasScrolledToBottom ? .white : Color.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(self.hasScrolledToBottom ? Color.occultaAccent : Color(.secondarySystemFill))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .shadow(color: self.hasScrolledToBottom ? Color.occultaAccent.opacity(0.27) : .clear, radius: 10, y: 4)
            }
            .buttonStyle(.plain)
            .disabled(!self.hasScrolledToBottom)

            if !self.hasScrolledToBottom {
                Text("Scroll to the bottom to continue")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Color.secondary.opacity(0.6))
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(.bar)
    }
}
