//
//  VaultSSSEducationSheet.swift
//  Occulta
//
//  Mandatory education modal shown before enabling Secret Sharing.
//  The "Enable" CTA is locked until the user has scrolled to the bottom —
//  detected via onAppear on a 1-pt anchor view at the end of the content.
//
//  Both callbacks are called on the main thread (sheet is @MainActor).
//  The sheet dismisses itself before invoking either callback.
//

import SwiftUI

struct VaultSSSEducationSheet: View {

    let onEnable: () -> Void
    let onCancel: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var hasScrolledToBottom = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    self.headerBlock
                    self.section(
                        icon: "key.fill",
                        color: VaultEntryType.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF)),
                        title: "What it does",
                        body: "Secret Sharing splits a vault entry's encryption key into mathematical shards using Shamir's Secret Sharing over GF(2⁸). Each shard goes to a different trusted contact (trustee). No single shard reveals anything about the key."
                    )
                    self.section(
                        icon: "person.2.fill",
                        color: VaultEntryType.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF)),
                        title: "Reconstruction threshold",
                        body: "You choose a threshold k. Any k of your n trustees — in any combination — can help reconstruct your key. Fewer than k shards reveal zero information, by mathematical guarantee."
                    )
                    self.section(
                        icon: "exclamationmark.triangle.fill",
                        color: VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)),
                        title: "Keys only — not content",
                        body: "Shards protect your encryption key, not the entry content. If you lose your device, the content is gone even if you can reconstruct the key. Export a vault backup separately to protect against full device loss."
                    )
                    self.section(
                        icon: "person.badge.key.fill",
                        color: VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)),
                        title: "Trustee requirements",
                        body: "Trustees must have ML-KEM keys — contacts who have exchanged keys with you via the proximity (UWB) flow. Classic-only contacts cannot receive shards."
                    )
                    self.section(
                        icon: "shield.lefthalf.filled",
                        color: VaultEntryType.cat(light: (0x1A, 0x6D, 0x4A), dark: (0x6E, 0xC9, 0x7E)),
                        title: "Trust carefully",
                        body: "Any k of your chosen trustees can reconstruct your key. Choose people you trust deeply and independently — if k collude, they can access the entry's encryption key. They cannot access the content without also having your vault backup."
                    )

                    // Scroll anchor — CTA unlocks when this becomes visible.
                    Color.clear
                        .frame(height: 1)
                        .onAppear { self.hasScrolledToBottom = true }
                }
                .padding(20)
            }
            .navigationTitle("About Secret Sharing")
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
                Text("Secret Sharing")
                    .font(.system(size: 20, weight: .bold))
                Text("Information-theoretic key recovery")
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

    // MARK: - CTA bar

    private var ctaBar: some View {
        VStack(spacing: 6) {
            Button {
                self.dismiss()
                self.onEnable()
            } label: {
                Text("Enable Secret Sharing")
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
