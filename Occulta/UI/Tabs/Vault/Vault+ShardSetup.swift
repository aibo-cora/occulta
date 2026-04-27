//
//  Vault+ShardSetup.swift
//  Occulta
//
//  V4 "Trust-first" shard distribution.
//  Single ML-KEM list, stacked avatar pile, "any k" stepper, Mark for Distribution CTA.
//

import SwiftUI
import SwiftData

struct VaultShardSetup: View {
    let entryID: UUID

    @Environment(VaultManager.self) private var vault
    @Environment(\.dismiss) private var dismiss

    @Query(sort: \Contact.Profile.familyName) private var allContacts: [Contact.Profile]

    @State private var selectedIDs: Set<String> = []
    @State private var threshold = 2
    @State private var marking = false
    @State private var error: String?

    private var mlkemContacts: [Contact.Profile] {
        allContacts.filter { $0.contactPublicKeys?.last?.quantumKeyMaterialEncrypted != nil }
    }

    private var selected: [Contact.Profile] {
        mlkemContacts.filter { selectedIDs.contains($0.identifier) }
    }

    // k is always in [2, max(2, n)] — clamped on every render.
    private var k: Int {
        max(2, min(threshold, max(2, selected.count)))
    }

    private var canMark: Bool { selected.count >= 2 }

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                summaryCard
                    .padding(.horizontal, 16)
                    .padding(.bottom, 12)

                trusteesHeader
                    .padding(.bottom, 6)

                trusteesCard
                    .padding(.horizontal, 16)

                Spacer().frame(height: 10)

                infoNote
                    .padding(.horizontal, 16)

                backupNote
                    .padding(.horizontal, 16)
                    .padding(.top, 6)

                if let err = error {
                    Text(err)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color.occultaDanger)
                        .padding(.horizontal, 16)
                        .padding(.top, 8)
                }

                Spacer().frame(height: 8)
            }
            .padding(.top, 8)
        }
        .navigationTitle("Shard Distribution")
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Done") { self.dismiss() }
                    .tint(.occultaAccent)
            }
        }
        .safeAreaInset(edge: .bottom) { ctaBar }
    }

    // MARK: - Summary card

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Avatar stack + trustee count
            HStack(spacing: 12) {
                if selected.isEmpty {
                    Circle()
                        .strokeBorder(Color.secondary.opacity(0.35), style: StrokeStyle(lineWidth: 1.5, dash: [4]))
                        .frame(width: 32, height: 32)
                        .overlay {
                            Image(systemName: "plus")
                                .font(.system(size: 13, weight: .medium))
                                .foregroundStyle(.secondary)
                        }
                } else {
                    avatarStack
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(selected.isEmpty
                         ? "No trustees yet"
                         : "\(selected.count) \(selected.count == 1 ? "trustee" : "trustees")")
                        .font(.system(size: 16, weight: .semibold))

                    Text(selected.count < 2
                         ? "Select ≥ 2 trustees below"
                         : "any \(k) of \(selected.count) can reconstruct")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(.bottom, 14)

            Divider()
                .padding(.bottom, 14)

            // Threshold label
            Text("Reconstruction threshold")
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .tracking(1.5)
                .textCase(.uppercase)
                .foregroundStyle(Color.secondary.opacity(0.55))
                .padding(.bottom, 8)

            // Stepper
            HStack(spacing: 10) {
                Button {
                    threshold = max(2, threshold - 1)
                } label: {
                    Circle()
                        .fill(Color(.secondarySystemFill))
                        .frame(width: 36, height: 36)
                        .overlay {
                            Text("−")
                                .font(.system(size: 20))
                                .foregroundStyle(k > 2 ? Color.primary : Color.secondary)
                        }
                }
                .buttonStyle(.plain)

                Spacer()

                Button {
                    threshold = min(max(selected.count, 2), threshold + 1)
                } label: {
                    Circle()
                        .fill(Color(.secondarySystemFill))
                        .frame(width: 36, height: 36)
                        .overlay {
                            Text("+")
                                .font(.system(size: 20))
                                .foregroundStyle(k < selected.count ? Color.primary : Color.secondary)
                        }
                }
                .buttonStyle(.plain)
            }

            if canMark {
                Text("Any **\(k)** of your \(selected.count) trustees — in any combination — can help reconstruct. No specific trustee is required.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineSpacing(2)
                    .padding(10)
                    .background(Color(.secondarySystemFill))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .padding(.top, 12)
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    // MARK: - Trustees section

    private var trusteesHeader: some View {
        HStack(spacing: 6) {
            Text("ML-KEM")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(Color(red: 0x36/255, green: 0x62/255, blue: 0xA6/255).opacity(0.13))
                .foregroundStyle(Color(red: 0x36/255, green: 0x62/255, blue: 0xA6/255))
                .clipShape(RoundedRectangle(cornerRadius: 3))

            Text("Eligible Trustees")
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .tracking(1.6)
                .foregroundStyle(.secondary)

            Spacer()

            Text("\(mlkemContacts.count)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Color.secondary.opacity(0.5))
        }
        .padding(.horizontal, 20)
    }

    private var trusteesCard: some View {
        VStack(spacing: 0) {
            if mlkemContacts.isEmpty {
                Text("No ML-KEM contacts yet. Exchange keys with a contact first.")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                ForEach(Array(mlkemContacts.enumerated()), id: \.element.identifier) { idx, contact in
                    trusteeRow(contact)
                    if idx < mlkemContacts.count - 1 {
                        Divider().padding(.leading, 62)
                    }
                }
            }
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func trusteeRow(_ contact: Contact.Profile) -> some View {
        let given  = contact.givenName.decrypt()
        let family = contact.familyName.decrypt()
        let name   = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        let sel    = selectedIDs.contains(contact.identifier)

        return Button {
            if sel {
                selectedIDs.remove(contact.identifier)
                threshold = max(2, min(threshold, selectedIDs.count))
            } else {
                selectedIDs.insert(contact.identifier)
            }
        } label: {
            HStack(spacing: 12) {
                contactAvatar(contact, size: 36)

                VStack(alignment: .leading, spacing: 3) {
                    Text(name.isEmpty ? contact.identifier : name)
                        .font(.system(size: 15))
                        .foregroundStyle(.primary)
                    Text("ML-KEM · verified key")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Color(red: 0x36/255, green: 0x62/255, blue: 0xA6/255).opacity(0.13))
                        .foregroundStyle(Color(red: 0x36/255, green: 0x62/255, blue: 0xA6/255))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }

                Spacer()

                ZStack {
                    Circle()
                        .fill(sel ? Color.occultaAccent : Color.clear)
                    Circle()
                        .strokeBorder(sel ? Color.occultaAccent : Color.secondary.opacity(0.35), lineWidth: 1.5)
                    if sel {
                        Image(systemName: "checkmark")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.white)
                    }
                }
                .frame(width: 24, height: 24)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Info note

    private var infoNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Text("🔮")
                .font(.system(size: 14))
            VStack(alignment: .leading, spacing: 4) {
                Text("Information-theoretic security")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(VaultEntryType.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF)))
                Text("Fewer than \(k) shards reveal zero information. Perfect secrecy over GF(2⁸) — not computational hardness.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(VaultEntryType.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF)).opacity(0.85))
                    .lineSpacing(2)
            }
        }
        .padding(12)
        .background(VaultEntryType.cat(light: (0xEE, 0xED, 0xFE), dark: (0x1e, 0x1c, 0x38)))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Backup note

    private var backupNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Text("⚠️")
                .font(.system(size: 14))
            VStack(alignment: .leading, spacing: 4) {
                Text("Key recovery only")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)))
                Text("Shards protect your encryption key — not the entry content. To recover your content after device loss, export a separate vault backup.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)).opacity(0.85))
                    .lineSpacing(2)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VaultEntryType.cat(light: (0xFF, 0xF3, 0xCD), dark: (0x2D, 0x22, 0x00)))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - CTA bar

    private var ctaBar: some View {
        VStack(spacing: 6) {
            Button(action: self.markForDistribution) {
                Group {
                    if self.marking {
                        ProgressView().tint(.white)
                    } else {
                        Text("Mark for Distribution")
                            .font(.system(size: 16, weight: .semibold))
                    }
                }
                .foregroundStyle(canMark ? .white : Color.secondary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(canMark ? Color.occultaAccent : Color(.secondarySystemFill))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .shadow(color: canMark ? Color.occultaAccent.opacity(0.27) : .clear, radius: 10, y: 4)
            }
            .buttonStyle(.plain)
            .disabled(!canMark || marking)

            if canMark {
                Text("Shards will be delivered automatically with your next message.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Color.secondary.opacity(0.6))
                    .multilineTextAlignment(.center)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.bar)
    }

    // MARK: - Avatar stack

    private var avatarStack: some View {
        let maxVis   = 7
        let visible  = Array(selected.prefix(maxVis))
        let overflow = selected.count > maxVis ? selected.count - maxVis : 0

        return HStack(spacing: -10) {
            ForEach(Array(visible.enumerated()), id: \.offset) { i, contact in
                contactAvatar(contact, size: 32)
                    .zIndex(Double(maxVis - i))
            }
            if overflow > 0 {
                ZStack {
                    Circle().fill(Color(.secondarySystemFill))
                    Circle().strokeBorder(Color(.systemBackground), lineWidth: 2)
                    Text("+\(overflow)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .frame(width: 32, height: 32)
                .zIndex(0)
            }
        }
    }

    @ViewBuilder
    private func contactAvatar(_ contact: Contact.Profile, size: CGFloat) -> some View {
        let given = contact.givenName.decrypt()
        let family = contact.familyName.decrypt()
        let name  = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        let inits = name.isEmpty
            ? String(contact.identifier.prefix(2)).uppercased()
            : name.initials

        ZStack {
            Circle().fill(avatarGradientV2(for: contact.identifier))
            Text(inits)
                .font(.system(size: size * 0.36, weight: .semibold, design: .monospaced))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .overlay(Circle().strokeBorder(Color(.systemBackground), lineWidth: 2))
    }

    // MARK: - Action

    private func markForDistribution() {
        self.marking = true
        self.error   = nil
        do {
            _ = try self.vault.prepareShards(
                for:        self.entryID,
                threshold:  self.k,
                recipients: self.selected
            )
            self.dismiss()
        } catch VaultManager.VaultError.locked {
            self.error   = "Vault locked — unlock and try again."
            self.marking = false
        } catch {
            self.error   = "Failed: \(error.localizedDescription)"
            self.marking = false
        }
    }
}
