//
//  VaultGlobalTrustees.swift
//  Occulta
//
//  Global trustee configuration for Secret Sharing.
//  Selections here pre-populate VaultShardSetup when setting up shards for a
//  new vault entry. Per-entry configuration can always override these defaults.
//
//  Storage: GlobalShardConfig (SwiftData), AES-GCM sealed under the shard
//  custody key. Read and written through ShardCustodyManager.
//

import SwiftUI
import SwiftData

struct VaultGlobalTrustees: View {

    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Query(sort: \Contact.Profile.familyName) private var allContacts: [Contact.Profile]
    @Environment(\.dismiss) private var dismiss

    @State private var selectedIDs: Set<String> = []
    @State private var threshold: Int = 2
    @State private var saveError: String?

    private var mlkemContacts: [Contact.Profile] {
        allContacts.filter { $0.contactPublicKeys?.last?.quantumKeyMaterialEncrypted != nil }
    }

    private var selected: [Contact.Profile] {
        mlkemContacts.filter { selectedIDs.contains($0.identifier) }
    }

    private var k: Int {
        max(2, min(threshold, max(2, selected.count)))
    }

    private var canSave: Bool { selected.count >= 2 }

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                self.summaryCard
                    .padding(.horizontal, 16)
                    .padding(.bottom, 12)

                self.trusteesHeader
                    .padding(.bottom, 6)

                self.trusteesCard
                    .padding(.horizontal, 16)

                Spacer().frame(height: 10)

                self.scopeNote
                    .padding(.horizontal, 16)

                if let err = saveError {
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
        .navigationTitle("Global Trustees")
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Save") { self.save() }
                    .tint(.occultaAccent)
                    .disabled(!self.canSave)
            }
        }
        .onAppear { self.loadConfig() }
    }

    // MARK: - Summary card (mirrors VaultShardSetup)

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                if self.selected.isEmpty {
                    Circle()
                        .strokeBorder(Color.secondary.opacity(0.35), style: StrokeStyle(lineWidth: 1.5, dash: [4]))
                        .frame(width: 32, height: 32)
                        .overlay {
                            Image(systemName: "plus")
                                .font(.system(size: 13, weight: .medium))
                                .foregroundStyle(.secondary)
                        }
                } else {
                    self.avatarStack
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(self.selected.isEmpty
                         ? "No trustees yet"
                         : "\(self.selected.count) \(self.selected.count == 1 ? "trustee" : "trustees")")
                        .font(.system(size: 16, weight: .semibold))
                    Text(self.selected.count < 2
                         ? "Select ≥ 2 trustees below"
                         : "any \(self.k) of \(self.selected.count) can reconstruct")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.bottom, 14)

            Divider().padding(.bottom, 14)

            Text("Reconstruction threshold")
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .tracking(1.5)
                .textCase(.uppercase)
                .foregroundStyle(Color.secondary.opacity(0.55))
                .padding(.bottom, 8)

            HStack(spacing: 10) {
                Button {
                    self.threshold = max(2, self.threshold - 1)
                } label: {
                    Circle()
                        .fill(Color(.secondarySystemFill))
                        .frame(width: 36, height: 36)
                        .overlay {
                            Text("−")
                                .font(.system(size: 20))
                                .foregroundStyle(self.k > 2 ? Color.primary : Color.secondary)
                        }
                }
                .buttonStyle(.plain)

                Spacer()

                Button {
                    self.threshold = min(max(self.selected.count, 2), self.threshold + 1)
                } label: {
                    Circle()
                        .fill(Color(.secondarySystemFill))
                        .frame(width: 36, height: 36)
                        .overlay {
                            Text("+")
                                .font(.system(size: 20))
                                .foregroundStyle(self.k < self.selected.count ? Color.primary : Color.secondary)
                        }
                }
                .buttonStyle(.plain)
            }

            if self.canSave {
                Text("Any **\(self.k)** of your \(self.selected.count) trustees — in any combination — can help reconstruct. No specific trustee is required.")
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
            if self.mlkemContacts.isEmpty {
                Text("No ML-KEM contacts yet. Exchange keys with a contact first.")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                ForEach(Array(mlkemContacts.enumerated()), id: \.element.identifier) { idx, contact in
                    self.trusteeRow(contact)
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
                self.contactAvatar(contact, size: 36)

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
                    Circle().fill(sel ? Color.occultaAccent : Color.clear)
                    Circle().strokeBorder(sel ? Color.occultaAccent : Color.secondary.opacity(0.35), lineWidth: 1.5)
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

    // MARK: - Scope note

    private var scopeNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "info.circle")
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
            Text("These trustees will be suggested when you set up shards for a new vault entry. You can override them per entry.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineSpacing(2)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 10))
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
        let given  = contact.givenName.decrypt()
        let family = contact.familyName.decrypt()
        let name   = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        let inits  = name.isEmpty
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

    // MARK: - Load / save

    private func loadConfig() {
        guard let config = try? shardCustodyManager?.globalShardConfig() else { return }
        selectedIDs = Set(config.trusteeIDs)
        threshold   = config.threshold
    }

    private func save() {
        let payload = GlobalShardConfig.Payload(
            trusteeIDs: Array(selectedIDs),
            threshold:  k
        )
        do {
            try shardCustodyManager?.saveGlobalShardConfig(payload)
            dismiss()
        } catch {
            saveError = "Failed to save: \(error.localizedDescription)"
        }
    }
}
