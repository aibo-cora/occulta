//
//  Vault+ShardSetup.swift
//  Occulta
//
//  V5: status chips, manual revocation, dirty tracking, context-aware CTA.
//

import SwiftUI
import SwiftData

struct VaultShardSetup: View {
    let entryID: UUID

    @Environment(VaultManager.self) private var vault
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Environment(\.dismiss) private var dismiss

    @Query(sort: \Contact.Profile.familyName) private var allContacts: [Contact.Profile]
    @Query private var globalConfigRows: [GlobalShardConfig]

    @State private var selectedIDs: Set<String> = []
    @State private var threshold = 2
    @State private var marking = false
    @State private var error: String?
    @State private var distributionMeta: ShardDistributionMetadata? = nil
    @State private var snapshotIDs: Set<String> = []
    @State private var snapshotThreshold: Int = 2
    @State private var confirmationMessage: String? = nil
    @State private var revokeTarget: ShardRecord? = nil

    /// Shards in these two states count toward active recovery coverage.
    private static let activeStatuses: Set<ShardStatus> = [.pending, .confirmed]

    /// Live set of contact IDs in the user's global trustee config.
    /// Recomputed whenever `globalConfigRows` changes — reactive badge display.
    private var globalTrusteeIDs: Set<String> {
        guard
            let row     = globalConfigRows.first,
            let payload = try? shardCustodyManager?.decryptGlobalConfig(row)
        else { return [] }
        return Set(payload.trusteeIDs)
    }

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

    private var hasExistingDistribution: Bool { distributionMeta != nil }

    private var isDirty: Bool {
        selectedIDs != snapshotIDs || threshold != snapshotThreshold
    }

    private var ctaTitle: String {
        if !hasExistingDistribution { return "Mark for Distribution" }
        return isDirty ? "Update Distribution" : "Up to date"
    }

    private var ctaEnabled: Bool {
        canMark && (!hasExistingDistribution || isDirty)
    }

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
        .onAppear { self.seedInitialState() }
        .confirmationDialog(
            "Revoke Shard",
            isPresented: Binding(
                get: { revokeTarget != nil },
                set: { if !$0 { revokeTarget = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Revoke", role: .destructive) {
                if let target = revokeTarget { self.revokeShard(target) }
                revokeTarget = nil
            }
            Button("Cancel", role: .cancel) { revokeTarget = nil }
        } message: {
            Text("The shard will be remotely erased from the trustee's device on their next interaction.")
        }
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
                    confirmationMessage = nil
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
                    confirmationMessage = nil
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
        let record = shardRecord(for: contact.identifier)
        // A contact is selectable if they have no shard record yet, or their shard
        // is in an active (non-revoked/non-lost) state.
        let isSelectable = record.map { Self.activeStatuses.contains($0.status) } ?? true

        return Button {
            guard isSelectable else { return }
            if sel {
                selectedIDs.remove(contact.identifier)
                threshold = max(2, min(threshold, selectedIDs.count))
            } else {
                selectedIDs.insert(contact.identifier)
            }
            confirmationMessage = nil
        } label: {
            HStack(spacing: 12) {
                contactAvatar(contact, size: 36)

                VStack(alignment: .leading, spacing: 3) {
                    Text(name.isEmpty ? contact.identifier : name)
                        .font(.system(size: 15))
                        .foregroundStyle(isSelectable ? .primary : .secondary)
                    HStack(spacing: 4) {
                        Text("ML-KEM · verified key")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color(red: 0x36/255, green: 0x62/255, blue: 0xA6/255).opacity(0.13))
                            .foregroundStyle(Color(red: 0x36/255, green: 0x62/255, blue: 0xA6/255))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                        if globalTrusteeIDs.contains(contact.identifier) {
                            Text("GLOBAL")
                                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Color.secondary.opacity(0.12))
                                .foregroundStyle(Color.secondary)
                                .clipShape(RoundedRectangle(cornerRadius: 3))
                        }
                        if let record = record {
                            let style = statusChipStyle(for: record.status)
                            Text(style.label)
                                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(style.bg)
                                .foregroundStyle(style.fg)
                                .clipShape(RoundedRectangle(cornerRadius: 3))
                        }
                    }
                }

                Spacer()

                if isSelectable {
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
                } else {
                    Color.clear.frame(width: 24, height: 24)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
        .buttonStyle(.plain)
        .contextMenu {
            if let record = record, Self.activeStatuses.contains(record.status) {
                Button(role: .destructive) {
                    revokeTarget = record
                } label: {
                    Label("Revoke Shard", systemImage: "xmark.circle")
                }
            }
        }
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
            if let msg = confirmationMessage, !isDirty {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
                    Text(msg)
                        .font(.system(size: 14, weight: .medium, design: .monospaced))
                }
                .foregroundStyle(Color.occultaAccent)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(Color.occultaAccent.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            } else {
                Button(action: self.markForDistribution) {
                    Group {
                        if self.marking {
                            ProgressView().tint(.white)
                        } else {
                            Text(ctaTitle)
                                .font(.system(size: 16, weight: .semibold))
                        }
                    }
                    .foregroundStyle(ctaEnabled ? .white : Color.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(ctaEnabled ? Color.occultaAccent : Color(.secondarySystemFill))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .shadow(color: ctaEnabled ? Color.occultaAccent.opacity(0.27) : .clear, radius: 10, y: 4)
                }
                .buttonStyle(.plain)
                .disabled(!ctaEnabled || marking)

                if canMark {
                    Text("Shards will be delivered automatically with your next message.")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Color.secondary.opacity(0.6))
                        .multilineTextAlignment(.center)
                }
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

    // MARK: - Helpers

    private func shardRecord(for contactIdentifier: String) -> ShardRecord? {
        distributionMeta?.shards.first { $0.contactIdentifier == contactIdentifier }
    }

    private func statusChipStyle(for status: ShardStatus) -> (label: String, bg: Color, fg: Color) {
        switch status {
        case .pending:
            return ("PENDING",   Color.orange.opacity(0.15),          Color.orange)
        case .confirmed:
            return ("CONFIRMED", Color.occultaVerified.opacity(0.15), Color.occultaVerified)
        case .revokePending:
            return ("REVOKING",  Color.red.opacity(0.12),             Color.red)
        case .revoked:
            return ("REVOKED",   Color.secondary.opacity(0.12),       Color.secondary)
        case .lost:
            return ("LOST",      Color.red.opacity(0.12),             Color.red)
        }
    }

    // MARK: - Initial state seeding

    /// Populate working state on first appear.
    ///
    /// - Existing distribution: seed selectedIDs and threshold from the persisted
    ///   ShardDistributionMetadata, using only active (.pending/.confirmed) shards.
    /// - New entry (no distribution): seed selectedIDs from the global trustee config
    ///   if set; threshold stays at its default of 2.
    private func seedInitialState() {
        distributionMeta = try? vault.shardDistributionMetadata(for: entryID)
        if let meta = distributionMeta {
            let activeIDs = Set(meta.shards
                .filter { Self.activeStatuses.contains($0.status) }
                .map { $0.contactIdentifier })
            selectedIDs       = activeIDs
            threshold         = meta.threshold
            snapshotIDs       = activeIDs
            snapshotThreshold = meta.threshold
        } else if !globalTrusteeIDs.isEmpty {
            selectedIDs = globalTrusteeIDs
        }
    }

    // MARK: - Actions

    private func markForDistribution() {
        self.marking = true
        self.error = nil
        
        do {
            // Capture old attrIDs BEFORE prepareShards overwrites the metadata.
            // Contacts staying in the distribution get a .replace op; new ones get .distribute.
            var oldAttrIDs: [String: UUID] = [:]
            
            if let existingMeta = try? self.vault.shardDistributionMetadata(for: self.entryID) {
                let newIDs  = Set(selected.map(\.identifier))
                let removed = existingMeta.shards.filter {
                    !newIDs.contains($0.contactIdentifier)
                        && $0.status != .revoked
                        && $0.status != .revokePending
                        && $0.status != .lost
                }
                for shard in removed {
                    try? self.shardCustodyManager?.queueRevoke(attributeID: shard.attributeID, for: shard.contactIdentifier, vaultManager: self.vault)
                }
                for shard in existingMeta.shards where newIDs.contains(shard.contactIdentifier) {
                    oldAttrIDs[shard.contactIdentifier] = shard.attributeID
                }
            }

            let attributes = try self.vault.prepareShards(
                for:        self.entryID,
                threshold:  self.k,
                recipients: self.selected
            )
            for (contact, attribute) in zip(self.selected, attributes) {
                try? shardCustodyManager?.queueDistribute(
                    attribute: attribute,
                    for:       contact.identifier,
                    replacing: oldAttrIDs[contact.identifier]
                )
            }
            // Reload metadata and update snapshot so isDirty becomes false.
            self.distributionMeta = try? vault.shardDistributionMetadata(for: entryID)
            let activeIDs = Set(
                distributionMeta?.shards
                    .filter { Self.activeStatuses.contains($0.status) }
                    .map { $0.contactIdentifier } ?? []
            )
            self.snapshotIDs       = activeIDs
            self.snapshotThreshold = self.k
            self.marking           = false
            self.confirmationMessage = "Shards queued for delivery."
        } catch VaultManager.VaultError.locked {
            self.error   = "Vault locked — unlock and try again."
            self.marking = false
        } catch {
            self.error   = "Failed: \(error.localizedDescription)"
            self.marking = false
        }
    }

    private func revokeShard(_ record: ShardRecord) {
        do {
            try self.shardCustodyManager?.queueRevoke(attributeID: record.attributeID, for: record.contactIdentifier, vaultManager: self.vault)
            // Reload metadata so the status chip updates immediately.
            self.distributionMeta = try? self.vault.shardDistributionMetadata(for: self.entryID)
            // Remove from selection so the UI reflects the change.
            self.selectedIDs.remove(record.contactIdentifier)
            self.snapshotIDs.remove(record.contactIdentifier)
            
            self.confirmationMessage = nil
        } catch {
            self.error = "Revoke failed: \(error.localizedDescription)"
        }
    }
}
