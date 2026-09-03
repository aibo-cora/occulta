//
//  Vault+ShardSetup.swift
//  Occulta
//
//  V5: status chips, manual revocation, dirty tracking, context-aware CTA.
//

import SwiftUI
import SwiftData

struct VaultShardSetup: View {
    enum Mode {
        case entry(UUID)
        case backup
    }

    let mode: Mode

    @Environment(VaultManager.self) private var vault
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Environment(ContactManager.self) private var contactManager
    @Environment(\.dismiss) private var dismiss

    @Query private var vaultEntries: [VaultEntry]
    @Query private var bekRows:      [BackupEncryptionKey]

    @State private var selectedIDs: Set<String> = []
    @State private var threshold = 2
    @State private var marking = false
    @State private var error: String?
    @State private var snapshotIDs: Set<String> = []
    @State private var snapshotThreshold: Int = 2
    @State private var confirmationMessage: String? = nil
    @State private var revokeTarget: ShardRecord? = nil

    /// Shards in these two states count toward active recovery coverage.
    private static let activeStatuses: Set<ShardStatus> = [.pending, .confirmed]

    /// Live set of contact IDs in the user's global trustee config, at the current
    /// depth. Reads `Contact.Profile.globalTrusteeDepth` exact-matches — the single
    /// mechanism at every depth, including depth 0 (see the shard-custody bug doc,
    /// item 3). A duress-created entry's suggestions can never leak trustees
    /// designated at a different depth.
    private var globalTrusteeIDs: Set<String> {
        self.contactManager.globalTrusteeIdentifiers()
    }

    private var mlkemContacts: [Contact.Profile] {
        self.contactManager.mlkemEligibleContacts()
    }

    private var isDirty: Bool {
        self.selectedIDs != self.snapshotIDs || self.threshold != self.snapshotThreshold
    }

    var body: some View {
        let meta       = self.fetchDistributionMeta()
        let contacts   = self.mlkemContacts
        let trusteeIDs = self.globalTrusteeIDs
        let selected   = contacts.filter { self.selectedIDs.contains($0.identifier) }
        let k          = max(2, min(self.threshold, max(2, selected.count)))
        let canMark    = selected.count >= 2

        return ScrollView {
            VStack(spacing: 0) {
                self.summaryCard(selected: selected, k: k)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 12)

                self.trusteesHeader(contacts: contacts)
                    .padding(.bottom, 6)

                self.trusteesCard(contacts: contacts, meta: meta, trusteeIDs: trusteeIDs)
                    .padding(.horizontal, 16)

                Spacer().frame(height: 10)

                self.infoNote(k: k)
                    .padding(.horizontal, 16)

                self.contextNote(k: k)
                    .padding(.horizontal, 16)
                    .padding(.top, 6)

                if let err = self.error {
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
        .navigationTitle({
            switch self.mode {
            case .entry: "Shard Distribution"
            case .backup: "Backup Recovery"
            }
        }())
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Done") { self.dismiss() }
                    .tint(.occultaAccent)
            }
        }
        .safeAreaInset(edge: .bottom) { self.ctaBar(meta: meta, canMark: canMark) }
        .onAppear { self.seedInitialState() }
        .confirmationDialog(
            "Revoke Shard",
            isPresented: Binding(
                get: { self.revokeTarget != nil },
                set: { if !$0 { self.revokeTarget = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Revoke", role: .destructive) {
                if let target = self.revokeTarget { self.revokeShard(target) }
                self.revokeTarget = nil
            }
            Button("Cancel", role: .cancel) { self.revokeTarget = nil }
        } message: {
            Text("The shard will be remotely erased from the trustee's device on their next interaction.")
        }
    }

    // MARK: - Summary card

    private func summaryCard(selected: [Contact.Profile], k: Int) -> some View {
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
                    self.avatarStack(selected: selected)
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
                    self.threshold = max(2, self.threshold - 1)
                    self.confirmationMessage = nil
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
                    self.threshold = min(max(selected.count, 2), self.threshold + 1)
                    self.confirmationMessage = nil
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

            if selected.count >= 2 {
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

    private func trusteesHeader(contacts: [Contact.Profile]) -> some View {
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

            Text("\(contacts.count)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Color.secondary.opacity(0.5))
        }
        .padding(.horizontal, 20)
    }

    private func trusteesCard(contacts: [Contact.Profile], meta: ShardDistributionMetadata?, trusteeIDs: Set<String>) -> some View {
        VStack(spacing: 0) {
            if contacts.isEmpty {
                Text("No ML-KEM contacts yet. Exchange keys with a contact first.")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                ForEach(Array(contacts.enumerated()), id: \.element.identifier) { idx, contact in
                    self.trusteeRow(contact, meta: meta, trusteeIDs: trusteeIDs)
                    if idx < contacts.count - 1 {
                        Divider().padding(.leading, 62)
                    }
                }
            }
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func trusteeRow(_ contact: Contact.Profile, meta: ShardDistributionMetadata?, trusteeIDs: Set<String>) -> some View {
        let given  = contact.givenName.decrypt()
        let family = contact.familyName.decrypt()
        let name   = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        let sel    = self.selectedIDs.contains(contact.identifier)
        let record = self.shardRecord(for: contact.identifier, in: meta)
        // A contact is selectable if he has no shard record yet, or their shard
        // is in an active (non-revoked/non-lost) state.
        let isSelectable = record.map { Self.activeStatuses.contains($0.status) } ?? true

        return Button {
            guard isSelectable else { return }
            if sel {
                self.selectedIDs.remove(contact.identifier)
                self.threshold = max(2, min(self.threshold, self.selectedIDs.count))
            } else {
                self.selectedIDs.insert(contact.identifier)
            }
            self.confirmationMessage = nil
        } label: {
            HStack(spacing: 12) {
                self.contactAvatar(contact, size: 36)

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
                        if trusteeIDs.contains(contact.identifier) {
                            Text("GLOBAL")
                                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Color.secondary.opacity(0.12))
                                .foregroundStyle(Color.secondary)
                                .clipShape(RoundedRectangle(cornerRadius: 3))
                        }
                        if let record = record {
                            let style = self.statusChipStyle(for: record.status)
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
                    self.revokeTarget = record
                } label: {
                    Label("Revoke Shard", systemImage: "xmark.circle")
                }
            }
        }
    }

    // MARK: - Info note

    private func infoNote(k: Int) -> some View {
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

    // MARK: - Context note

    private func contextNote(k: Int) -> some View {
        let amber   = VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66))
        let amberBg = VaultEntryType.cat(light: (0xFF, 0xF3, 0xCD), dark: (0x2D, 0x22, 0x00))

        let title: String
        let body:  String
        switch self.mode {
        case .entry:
            title = "Key recovery only"
            body  = "Shards protect your encryption key — not the entry content. Export a separate vault backup to recover content after device loss. Any k trustees together can reconstruct your key — pick people who are independent of each other."
        case .backup:
            title = "Export gate"
            body  = "Export becomes available once \(k) trustees confirm receipt. A trustee who hasn't confirmed cannot return their piece during recovery."
        }

        return HStack(alignment: .top, spacing: 8) {
            Text("⚠️")
                .font(.system(size: 14))
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(amber)
                Text(body)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(amber.opacity(0.85))
                    .lineSpacing(2)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(amberBg)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - CTA bar

    private func ctaBar(meta: ShardDistributionMetadata?, canMark: Bool) -> some View {
        let dirty = self.isDirty

        return VStack(spacing: 6) {
            if let msg = self.confirmationMessage, !dirty {
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
                let hasExisting = meta != nil
                let title = !hasExisting ? "Mark for Distribution" : (dirty ? "Update Distribution" : "Up to date")
                let enabled = canMark && (!hasExisting || dirty)

                DistributionCTAButton(
                    title:     title,
                    enabled:   enabled,
                    isMarking: self.marking,
                    canMark:   canMark,
                    action:    self.markForDistribution
                )
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.bar)
    }

    // MARK: - Avatar stack

    private func avatarStack(selected: [Contact.Profile]) -> some View {
        let maxVis   = 7
        let visible  = Array(selected.prefix(maxVis))
        let overflow = selected.count > maxVis ? selected.count - maxVis : 0

        return HStack(spacing: -10) {
            ForEach(Array(visible.enumerated()), id: \.offset) { i, contact in
                self.contactAvatar(contact, size: 32)
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

    private func shardRecord(for contactIdentifier: String, in meta: ShardDistributionMetadata?) -> ShardRecord? {
        meta?.shards.first { $0.contactIdentifier == contactIdentifier }
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

    // MARK: - Mode helpers

    /// Fetches the current shard-distribution metadata for this entry (or BEK).
    /// Not cached — call once per need (once in `body`, once each in the action
    /// methods below) rather than from a redundantly-read computed property.
    /// `VaultManager.shardDistributionMetadata(for:)` already derives its own
    /// vault key once per call internally; the fix here is call frequency, not
    /// key derivation.
    private func fetchDistributionMeta() -> ShardDistributionMetadata? {
        switch self.mode {
        case .entry(let id):
            _ = self.vaultEntries
            return try? self.vault.shardDistributionMetadata(for: id)
        case .backup:
            _ = self.bekRows
            return try? self.vault.bekShardMetadata()
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
        if case .backup = self.mode { try? self.vault.setupBEK() }

        if let meta = self.fetchDistributionMeta() {
            let activeIDs = Set(meta.shards
                .filter { Self.activeStatuses.contains($0.status) }
                .map { $0.contactIdentifier })
            self.selectedIDs       = activeIDs
            self.threshold         = meta.threshold
            self.snapshotIDs       = activeIDs
            self.snapshotThreshold = meta.threshold
        } else if !self.globalTrusteeIDs.isEmpty {
            self.selectedIDs = self.globalTrusteeIDs
        }
    }

    // MARK: - Actions

    private func markForDistribution() {
        self.marking = true
        self.error = nil

        let contacts = self.mlkemContacts
        let selected = contacts.filter { self.selectedIDs.contains($0.identifier) }
        let k        = max(2, min(self.threshold, max(2, selected.count)))

        do {
            // Capture old attrIDs BEFORE prepareShards overwrites the metadata.
            // Contacts staying in the distribution get a .replace op; new ones get .distribute.
            var oldAttrIDs: [String: UUID] = [:]

            if let existingMeta = self.fetchDistributionMeta() {
                let newIDs  = Set(selected.map(\.identifier))
                let removed = existingMeta.shards.filter {
                    !newIDs.contains($0.contactIdentifier)
                        && $0.status != .revoked
                        && $0.status != .revokePending
                        && $0.status != .lost
                }
                for shard in removed {
                    try? self.vault.updateShardStatus(attributeID: shard.attributeID, to: .revoked)
                }
                for shard in existingMeta.shards where newIDs.contains(shard.contactIdentifier) {
                    oldAttrIDs[shard.contactIdentifier] = shard.attributeID
                }
            }

            let attributes = try self.performPrepareShards(k: k, recipients: selected)
            for (contact, attribute) in zip(selected, attributes) {
                try self.shardCustodyManager?.queueDistribute(
                    attribute: attribute,
                    for:       contact.identifier,
                    replacing: oldAttrIDs[contact.identifier]
                )
            }
            let activeIDs = Set(
                self.fetchDistributionMeta()?.shards
                    .filter { Self.activeStatuses.contains($0.status) }
                    .map { $0.contactIdentifier } ?? []
            )
            self.snapshotIDs       = activeIDs
            self.snapshotThreshold = k
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

    /// Call the correct prepare function for the current mode.
    private func performPrepareShards(k: Int, recipients: [Contact.Profile]) throws -> [SignedAttribute] {
        switch self.mode {
        case .entry(let id): return try self.vault.prepareShards(for: id, threshold: k, recipients: recipients)
        case .backup:        return try self.vault.prepareBEKShards(threshold: k, recipients: recipients)
        }
    }

    private func revokeShard(_ record: ShardRecord) {
        do {
            try self.vault.updateShardStatus(attributeID: record.attributeID, to: .revoked)
            // Remove from selection so the UI reflects the change.
            self.selectedIDs.remove(record.contactIdentifier)
            self.snapshotIDs.remove(record.contactIdentifier)
            self.confirmationMessage = nil
        } catch {
            self.error = "Revoke failed: \(error.localizedDescription)"
        }
    }
}

// MARK: - Distribution CTA button

private struct DistributionCTAButton: View {
    let title:     String
    let enabled:   Bool
    let isMarking: Bool
    let canMark:   Bool
    let action:    () -> Void

    var body: some View {
        VStack(spacing: 6) {
            Button(action: self.action) {
                SwiftUI.Group {
                    if self.isMarking {
                        ProgressView().tint(.white)
                    } else {
                        Text(self.title)
                            .font(.system(size: 16, weight: .semibold))
                    }
                }
                .foregroundStyle(self.enabled ? .white : Color.secondary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(self.enabled ? Color.occultaAccent : Color(.secondarySystemFill))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .shadow(color: self.enabled ? Color.occultaAccent.opacity(0.27) : .clear, radius: 10, y: 4)
            }
            .buttonStyle(.plain)
            .disabled(!self.enabled || self.isMarking)

            if self.canMark {
                Text("Shards will be delivered automatically with your next message.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Color.secondary.opacity(0.6))
                    .multilineTextAlignment(.center)
            }
        }
    }
}
