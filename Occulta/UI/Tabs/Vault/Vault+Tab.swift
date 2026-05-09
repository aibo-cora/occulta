//
//  Vault+Tab.swift
//  Occulta
//

import SwiftUI
import SwiftData
import LocalAuthentication

// MARK: - VaultEntryType UI helpers

extension VaultEntryType {
    var emoji: String {
        switch self {
        case .seedPhrase: "🌱"
        case .note:       "📝"
        case .keyToken:   "🔑"
//        case .document:   "📄"
//        case .photo:      "🖼️"
        }
    }

    var displayName: String {
        switch self {
        case .seedPhrase: "Seed Phrase"
        case .note:       "Secure Note"
        case .keyToken:   "Key Token"
//        case .document:   "Document"
//        case .photo:      "Photo"
        }
    }

    var tileTint: Color {
        switch self {
        case .seedPhrase:
            // Deep legible purple in light mode + bright in dark
            Self.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF))
        case .note:
            Color(red: 0x88/255, green: 0x44/255, blue: 0x94/255)  // Keep for now or make adaptive if pale
        case .keyToken:
            .occultaWarn
//        case .document:
//            Color(red: 0x1A/255, green: 0x6D/255, blue: 0xB5/255)  // Good blue
//        case .photo:
//            .occultaAccent
        }
    }

    // Improved backgrounds: better contrast in light mode
    var tileBackground: Color {
        switch self {
        case .seedPhrase:
            Self.cat(light: (0xE8, 0xF0, 0xE0), dark: (0x1F, 0x2E, 0x1F))   // Softer green tint
        case .note:
            Self.cat(light: (0xF0, 0xF0, 0xFA), dark: (0x1C, 0x1B, 0x2E))   // Soft lavender
        case .keyToken:
            Self.cat(light: (0xFA, 0xF0, 0xF0), dark: (0x2E, 0x1C, 0x1C))   // Soft warm red
//        case .document:
//            Self.cat(light: (0xF0, 0xF4, 0xFA), dark: (0x1C, 0x2A, 0x38))   // Soft blue
//        case .photo:
//            Self.cat(light: (0xF8, 0xF0, 0xFA), dark: (0x2A, 0x1C, 0x2E))   // Soft purple
        }
    }

    static func cat(light l: (Int, Int, Int), dark d: (Int, Int, Int)) -> Color {
        Color(UIColor { traitCollection in
            traitCollection.userInterfaceStyle == .dark
                ? UIColor(red: CGFloat(d.0)/255, green: CGFloat(d.1)/255, blue: CGFloat(d.2)/255, alpha: 1.0)
                : UIColor(red: CGFloat(l.0)/255, green: CGFloat(l.1)/255, blue: CGFloat(l.2)/255, alpha: 1.0)
        })
    }
}

// MARK: - VaultTab

struct VaultTab: View {
    @Environment(VaultManager.self) private var vault
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?

    @Query(sort: \VaultEntry.createdAt, order: .reverse) private var entries: [VaultEntry]
    @Query private var rawCustodyShards: [CustodyShard]
    @Query private var allContacts: [Contact.Profile]

    @AppStorage("vault.postRestoreActionNeeded") private var postRestoreActionNeeded = false

    @State private var filter: Filter = .all
    @State private var showNewEntry = false
    @State private var unlocking = false
    @State private var showExportEducation = false
    @State private var showPostRestoreSheet = false
    @State private var showBEKSetup = false

    private enum Filter: String, CaseIterable {
        case all      = "All"
        case personal = "Personal"
        case shards   = "Shards"
    }

    var body: some View {
        NavigationStack {
            Group {
                if self.vault.isUnlocked {
                    self.list
                } else {
                    self.lockGate
                }
            }
            .navigationTitle("Vault")
            .toolbar {
                if self.vault.isUnlocked {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button { self.showNewEntry = true } label: {
                            Image(systemName: "plus")
                        }
                        .tint(.occultaAccent)
                    }
                }
            }
            .sheet(isPresented: $showNewEntry) {
                VaultNewEntrySheet()
            }
            .navigationDestination(for: UUID.self) { id in
                VaultEntryDetail(entryID: id)
            }
            .navigationDestination(isPresented: $showExportEducation) {
                BackupExportEducationView { self.startExport() }
            }
            .navigationDestination(isPresented: $showBEKSetup) {
                VaultShardSetup(mode: .backup)
            }
            .sheet(isPresented: $showPostRestoreSheet) {
                VaultPostRestoreSheet {
                    self.postRestoreActionNeeded = false
                } onSetupBackup: {
                    self.postRestoreActionNeeded = false
                    self.showPostRestoreSheet    = false
                    self.showBEKSetup            = true
                }
            }
            .onChange(of: self.vault.isUnlocked) { _, isUnlocked in
                if isUnlocked && self.postRestoreActionNeeded {
                    self.showPostRestoreSheet = true
                }
            }
            .onChange(of: self.postRestoreActionNeeded) { _, newValue in
                if newValue && self.vault.isUnlocked {
                    self.showPostRestoreSheet = true
                }
            }
        }
    }

    // MARK: Lock gate

    private var lockGate: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 52))
                .foregroundStyle(.secondary)

            VStack(spacing: 8) {
                Text("Vault Locked")
                    .font(.title2.bold())
                Text("Protected by Face ID and a dedicated\nSecure Enclave key.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            Button {
                self.unlockVault()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "faceid")
                    Text("Unlock Vault")
                        .font(.system(size: 16, weight: .semibold))
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 28)
                .padding(.vertical, 13)
                .background(Capsule().fill(Color.occultaAccent))
            }
            .buttonStyle(.plain)
            .disabled(self.unlocking)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemGroupedBackground))
    }

    // MARK: Entry list

    private var list: some View {
        let affected       = self.vault.recoveryHealth?.affected ?? []
        let affectedIDs    = Set(affected.map(\.entryID))
        let normalEntries  = self.entries.filter { !affectedIDs.contains($0.id) }

        // BEK erosion: non-nil when distribution exists but confirmed < threshold.
        let bekAffected: (confirmed: Int, threshold: Int)? = {
            if case .waitingForConfirmations(let c, let t) = self.vault.bekSetupState {
                return (c, t)
            }
            return nil
        }()

        let stale      = self.vault.backupStaleness
        let staleCount = stale.map {
            ($0.bekRotated ? 1 : 0) + ($0.newEntryCount > 0 ? 1 : 0) + ($0.trusteeSetChanged ? 1 : 0)
        } ?? 0

        let hasCritical    = affected.contains { $0.status == .critical }
                          || bekAffected.map { $0.confirmed == 0 } ?? false
                          || stale?.bekRotated == true
        let attentionColor = hasCritical ? Color.red : Color.occultaWarn

        return List {
            Section {
                Picker("Filter", selection: $filter) {
                    ForEach(Filter.allCases, id: \.self) { f in
                        Text(f.rawValue).tag(f)
                    }
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
            }

            // Pending restore section — shown while a .occbak file awaits BEK shard collection
            if self.vault.pendingRestoreActive {
                Section {
                    HStack(spacing: 12) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 9)
                                .fill(Color.occultaAccent.opacity(0.12))
                                .frame(width: 36, height: 36)
                            Image(systemName: "arrow.down.circle")
                                .font(.system(size: 16))
                                .foregroundStyle(Color.occultaAccent)
                        }
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Restoring your vault")
                                .font(.system(size: 16, weight: .medium))
                            Text("\(self.vault.pendingRestoreShardCount) recovery pieces collected")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(Color.occultaAccent)
                        }
                        Spacer()
                    }
                    .padding(.vertical, 3)
                } header: {
                    HStack(spacing: 6) {
                        ProgressView()
                            .scaleEffect(0.7)
                            .tint(Color.occultaAccent)
                        Text("Recovery in Progress")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .tracking(1.6)
                            .foregroundStyle(Color.occultaAccent)
                    }
                } footer: {
                    Text("Open Occulta near your trustees to collect recovery pieces.")
                        .font(.system(size: 10, design: .monospaced))
                }
            }

            // Attention section — entries with degraded or critical coverage + BEK erosion + stale backup
            if self.filter != .shards, !affected.isEmpty || bekAffected != nil || staleCount > 0 {
                Section {
                    // Stale backup rows — one per active staleness reason
                    if let s = stale {
                        if s.bekRotated {
                            Button { self.showExportEducation = true } label: {
                                VaultBackupStaleRow(
                                    title:      "Backup can't be restored",
                                    subtitle:   "Backup key changed — re-export required",
                                    isCritical: true
                                )
                            }
                            .buttonStyle(.plain)
                        }
                        if s.newEntryCount > 0 {
                            Button { self.showExportEducation = true } label: {
                                VaultBackupStaleRow(
                                    title:      "\(s.newEntryCount) \(s.newEntryCount == 1 ? "entry" : "entries") not in backup",
                                    subtitle:   "Export a new backup to include them",
                                    isCritical: false
                                )
                            }
                            .buttonStyle(.plain)
                        }
                        if s.trusteeSetChanged {
                            Button { self.showExportEducation = true } label: {
                                VaultBackupStaleRow(
                                    title:      "Trustee set changed",
                                    subtitle:   "Backup coverage has shifted — re-export",
                                    isCritical: false
                                )
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    if let bek = bekAffected {
                        NavigationLink {
                            VaultShardSetup(mode: .backup)
                        } label: {
                            VaultBEKAttentionRow(confirmed: bek.confirmed, threshold: bek.threshold)
                        }
                    }
                    ForEach(affected, id: \.entryID) { item in
                        NavigationLink(value: item.entryID) {
                            VaultAffectedEntryRow(item: item)
                        }
                    }
                } header: {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(attentionColor)
                        Text("Needs Attention")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .tracking(1.6)
                            .foregroundStyle(attentionColor)
                        Spacer()
                        Text("\(affected.count + (bekAffected != nil ? 1 : 0) + staleCount)")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                }
            }

            // Personal entries (excludes entries already shown in attention section)
            if self.filter != .shards {
                Section {
                    if self.entries.isEmpty {
                        Text("No entries yet. Tap + to add one.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .listRowBackground(Color.clear)
                    } else {
                        ForEach(normalEntries) { entry in
                            NavigationLink(value: entry.id) {
                                VaultEntryRow(entry: entry)
                            }
                        }
                        .onDelete { offsets in
                            for i in offsets {
                                _ = try? self.vault.deleteEntry(id: normalEntries[i].id)
                            }
                        }
                    }
                } header: {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(Color.occultaVerified)
                            .frame(width: 7, height: 7)
                        Text("Personal")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .tracking(1.6)
                        if !self.entries.isEmpty {
                            Spacer()
                            Text("\(self.entries.count)")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundStyle(.tertiary)
                        }
                    }
                } footer: {
                    if !self.entries.isEmpty {
                        Text("\(self.entries.count) \(self.entries.count == 1 ? "entry" : "entries") · se-bound · this device only")
                            .font(.system(size: 10, design: .monospaced))
                    }
                }
            }

            // Backup recovery row — always visible in personal/all filter
            if self.filter != .shards {
                Section {
                    NavigationLink {
                        VaultShardSetup(mode: .backup)
                    } label: {
                        VaultBackupRow(state: self.vault.bekSetupState)
                    }
                } footer: {
                    if self.vault.bekSetupState == .ready {
                        Button {
                            self.showExportEducation = true
                        } label: {
                            Label("Export backup file", systemImage: "square.and.arrow.up")
                                .font(.system(size: 12, design: .monospaced))
                        }
                        .tint(Color.occultaAccent)
                    }
                }
            }

            if self.filter != .personal && !self.rawCustodyShards.isEmpty {
                Section {
                    if self.rawCustodyShards.isEmpty {
                        Text("Shards appear here once you get one from a contact for custody via .occ.")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .listRowBackground(Color.clear)
                    } else {
                        ForEach(self.custodianRows, id: \.ownerIdentifier) { row in
                            HStack(spacing: 12) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 9)
                                        .fill(Color(red: 0x3C/255, green: 0x34/255, blue: 0x89/255).opacity(0.15))
                                        .frame(width: 36, height: 36)
                                    Image(systemName: "shield.fill")
                                        .font(.system(size: 15))
                                        .foregroundStyle(Color(red: 0x3C/255, green: 0x34/255, blue: 0x89/255))
                                }
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(row.ownerName)
                                        .font(.system(size: 16, weight: .medium))
                                    Text("\(row.count) shard\(row.count == 1 ? "" : "s") in custody")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                            .padding(.vertical, 3)
                        }
                    }
                } header: {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(Color(red: 0x3C/255, green: 0x34/255, blue: 0x89/255))
                            .frame(width: 7, height: 7)
                        Text("Custodian Shards")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .tracking(1.6)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollIndicators(.hidden)
    }

    // MARK: Helpers

    private struct CustodianRow {
        let ownerIdentifier: String
        let ownerName: String
        let count: Int
    }

    private var custodianRows: [CustodianRow] {
        guard let mgr = self.shardCustodyManager else { return [] }
        return mgr.heldShards(from: self.rawCustodyShards)
            .compactMap { info -> CustodianRow? in
                let identifier = info.ownerContactIdentifier ?? ""
                let contact = self.allContacts.first { $0.identifier == identifier }
                let name: String
                if let c = contact {
                    let given  = c.givenName.decrypt()
                    let family = c.familyName.decrypt()
                    name = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
                } else {
                    name = identifier.isEmpty ? "Unknown" : identifier
                }
                return CustodianRow(ownerIdentifier: identifier, ownerName: name, count: info.count)
            }
            .sorted { $0.ownerName < $1.ownerName }
    }

    private func startExport() {
        do {
            let data = try vault.exportBackup()
            let url  = VaultManager.tempBackupURL()
            try data.write(to: url, options: .completeFileProtection)
            BackupPickerPresenter.present(fileURL: url) {
                try? FileManager.default.removeItem(at: url)
                self.showExportEducation = false
            }
        } catch {
            // TODO: surface export error
        }
    }

    private func unlockVault() {
        self.unlocking = true
        let ctx = LAContext()
        
        ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock your Vault") { success, _ in
            DispatchQueue.main.async {
                self.unlocking = false
                
                if success { self.vault.unlock(context: ctx) }
            }
        }
    }
}

// MARK: - Entry Row

private struct VaultEntryRow: View {
    let entry: VaultEntry
    @Environment(VaultManager.self) private var vault

    private var labelPayload: SealedLabelPayload? {
        try? self.vault.decryptLabelPayload(for: self.entry)
    }

    private var hasShards: Bool {
        (try? self.vault.shardDistributionMetadata(for: self.entry.id)) != nil
    }

    var body: some View {
        let payload = self.labelPayload
        let label     = payload?.label ?? "–"
        let entryType = payload?.type  ?? .note

        return HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9)
                    .fill(entryType.tileBackground)
                    .frame(width: 36, height: 36)
                Text(entryType.emoji)
                    .font(.system(size: 18))
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.system(size: 16, weight: .medium))
                    .lineLimit(1)
                Text("\(entryType.displayName) · \(self.entry.createdAt.formatted(date: .abbreviated, time: .omitted))")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            if !self.hasShards {
                Image(systemName: "shield.slash")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary.opacity(0.5))
            }

            Text("SE")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .tracking(0.8)
                .foregroundStyle(Color.occultaVerified)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(entryType.tileBackground)
                .clipShape(RoundedRectangle(cornerRadius: 5))
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Backup Recovery Row

private struct VaultBackupRow: View {
    let state: VaultManager.BEKSetupState

    private var subtitle: String {
        switch state {
        case .notSetup:
            return "Set up to enable export"
        case .waitingForConfirmations(let confirmed, let threshold):
            return "\(confirmed) of \(threshold) trustees confirmed"
        case .ready:
            return "Ready to export"
        }
    }

    private var accentColor: Color {
        switch state {
        case .notSetup:                  .secondary
        case .waitingForConfirmations:   .occultaWarn
        case .ready:                     .occultaVerified
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9)
                    .fill(Color(.secondarySystemFill))
                    .frame(width: 36, height: 36)
                Image(systemName: "archivebox")
                    .font(.system(size: 16))
                    .foregroundStyle(accentColor)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("Backup Recovery")
                    .font(.system(size: 16, weight: .medium))
                    .lineLimit(1)
                Text(subtitle)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(accentColor)
                    .lineLimit(1)
            }

            Spacer()
        }
        .padding(.vertical, 3)
        .opacity(state == .notSetup ? 0.45 : 1.0)
    }
}

// MARK: - BEK Attention Row

private struct VaultBEKAttentionRow: View {
    let confirmed: Int
    let threshold: Int

    private var isCritical: Bool { confirmed == 0 }
    private var accentColor: Color { isCritical ? .red : .occultaWarn }

    private var subtitleText: String {
        isCritical
            ? "backup recovery unavailable"
            : "\(confirmed) of \(threshold) backup recovery pieces"
    }

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9)
                    .fill(Color(.secondarySystemFill))
                    .frame(width: 36, height: 36)
                Image(systemName: "archivebox")
                    .font(.system(size: 16))
                    .foregroundStyle(accentColor)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("Backup Recovery")
                    .font(.system(size: 16, weight: .medium))
                    .lineLimit(1)
                Text(subtitleText)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(accentColor)
                    .lineLimit(1)
            }

            Spacer()

            Image(systemName: isCritical ? "exclamationmark.circle.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 14))
                .foregroundStyle(accentColor)
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Backup Stale Row

private struct VaultBackupStaleRow: View {
    let title:      String
    let subtitle:   String
    let isCritical: Bool

    private var accentColor: Color { isCritical ? .red : .occultaWarn }

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9)
                    .fill(Color(.secondarySystemFill))
                    .frame(width: 36, height: 36)
                Image(systemName: "archivebox")
                    .font(.system(size: 16))
                    .foregroundStyle(accentColor)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 16, weight: .medium))
                    .lineLimit(1)
                Text(subtitle)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(accentColor)
                    .lineLimit(1)
            }
            Spacer()
            Image(systemName: isCritical ? "exclamationmark.circle.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 14))
                .foregroundStyle(accentColor)
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Affected Entry Row

private struct VaultAffectedEntryRow: View {
    let item: RecoveryHealthSummary.AffectedEntry

    private var accentColor: Color {
        item.status == .critical ? .red : .occultaWarn
    }

    private var subtitleText: String {
        switch item.status {
        case .critical: "recovery unavailable"
        case .degraded: "\(item.active) of \(item.threshold) recovery pieces"
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9)
                    .fill(item.entryType.tileBackground)
                    .frame(width: 36, height: 36)
                Text(item.entryType.emoji)
                    .font(.system(size: 18))
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(item.label)
                    .font(.system(size: 16, weight: .medium))
                    .lineLimit(1)
                Text(subtitleText)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(accentColor)
                    .lineLimit(1)
            }

            Spacer()

            Image(systemName: item.status == .critical
                  ? "exclamationmark.circle.fill"
                  : "exclamationmark.triangle.fill")
                .font(.system(size: 14))
                .foregroundStyle(accentColor)
        }
        .padding(.vertical, 3)
    }
}
