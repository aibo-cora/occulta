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

    @AppStorage("vault.sss.enabled") private var ssEnabled = false

    @Query(sort: \VaultEntry.createdAt, order: .reverse) private var entries: [VaultEntry]

    @State private var filter: Filter = .all
    @State private var showNewEntry = false
    @State private var unlocking = false

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
        let hasCritical    = affected.contains { $0.status == .critical }
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

            // Attention section — entries with degraded or critical coverage
            if self.filter != .shards, !affected.isEmpty {
                Section {
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
                        Text("\(affected.count)")
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
                                let metadata = try? self.vault.deleteEntry(id: normalEntries[i].id)
                                if let metadata { self.shardCustodyManager?.queueRevokes(from: metadata) }
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

            if self.ssEnabled {
                if self.filter != .personal {
                    Section {
                        Text("Shards appear here once you get one from a contact for custody via .occ.")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .listRowBackground(Color.clear)
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
        }
        .listStyle(.insetGrouped)
        .scrollIndicators(.hidden)
    }

    // MARK: Helpers

    private func unlockVault() {
        self.unlocking = true
        let ctx = LAContext()
        ctx.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Unlock your Vault"
        ) { success, _ in
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
