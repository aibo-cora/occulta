//
//  Vault+Tab.swift
//  Occulta
//
//  Root NavigationStack for the Vault tab.
//  Shows a lock gate when the vault is locked; the entry list when unlocked.
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
        case .document:   "📄"
        case .photo:      "🖼️"
        }
    }

    var displayName: String {
        switch self {
        case .seedPhrase: "Seed Phrase"
        case .note:       "Secure Note"
        case .keyToken:   "Key Token"
        case .document:   "Document"
        case .photo:      "Photo"
        }
    }

    var tileTint: Color {
        switch self {
        case .seedPhrase: .occultaVerified
        case .note:       Color(red: 0x88/255, green: 0x44/255, blue: 0x94/255)
        case .keyToken:   .occultaWarn
        case .document:   Color(red: 0x1A/255, green: 0x6D/255, blue: 0xB5/255)
        case .photo:      .occultaAccent
        }
    }
}

// MARK: - VaultTab

struct VaultTab: View {
    @Environment(VaultManager.self) private var vault

    @Query(sort: \VaultEntry.createdAt, order: .reverse) private var entries: [VaultEntry]

    @State private var filter: Filter = .all
    @State private var showNewEntry  = false
    @State private var unlocking     = false

    private enum Filter: String, CaseIterable {
        case all      = "All"
        case personal = "Personal"
        case shards   = "Shards"
    }

    var body: some View {
        NavigationStack {
            Group {
                if vault.isUnlocked {
                    list
                } else {
                    lockGate
                }
            }
            .navigationTitle("Vault")
            .toolbar {
                if vault.isUnlocked {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button { showNewEntry = true } label: {
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
                unlockVault()
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
            .disabled(unlocking)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemGroupedBackground))
    }

    // MARK: Entry list

    private var list: some View {
        List {
            // Segment control
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

            // Personal entries
            if filter != .shards {
                Section {
                    if entries.isEmpty {
                        Text("No entries yet. Tap + to add one.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .listRowBackground(Color.clear)
                    } else {
                        ForEach(entries) { entry in
                            NavigationLink(value: entry.id) {
                                VaultEntryRow(entry: entry)
                            }
                        }
                        .onDelete { offsets in
                            for i in offsets { try? vault.deleteEntry(id: entries[i].id) }
                        }
                    }
                } header: {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(Color.occultaVerified)
                            .frame(width: 7, height: 7)
                        Text("Personal")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .tracking(1.4)
                        if !entries.isEmpty {
                            Spacer()
                            Text("\(entries.count)")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundStyle(.tertiary)
                        }
                    }
                } footer: {
                    if !entries.isEmpty {
                        Text("\(entries.count) \(entries.count == 1 ? "entry" : "entries") · se-bound · this device only")
                            .font(.system(size: 11, design: .monospaced))
                    }
                }
            }

            // Shards held for you (received from contacts via .occ)
            if filter != .personal {
                Section {
                    Text("Shards held for you appear here once\ncontacts deliver them via .occ.")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .listRowBackground(Color.clear)
                } header: {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(Color(red: 0x3C/255, green: 0x34/255, blue: 0x89/255))
                            .frame(width: 7, height: 7)
                        Text("Shards Held for You")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .tracking(1.4)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollIndicators(.hidden)
    }

    // MARK: Helpers

    private func unlockVault() {
        unlocking = true
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

    private var label: String {
        (try? vault.decryptLabel(for: entry)) ?? entry.type.displayName
    }

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9)
                    .fill(entry.type.tileTint.opacity(0.15))
                    .frame(width: 36, height: 36)
                Text(entry.type.emoji)
                    .font(.system(size: 18))
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.system(size: 16, weight: .medium))
                    .lineLimit(1)
                Text("\(entry.type.displayName) · \(entry.createdAt.formatted(date: .abbreviated, time: .omitted))")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            Text("SE")
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(Color.occultaVerified)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(Color.occultaVerified.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 5))
        }
        .padding(.vertical, 3)
    }
}
