//
//  VaultShardHealth.swift
//  Occulta
//
//  Shard health summary across all vault entries that have SSS configured.
//  Decrypting ShardDistributionMetadata requires an unlocked vault — if locked,
//  the view shows a biometric prompt before rendering status.
//

import SwiftUI
import SwiftData
import LocalAuthentication

struct VaultShardHealth: View {

    @Environment(VaultManager.self) private var vault
    @Query private var entries: [VaultEntry]

    @State private var unlocking = false

    private var entriesWithShards: [VaultEntry] {
        entries.filter { $0.shardDistributionEncrypted != nil }
    }

    // Pairs (entry, metadata, label, type) for all entries we could decrypt.
    private var decoded: [(entry: VaultEntry, meta: ShardDistributionMetadata, label: String, type: VaultEntryType)] {
        guard vault.isUnlocked else { return [] }
        return entriesWithShards.compactMap { entry in
            guard let meta    = try? vault.shardDistributionMetadata(for: entry.id) else { return nil }
            let payload = try? vault.decryptLabelPayload(for: entry)
            return (entry, meta, payload?.label ?? "–", payload?.type ?? .note)
        }
    }

    private var atRiskCount: Int {
        decoded.filter { (_, meta, _, _) in
            let active = meta.shards.filter { $0.status == .pending || $0.status == .confirmed }.count
            return active < meta.threshold
        }.count
    }

    var body: some View {
        List {
            if !vault.isUnlocked {
                self.lockedSection
            } else if entriesWithShards.isEmpty {
                self.emptySection
            } else {
                if atRiskCount > 0 {
                    self.atRiskBanner
                }
                self.healthSection
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Shard Health")
        .navigationBarTitleDisplayMode(.large)
    }

    // MARK: - Locked state

    private var lockedSection: some View {
        Section {
            VStack(spacing: 16) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(.secondary)
                Text("Vault Locked")
                    .font(.system(size: 16, weight: .semibold))
                Text("Shard status is encrypted with your vault key. Unlock to view.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                Button {
                    self.unlockVault()
                } label: {
                    Group {
                        if self.unlocking {
                            ProgressView().tint(.white)
                        } else {
                            Text("Unlock Vault")
                                .font(.system(size: 15, weight: .semibold))
                        }
                    }
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color.occultaAccent)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
                .disabled(self.unlocking)
            }
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity)
        }
        .listRowBackground(Color.clear)
    }

    // MARK: - Empty state

    private var emptySection: some View {
        Section {
            VStack(spacing: 8) {
                Text("No Shard Distributions")
                    .font(.system(size: 15, weight: .semibold))
                Text("Set up shards from an entry's detail page to start protecting vault keys.")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity)
        }
        .listRowBackground(Color.clear)
    }

    // MARK: - At-risk banner

    private var atRiskBanner: some View {
        Section {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 14))
                    .foregroundStyle(VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)))
                VStack(alignment: .leading, spacing: 3) {
                    Text("Recovery at risk")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)))
                    Text("\(atRiskCount) \(atRiskCount == 1 ? "entry is" : "entries are") below threshold. Tap to redistribute.")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)).opacity(0.85))
                        .lineSpacing(2)
                }
            }
            .padding(.vertical, 4)
            .listRowBackground(VaultEntryType.cat(light: (0xFF, 0xF3, 0xCD), dark: (0x2D, 0x22, 0x00)))
        }
    }

    // MARK: - Health rows

    private var healthSection: some View {
        Section("Entries") {
            ForEach(decoded, id: \.entry.id) { entry, meta, label, type in
                NavigationLink {
                    VaultShardSetup(entryID: entry.id)
                } label: {
                    self.healthRow(meta: meta, label: label, type: type)
                }
            }
        }
    }

    private func healthRow(meta: ShardDistributionMetadata, label: String, type: VaultEntryType) -> some View {
        let active   = meta.shards.filter { $0.status == .pending || $0.status == .confirmed }.count
        let total    = meta.shards.count
        let atRisk   = active < meta.threshold

        return HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(type.tileBackground)
                    .frame(width: 36, height: 36)
                Text(type.emoji)
                    .font(.system(size: 18))
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(label)
                    .font(.system(size: 15))
                    .lineLimit(1)
                HStack(spacing: 4) {
                    Circle()
                        .fill(atRisk
                              ? VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66))
                              : Color.occultaVerified)
                        .frame(width: 6, height: 6)
                    Text(atRisk
                         ? "\(active) of \(meta.threshold) required — below threshold"
                         : "\(active) of \(total) active")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(atRisk
                                         ? VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66))
                                         : Color.secondary)
                }
            }
        }
        .padding(.vertical, 2)
    }

    // MARK: - Unlock

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
