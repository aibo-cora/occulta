//
//  VaultRecoverySettings.swift
//  Occulta
//
//  Vault recovery health dashboard — accessible from Settings › Vault Recovery.
//  Surfaces three layers of recovery readiness:
//
//    • BEK  — Backup Encryption Key shard status (threshold met → backups restorable)
//    • PEKs — Per-entry key shard health (how many entries are below threshold)
//    • Backup — Staleness report for the last exported .occbak file
//
//  Requires vault unlocked for BEK + PEK data. Shows an inline unlock button if locked.
//

import SwiftUI
import LocalAuthentication

struct VaultRecoverySettings: View {

    @Environment(VaultManager.self) private var vault
    @State private var unlocking = false

    // Amber consistent with the rest of the vault UI.
    private static let amber = VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66))

    var body: some View {
        List {
            self.bekSection
            self.pekSection
            self.backupSection
            self.configSection
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Vault Recovery")
        .navigationBarTitleDisplayMode(.large)
    }

    // MARK: - BEK

    private var bekSection: some View {
        Section {
            if !vault.isUnlocked {
                self.lockedRow(reason: "BEK status requires vault access.")
            } else {
                self.bekStatusRow
            }
        } header: {
            Text("Backup Encryption Key")
        } footer: {
            Text("The BEK encrypts exported vault backups. Distribute its shards to trustees so the key can be reconstructed if this device is lost.")
        }
    }

    @ViewBuilder
    private var bekStatusRow: some View {
        let state = vault.bekSetupState
        switch state {
        case .notSetup:
            statusRow(dot: .occultaDanger,
                      label: "Not configured",
                      sub: "BEK not set up. Export a backup to generate one.")
        case .waitingForConfirmations(let confirmed, let threshold):
            statusRow(dot: Self.amber,
                      label: "Awaiting confirmations",
                      sub: "\(confirmed) of \(threshold) required trustees confirmed")
        case .ready:
            statusRow(dot: .occultaVerified,
                      label: "Ready",
                      sub: "Threshold met — backup key is restorable")
        }
    }

    // MARK: - PEKs

    private var pekSection: some View {
        Section {
            if !vault.isUnlocked {
                self.lockedRow(reason: "Entry key health requires vault access.")
            } else {
                self.pekSummaryRow
            }
        } header: {
            Text("Per-Entry Keys")
        } footer: {
            Text("Each vault entry is encrypted with its own key (PEK). Distribute shards per entry so individual keys can be reconstructed independently.")
        }
    }

    @ViewBuilder
    private var pekSummaryRow: some View {
        let affected = vault.recoveryHealth?.affected ?? []
        let critical = affected.filter { $0.status == .critical }.count
        let degraded = affected.filter { $0.status == .degraded }.count

        NavigationLink {
            VaultShardHealth()
        } label: {
            if critical > 0 {
                statusRow(dot: .occultaDanger,
                          label: "\(critical) \(critical == 1 ? "entry" : "entries") critical",
                          sub: "No active trustees — key unrecoverable")
            } else if degraded > 0 {
                statusRow(dot: Self.amber,
                          label: "\(degraded) \(degraded == 1 ? "entry" : "entries") degraded",
                          sub: "Below threshold — add or re-send shards")
            } else {
                statusRow(dot: .occultaVerified,
                          label: "All entries healthy",
                          sub: "Every distributed key meets its threshold")
            }
        }
    }

    // MARK: - Backup

    private var backupSection: some View {
        Section {
            self.backupStatusRow
            NavigationLink {
                VaultShardSetup(mode: .backup)
            } label: {
                Label("Backup Key Trustees", systemImage: "person.3.fill")
            }
        } header: {
            Text("Vault Backup")
        } footer: {
            Text("Shards protect your encryption keys — not your content. A vault backup is required to recover entry content after device loss.")
        }
    }

    @ViewBuilder
    private var backupStatusRow: some View {
        if let s = vault.backupStaleness {
            if s.bekRotated {
                statusRow(dot: .occultaDanger,
                          label: "BEK rotated",
                          sub: "Existing backup file is permanently unrestorable")
            } else if s.newEntryCount > 0 {
                statusRow(dot: Self.amber,
                          label: "\(s.newEntryCount) new \(s.newEntryCount == 1 ? "entry" : "entries") missing",
                          sub: "Export a new backup to include them")
            } else if s.trusteeSetChanged {
                statusRow(dot: Self.amber,
                          label: "Trustee set changed",
                          sub: "Re-export to capture the updated distribution")
            } else {
                statusRow(dot: .occultaVerified,
                          label: "Backup current",
                          sub: "No changes since last export")
            }
        } else {
            statusRow(dot: .secondary,
                      label: "No issues detected",
                      sub: "Backup is current or vault not yet exported")
        }
    }

    // MARK: - Configuration

    private var configSection: some View {
        Section("Configuration") {
            NavigationLink {
                VaultGlobalTrustees()
            } label: {
                Label("Global Trustees", systemImage: "person.3.fill")
            }
        }
    }

    // MARK: - Shared components

    private func statusRow(dot: Color, label: String, sub: String) -> some View {
        HStack(spacing: 12) {
            Circle()
                .fill(dot)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 3) {
                Text(label)
                    .font(.system(size: 15))
                Text(sub)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }

    private func lockedRow(reason: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "lock.fill")
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text("Vault Locked")
                    .font(.system(size: 15))
                Text(reason)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(action: self.unlockVault) {
                if self.unlocking {
                    ProgressView().tint(Color.occultaAccent)
                } else {
                    Text("Unlock")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Color.occultaAccent)
                }
            }
            .buttonStyle(.plain)
            .disabled(self.unlocking)
        }
        .padding(.vertical, 2)
    }

    // MARK: - Biometric unlock

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
