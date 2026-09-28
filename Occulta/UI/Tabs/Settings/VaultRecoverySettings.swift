//
//  VaultRecoverySettings.swift
//  Occulta
//
//  Vault recovery health dashboard — accessible from Settings › Vault Recovery.
//  Surfaces two layers of recovery readiness:
//
//    • Backup key — its shard status (threshold met → backups restorable)
//    • Backup — Staleness report for the last exported .occbak file
//
//  Requires vault unlocked for backup-key data. Shows an inline unlock button if locked.
//  Per-entry key health went with per-entry splitting (`decisions.md`, "Retire per-entry
//  splitting").
//

import SwiftUI
import LocalAuthentication

struct VaultRecoverySettings: View {

    @Environment(VaultManager.self) private var vault
    @Environment(Manager.Security.self) private var security
    @State private var unlocking = false

    // Amber consistent with the rest of the vault UI.
    private static let amber = VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66))

    var body: some View {
        List {
            self.bekSection
            self.backupSection
            self.configSection
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Vault Recovery")
        .navigationBarTitleDisplayMode(.large)
        .scrollIndicators(.hidden)
        .onAppear {
            self.vault.extendSession()
            // backupStaleness and backupErosion are both depth-scoped; this view can be
            // reached without ever visiting Vault+Tab first, so it must refresh its
            // own copies rather than rely on that tab having already done it.
            if self.vault.isUnlocked {
                self.vault.refreshBackupStaleness(currentDepth: self.security.currentDepth)
                self.vault.refreshBackupErosion(currentDepth: self.security.currentDepth)
            }
        }
        .onChange(of: self.vault.isUnlocked) { _, isUnlocked in
            if isUnlocked {
                self.vault.refreshBackupStaleness(currentDepth: self.security.currentDepth)
                self.vault.refreshBackupErosion(currentDepth: self.security.currentDepth)
            }
        }
    }

    // MARK: - BEK

    private var bekSection: some View {
        Section {
            if !vault.isUnlocked {
                self.lockedRow(reason: "Unlock the vault to see backup key status.")
            } else {
                self.bekStatusRow
            }
        } header: {
            Text("Backup Key")
        } footer: {
            Text("Your backup key encrypts exported backups. Trustees each hold a piece of it, so it can be rebuilt if this device is lost.")
        }
    }

    @ViewBuilder
    private var bekStatusRow: some View {
        let state = self.vault.backupSetupState(currentDepth: self.security.currentDepth)
        switch state {
        case .notSetup:
            statusRow(dot: .occultaDanger,
                      label: "Not configured",
                      sub: "Not set up yet. Choose trustees in Backup Key Trustees to create it.")
        case .waitingForConfirmations(let confirmed, let threshold):
            statusRow(dot: Self.amber,
                      label: "Awaiting confirmations",
                      sub: "\(confirmed) of \(threshold) confirmed · trustees confirm with their next direct message to you")
        case .ready:
            statusRow(dot: .occultaVerified,
                      label: "Ready",
                      sub: "Threshold met — backup key is restorable")
        }
    }

    // MARK: - Backup

    private var backupSection: some View {
        Section {
            self.backupStatusRow
            NavigationLink {
                VaultShardSetup()
            } label: {
                Label("Backup Key Trustees", systemImage: "person.3.fill")
            }
        } header: {
            Text("Vault Backup")
        } footer: {
            Text("Trustees' pieces rebuild your backup key, not your entries. Keep an exported backup file too: it holds the entries, and the key opens it.")
        }
    }

    @ViewBuilder
    private var backupStatusRow: some View {
        if let s = vault.backupStaleness {
            if s.bekRotated {
                statusRow(dot: .occultaDanger,
                          label: "Backup can't be restored",
                          sub: "Backup key changed — export a new backup")
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
