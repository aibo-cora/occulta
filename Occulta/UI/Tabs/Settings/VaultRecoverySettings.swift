//
//  VaultRecoverySettings.swift
//  Occulta
//
//  Settings hub for Secret Sharing (SSS). Accessible from Settings.swift.
//  Controls the user-facing toggle that gates all SSS UI across the app.
//
//  Toggle semantics:
//  - Enabling: vault must be unlocked (biometric gate). If locked, triggers
//    authentication first, then presents the mandatory educational sheet.
//    The toggle only commits after the user reads the sheet and taps "Enable".
//  - Disabling: confirmation alert. Distributed shards are NOT revoked —
//    the alert makes this explicit.
//
//  State storage:
//  - `vault.sss.enabled` (AppStorage/UserDefaults Bool) — master gate read by
//    Vault+Tab and Vault+NewEntrySheet.
//  - Global trustee configuration lives in VaultGlobalTrustees (AppStorage).
//

import SwiftUI
import LocalAuthentication

struct VaultRecoverySettings: View {

    @AppStorage("vault.sss.enabled") private var ssEnabled = false
    @Environment(VaultManager.self) private var vault

    @State private var showEducation    = false
    @State private var showDisableAlert = false

    var body: some View {
        List {
            self.toggleSection
            if self.ssEnabled { self.configSection }
            self.backupSection
        }
        .navigationTitle("Secret Sharing")
        .navigationBarTitleDisplayMode(.large)
        .sheet(isPresented: self.$showEducation) {
            VaultSSSEducationSheet {
                self.ssEnabled = true
            } onCancel: {
                // sheet dismissed without confirming — toggle stays off
            }
        }
        .alert("Disable Secret Sharing?", isPresented: self.$showDisableAlert) {
            Button("Disable", role: .destructive) { self.ssEnabled = false }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The Secret Sharing interface will be hidden. Shards already distributed to trustees are not revoked — they remain valid until you revoke them from each entry's settings.")
        }
    }

    // MARK: - Toggle section

    private var toggleSection: some View {
        Section {
            Toggle(isOn: self.toggleBinding) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Enable Secret Sharing")
                    Text("Split vault entry keys across trusted contacts")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if !self.ssEnabled {
                Text("When enabled, you can split a vault entry's encryption key into shards and distribute them to trusted contacts. Any k of n trustees can reconstruct the key if you need to recover.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Configuration section (visible only when enabled)

    private var configSection: some View {
        Section("Configuration") {
            NavigationLink {
                VaultGlobalTrustees()
            } label: {
                Label("Global Trustees", systemImage: "person.3")
            }
            NavigationLink {
                VaultShardHealth()
            } label: {
                Label("Shard Health", systemImage: "waveform.path.ecg")
            }
        }
    }

    // MARK: - Backup section (always visible)

    private var backupSection: some View {
        Section {
            HStack {
                Label("Export Vault Backup", systemImage: "square.and.arrow.up")
                Spacer()
                Text("Coming soon")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .foregroundStyle(.secondary)

            Text("Shards protect your encryption keys — not your content. A separate vault backup is required to recover entry content after device loss.")
                .font(.caption)
                .foregroundStyle(.secondary)
        } header: {
            Text("Vault Backup")
        }
    }

    // MARK: - Toggle binding with vault-lock gate

    private var toggleBinding: Binding<Bool> {
        Binding(
            get: { self.ssEnabled },
            set: { newValue in
                guard newValue else {
                    self.showDisableAlert = true
                    return
                }
                if self.vault.isUnlocked {
                    self.showEducation = true
                } else {
                    self.unlockThenShowEducation()
                }
            }
        )
    }

    private func unlockThenShowEducation() {
        let ctx = LAContext()
        ctx.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Unlock to enable Secret Sharing"
        ) { success, _ in
            DispatchQueue.main.async {
                if success {
                    self.vault.unlock(context: ctx)
                    self.showEducation = true
                }
            }
        }
    }
}
