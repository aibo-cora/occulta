//
//  Vault+PostRestore+Sheet.swift
//  Occulta
//
//  Shown on the first vault unlock after a successful backup restore.
//  Guides the user through the three steps needed to restore full protection.
//

import SwiftUI

struct VaultPostRestoreSheet: View {

    /// Called when the user taps Done. Caller clears the post-restore flag.
    let onDone: () -> Void

    /// Called when the user taps "Set up backup recovery". Caller dismisses the
    /// sheet and pushes VaultShardSetup(mode: .backup) onto the NavigationStack.
    let onSetupBackup: () -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {

                // ── Success header ────────────────────────────────────────────
                Section {
                    HStack(spacing: 14) {
                        ZStack {
                            Circle()
                                .fill(Color.occultaVerified.opacity(0.14))
                                .frame(width: 52, height: 52)
                            Image(systemName: "checkmark.shield.fill")
                                .font(.system(size: 24))
                                .foregroundStyle(Color.occultaVerified)
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Vault Restored")
                                .font(.system(size: 17, weight: .semibold))
                            Text("Your entries have been recovered. Complete these steps to restore full protection.")
                                .font(.system(size: 13))
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.vertical, 8)
                }
                .listRowBackground(Color.clear)

                // ── Next steps ────────────────────────────────────────────────
                Section {
                    self.infoRow(
                        icon: "person.2.fill",
                        iconColor: Color.occultaAccent,
                        title: "Re-add your contacts",
                        subtitle: "Open Occulta near each person to re-establish secure sessions. Your contact book lives on your devices, not in the backup."
                    )

                    Button {
                        self.onSetupBackup()
                    } label: {
                        self.actionRow(
                            icon: "archivebox.fill",
                            iconColor: Color.occultaWarn,
                            title: "Set up backup recovery",
                            subtitle: "Distribute your backup key to trustees so future restores are covered."
                        )
                    }
                    .tint(.primary)

                    self.infoRow(
                        icon: "key.fill",
                        iconColor: .secondary,
                        title: "Redistribute entry shards",
                        subtitle: "Any flagged entries in your vault list need new recovery pieces. Tap each one to reshare."
                    )
                } header: {
                    Text("Next Steps")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .tracking(1.6)
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Restore Complete")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        self.onDone()
                        self.dismiss()
                    }
                    .tint(Color.occultaAccent)
                }
            }
        }
    }

    // MARK: - Row helpers

    @ViewBuilder
    private func infoRow(icon: String, iconColor: Color, title: String, subtitle: String) -> some View {
        HStack(spacing: 12) {
            self.iconBadge(icon: icon, color: iconColor)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(.primary)
                Text(subtitle)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private func actionRow(icon: String, iconColor: Color, title: String, subtitle: String) -> some View {
        HStack(spacing: 12) {
            self.iconBadge(icon: icon, color: iconColor)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 16, weight: .medium))
                Text(subtitle)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private func iconBadge(icon: String, color: Color) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 9)
                .fill(color.opacity(0.12))
                .frame(width: 36, height: 36)
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundStyle(color)
        }
        .fixedSize()
    }
}
