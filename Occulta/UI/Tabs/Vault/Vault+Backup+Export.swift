//
//  Vault+Backup+Export.swift
//  Occulta
//
//  Two components for the vault backup export flow:
//
//  BackupExportEducationView — mandatory educational sheet shown before every
//  export. Calls onConfirm() when the user taps "I understand — Export".
//  No persistent dismiss; always shown.
//
//  BackupDocumentExporter — UIViewControllerRepresentable wrapping
//  UIDocumentPickerViewController(forExporting:asCopy:). Presents the system
//  save dialog for a pre-written temp .occbak file and cleans up the temp
//  file on dismissal.
//

import SwiftUI
import UniformTypeIdentifiers

// MARK: - Educational sheet

struct BackupExportEducationView: View {
    let onConfirm: () -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {

                    // Hero
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Before you export")
                            .font(.system(size: 22, weight: .bold))
                        Text("Read carefully — this cannot be undone.")
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }

                    // What the file contains
                    infoBlock(
                        icon: "archivebox.fill",
                        iconColor: VaultEntryType.cat(light: (0x5A, 0x4A, 0xB0), dark: (0xB8, 0xA8, 0xFF)),
                        bgColor:   VaultEntryType.cat(light: (0xEE, 0xED, 0xFE), dark: (0x1e, 0x1c, 0x38)),
                        title: "What the file contains",
                        body: "All your vault entries — labels, types, and content — sealed under a key that only your trustees can reconstruct together."
                    )

                    // What it does NOT contain
                    infoBlock(
                        icon: "key.slash",
                        iconColor: VaultEntryType.cat(light: (0x1A, 0x6D, 0xB5), dark: (0x64, 0xD2, 0xFF)),
                        bgColor:   VaultEntryType.cat(light: (0xE5, 0xF3, 0xFF), dark: (0x0a, 0x1e, 0x30)),
                        title: "What it does NOT contain",
                        body: "The decryption key. The backup file is useless on its own. You need at least k trustee recovery pieces to open it."
                    )

                    // Critical warning
                    infoBlock(
                        icon: "exclamationmark.triangle.fill",
                        iconColor: VaultEntryType.cat(light: (0x7A, 0x50, 0x00), dark: (0xFF, 0xCC, 0x66)),
                        bgColor:   VaultEntryType.cat(light: (0xFF, 0xF3, 0xCD), dark: (0x2D, 0x22, 0x00)),
                        title: "Backup file + k trustee pieces = full vault access",
                        body: "Anyone who obtains this file and collects enough recovery pieces from your trustees can decrypt your entire vault. Store it somewhere your trustees cannot access."
                    )

                    // Storage guidance
                    infoBlock(
                        icon: "externaldrive.fill",
                        iconColor: .secondary,
                        bgColor:   Color(.secondarySystemGroupedBackground),
                        title: "Where to store it",
                        body: "A personal encrypted drive, a password manager's secure notes, or a location only you control. Not iCloud if your trustees also have iCloud access to your device."
                    )

                    // CTA
                    Button(action: {
                        dismiss()
                        onConfirm()
                    }) {
                        Text("I understand — Export")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(Color.occultaAccent)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                            .shadow(color: Color.occultaAccent.opacity(0.27), radius: 10, y: 4)
                    }
                    .buttonStyle(.plain)
                    .padding(.top, 4)
                }
                .padding(20)
            }
            .background(Color(.systemGroupedBackground))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { dismiss() }
                        .tint(.occultaAccent)
                }
            }
        }
    }

    @ViewBuilder
    private func infoBlock(
        icon: String,
        iconColor: Color,
        bgColor: Color,
        title: String,
        body: String
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundStyle(iconColor)
                .frame(width: 24)
                .padding(.top, 1)

            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(iconColor)
                Text(body)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(iconColor.opacity(0.85))
                    .lineSpacing(3)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(bgColor)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Document exporter

/// Wraps UIDocumentPickerViewController for saving a .occbak file.
/// Present via .sheet(item: $exportURL) — URL is cleaned up on dismissal.
struct BackupDocumentExporter: UIViewControllerRepresentable {

    /// Temp file URL written by the caller before presenting this sheet.
    let fileURL: URL
    /// Called after the picker dismisses (success or cancel) so the caller
    /// can clean up the temp file and reset state.
    let onDismiss: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onDismiss: onDismiss) }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forExporting: [fileURL], asCopy: true)
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onDismiss: () -> Void
        init(onDismiss: @escaping () -> Void) { self.onDismiss = onDismiss }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            onDismiss()
        }

        func documentPicker(_ controller: UIDocumentPickerViewController,
                            didPickDocumentsAt urls: [URL]) {
            onDismiss()
        }
    }
}

// MARK: - Temp file helper

extension VaultManager {
    /// Write backup bytes to a deterministic temp URL with a .occbak extension.
    /// The caller is responsible for deleting the file after the picker dismisses.
    static func tempBackupURL() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("occulta-backup")
            .appendingPathExtension("occbak")
    }
}
