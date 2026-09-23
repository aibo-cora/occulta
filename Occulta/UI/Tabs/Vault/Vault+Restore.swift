//
//  Vault+Restore.swift
//  Occulta
//
//  Restore from a backup file, pushed from the Vault tab's + menu
//  (RECOVERY_BUFFER_LAYERING.md §9.4, Stage 3). Reads the same at every depth.
//

import SwiftUI
import UniformTypeIdentifiers

/// Lists the steps a new-phone owner has to finish before a restore can work, then picks the
/// backup file and runs one attempt. A file chosen here was asked for, so it skips the
/// "Restore from this backup?" alert that guards files arriving through Open in Occulta.
///
/// Leaving is the back button, as with the export screen. A failed attempt stays here so the
/// owner can choose another file or go back; a successful one pops back to the vault list,
/// where `VaultTab` shows the post-restore prompt.
struct VaultRestoreView: View {
    @Environment(VaultManager.self) private var vault
    @Environment(ContactManager.self) private var contactManager
    @Environment(Manager.Security.self) private var security
    @Environment(\.dismiss) private var dismiss

    @State private var showPicker = false
    @State private var failureMessage: String?

    /// The reply to every failed attempt, from here or from Open in Occulta, whatever the
    /// cause — so it never reveals which one happened.
    static let nothingRestoredMessage =
        "Not enough recovery pieces have come back yet. Open your backup file again after more people have sent their messages."

    var body: some View {
        List {
            Section {
                Text("Bring your vault back on a new phone. You'll need your backup file and the people who hold your recovery pieces.")
            }
            Section("Before you choose the file") {
                Label("Meet each of them in person and exchange contacts again in Occulta.", systemImage: "1.circle")
                Label("Ask each of them to send you a message in Occulta, then open it. It brings your recovery piece back.", systemImage: "2.circle")
                Label("Choose your backup file below.", systemImage: "3.circle")
            }
            Section {
                Button("Choose Backup File") { self.showPicker = true }
            }
        }
        .navigationTitle("Restore from Backup")
        .navigationBarTitleDisplayMode(.inline)
        .fileImporter(
            isPresented: self.$showPicker,
            allowedContentTypes: [UTType(exportedAs: "com.github.aibo-cora.occulta.backup")]
        ) { result in
            self.restore(from: result)
        }
        .alert(
            "Nothing was restored",
            isPresented: Binding(get: { self.failureMessage != nil }, set: { if !$0 { self.failureMessage = nil } })
        ) {
            Button("OK") {}
        } message: {
            Text(self.failureMessage ?? "")
        }
    }

    private func restore(from result: Result<URL, Error>) {
        guard case .success(let url) = result else { return }
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }

        do {
            let data  = try Data(contentsOf: url)
            let depth = self.security.currentDepth
            let imported = try self.vault.restoreBackup(
                from: data, currentDepth: depth,
                visibleContactIdentifiers: self.contactManager.visibleContactIdentifiers(atDepth: depth)
            )
            if imported {
                self.dismiss()
            } else {
                self.failureMessage = Self.nothingRestoredMessage
            }
        } catch {
            self.failureMessage = "There was an error. \(error.localizedDescription)"
        }
    }
}
