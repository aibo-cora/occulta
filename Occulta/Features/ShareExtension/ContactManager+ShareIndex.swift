//
//  ContactManager+ShareIndex.swift
//  Occulta
//
//  Full rebuild of the shared contact index after every contact mutation.
//  Main app only — the extension never writes to the shared store.
//

import SwiftData
import Foundation

extension ContactManager {

    /// Rebuild the shared contact index from scratch.
    ///
    /// Called after every contact save/delete and on `scenePhase == .active`.
    /// The dataset is small (identifier + display name per contact), so a full
    /// rebuild is cheap and eliminates incremental sync bugs.
    ///
    /// Sync failures are silently caught — a failed sync is not worth crashing
    /// the primary contact operation that triggered it.
    func syncShareIndex() {
        do {
            try self._syncShareIndex()
        } catch {
            #if DEBUG
            debugPrint("syncShareIndex failed: \(error)")
            #endif
        }
    }

    private func _syncShareIndex() throws {
        let contacts = try self.fetchAllContacts()
        let keyManager = ShareIndexKeyManager()

        var entries: [(identifier: Data, displayName: Data)] = []

        for contact in contacts {
            // Decrypt names using the local DB crypto manager (via String.decrypt()).
            // The identifier is stored as-is — it's the opaque lookup key used by
            // fetchContact(by:), whether it's a public-key hash or encrypted CNContact ID.
            let givenName = contact.givenName.decrypt()
            let familyName = contact.familyName.decrypt()
            let displayName = "\(givenName) \(familyName)".trimmingCharacters(in: .whitespaces)

            guard
                let identifierData = contact.identifier.data(using: .utf8),
                let displayNameData = displayName.data(using: .utf8)
            else { continue }

            // Re-encrypt with the share index key — not the local DB key.
            // This is the only plaintext→ciphertext transformation that touches the shared store.
            let encId = try keyManager.encrypt(data: identifierData)
            let encName = try keyManager.encrypt(data: displayNameData)
            entries.append((encId, encName))
        }

        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
        else { return }

        let storeURL = containerURL.appendingPathComponent("ShareIndex.sqlite")

        let config = ModelConfiguration(
            schema: Schema([ShareableContact.self]),
            url: storeURL,
            cloudKitDatabase: .none
        )
        let container = try ModelContainer(for: ShareableContact.self, configurations: config)
        let context = ModelContext(container)

        // Delete-all → insert-new is atomic from SwiftData's perspective (single save()).
        // If the app is killed mid-operation, the next launch rebuilds from scratch.
        try context.delete(model: ShareableContact.self)

        for entry in entries {
            context.insert(ShareableContact(
                encryptedIdentifier: entry.identifier,
                encryptedDisplayName: entry.displayName
            ))
        }

        try context.save()

        // SQLite may recreate -wal and -shm during checkpointing.
        // Re-apply .completeFileProtection every time — even though field contents
        // are AES-GCM encrypted, SQLite metadata leaks row count, sizes, and timestamps.
        for name in ["ShareIndex.sqlite", "ShareIndex.sqlite-wal", "ShareIndex.sqlite-shm"] {
            let fileURL = containerURL.appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: fileURL.path) {
                try (fileURL as NSURL).setResourceValue(
                    URLFileProtection.complete,
                    forKey: .fileProtectionKey
                )
            }
        }
    }

    // MARK: - Cleanup

    /// Delete stale share sessions from the shared container.
    ///
    /// Called on every `scenePhase == .active`:
    /// - Sessions with a manifest older than 1 hour → delete
    /// - Sessions without a manifest (extension killed mid-write) → delete immediately
    /// - Sessions with an unreadable manifest (corrupted/orphaned) → delete immediately
    func cleanupPendingSessions() {
        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
        else { return }

        let pendingURL = containerURL.appendingPathComponent("pending")
        let fm = FileManager.default

        guard let sessions = try? fm.contentsOfDirectory(
            at: pendingURL,
            includingPropertiesForKeys: nil
        ) else { return }

        let keyManager = ShareIndexKeyManager()
        let oneHourAgo = Date().addingTimeInterval(-3600)

        for sessionDir in sessions {
            guard sessionDir.hasDirectoryPath else { continue }

            let manifestURL = sessionDir.appendingPathComponent("manifest.enc")

            if fm.fileExists(atPath: manifestURL.path) {
                // Decrypt manifest to read the creation timestamp.
                // If decryption or parsing fails, the manifest is corrupted — delete.
                if let encData = try? Data(contentsOf: manifestURL),
                   let plaintext = try? keyManager.decrypt(data: encData),
                   let manifest = try? JSONDecoder().decode(ShareManifest.self, from: plaintext),
                   manifest.createdAt > oneHourAgo {
                    continue // Fresh session — keep it
                }
                try? fm.removeItem(at: sessionDir)
            } else {
                // No manifest means the extension was killed before it finished writing.
                // These files are plaintext — delete immediately.
                try? fm.removeItem(at: sessionDir)
            }
        }
    }
}
