//
//  Manager+App.swift
//  Occulta
//

import Foundation

extension Manager {
    /// Top-level coordinator for operations that span multiple managers.
    @Observable
    final class App {
        private let contacts: ContactManager
        private let vault: VaultManager

        init(contacts: ContactManager, vault: VaultManager) {
            self.contacts = contacts
            self.vault = vault
        }

        /// Deletes all app data: prekeys, contacts, drafts, vault, share-extension leftovers, and SE keys.
        /// SE keys are deleted last — once gone, all data encrypted under them is permanently inaccessible.
        func eraseAllData() throws {
            Manager.PrekeySecretsManager().deleteAllKeys()
            try self.contacts.deleteAllContacts()
            try self.contacts.deleteAllDrafts()
            try self.vault.deleteAllData()
            // Every row is gone; flush the pre-deletion frames out of the WAL. `secure_delete` only zeroes the
            // page being freed, and nothing else checkpoints before the next launch or unlock.
            self.contacts.security.checkpointStore()
            if let container = ShareSession.sharedContainer {
                ShareSession.removeAll(in: container)
            }
            ShareStagingKeyManager().deleteKey()
            Manager.Key().deleteAllKeys()
        }
    }
}
