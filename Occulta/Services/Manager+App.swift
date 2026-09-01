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

        /// Deletes all app data: prekeys, contacts, vault, and SE keys.
        /// SE keys are deleted last — once gone, all data encrypted under them is permanently inaccessible.
        func eraseAllData() throws {
            Manager.PrekeyManager().deleteAllKeys()
            try self.contacts.deleteAllContacts()
            try self.vault.deleteAllData()
            Manager.Key().deleteAllKeys()
        }
    }
}
