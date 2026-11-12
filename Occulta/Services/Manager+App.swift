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
        ///
        /// The parameters are a seam for a test that runs this without wiping the Simulator's canonical keys, which
        /// other tests are using, and the real app group. Each default is exactly what this did before they existed.
        /// - Parameters:
        ///   - erasePrekeys: Deletes every prekey in the keychain.
        ///   - draftsRoot: The `Drafts/` directory, which other tests write drafts into.
        ///   - stagingContainer: The app group container the share extension stages into, or nil if there is none.
        ///   - staging: The share-staging key, its secret `r_S` and its PQ record.
        ///   - keys: The Secure Enclave keys, the tier secrets and the tier PQ records.
        func eraseAllData(
            erasePrekeys: () -> Void = { Manager.PrekeySecretsManager().deleteAllKeys() },
            draftsRoot: URL = Message.Draft.attachmentsRoot,
            stagingContainer: URL? = ShareSession.sharedContainer,
            staging: ShareStagingKeyManager = ShareStagingKeyManager(),
            keys: Manager.Key = Manager.Key()
        ) throws {
            erasePrekeys()
            try self.contacts.deleteAllContacts()
            try self.contacts.deleteAllDrafts(root: draftsRoot)
            try self.vault.deleteAllData()
            // Every row is gone; flush the pre-deletion frames out of the WAL. `secure_delete` only zeroes the
            // page being freed, and nothing else checkpoints before the next launch or unlock.
            self.contacts.security.checkpointStore()
            if let stagingContainer {
                ShareSession.removeAll(in: stagingContainer)
            }
            staging.deleteKey()
            keys.deleteAllKeys()
        }
    }
}
