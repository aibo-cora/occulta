//
//  ContactManager+Classification.swift
//  Occulta
//
//  Contact visibility and classification — reads and writes visibleThroughDepth
//  through ContactManager's own context so activation and the share index both
//  see the correct values without cross-context identity-map divergence.
//

import SwiftData
import CryptoKit
import Foundation

extension ContactManager {

    // MARK: - Reads

    /// Returns true if the contact is sensitive at the current depth —
    /// visible now but hidden at the next layer (`visibleThroughDepth == currentDepth`).
    func isSensitive(_ identifier: String) -> Bool {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
        )
        guard let contact = try? self.modelContext.fetch(descriptor).first,
              let data    = contact.visibleThroughDepth,
              let plain   = data.decrypt(),
              let value   = try? JSONDecoder().decode(Int.self, from: plain)
        else { return false }
        return value == self.security.currentDepth
    }

    /// Returns true if the contact is visible at the current depth.
    /// Unknown contacts return false — conservative default.
    func isSafeContact(_ identifier: String) -> Bool {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
        )
        guard let contact = try? self.modelContext.fetch(descriptor).first else { return false }
        return Manager.Security.isVisible(contact, atDepth: self.security.currentDepth)
    }

    // MARK: - Writes

    /// Classifies contacts relative to `security.currentDepth`.
    ///
    /// Contacts in `safeIDs` are marked always-visible (`encrypt(Int.max)`).
    /// Contacts not in `safeIDs` that are currently visible are marked hidden at the
    /// next layer (`encrypt(currentDepth)`). Contacts already hidden below `currentDepth`
    /// are left untouched — this call does not own them.
    func saveClassification(safeIDs: Set<String>) throws {
        let contacts = try self.fetchAllContacts()
        let depth    = self.security.currentDepth
        for contact in contacts {
            guard self.security.isDisplayable(contact) else { continue }
            let depthValue = safeIDs.contains(contact.identifier) ? Int.max : depth
            contact.visibleThroughDepth = try JSONEncoder().encode(depthValue).encrypt()
        }
        try self.modelContext.save()
    }

    /// Sets a single contact's visibility relative to `security.currentDepth`.
    ///
    /// Sensitive → `encrypt(currentDepth)`: visible through the current layer, hidden at the next.
    /// Safe      → `encrypt(Int.max)`: visible at all depths.
    func setVisibility(for identifier: String, isSensitive: Bool) throws {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
        )
        guard let contact = try? self.modelContext.fetch(descriptor).first else { return }
        contact.visibleThroughDepth = try JSONEncoder().encode(
            isSensitive ? self.security.currentDepth : Int.max
        ).encrypt()
        try self.modelContext.save()
    }

    // MARK: - Deactivation restore

    /// Restores a blob contact record into the DB during `deactivateSecureMode` Step 5.
    ///
    /// Saves the contact's text fields via `crypto` (staged-key protocol), then writes
    /// `visibleThroughDepth` and `signedAttributes` directly under the staged key.
    /// The caller is responsible for calling `modelContext.save()` after processing all records.
    func restoreContact(_ record: LayerContact,
                        using crypto: any CryptoProtocol,
                        stagedKey: SymmetricKey,
                        aad: Data) throws {
        try self.save(contact: record.draft, using: crypto)

        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.identifier == record.draft.identifier }
        )
        guard let restored = try self.modelContext.fetch(descriptor).first else { return }

        // Restore the depth stored at activation time, encrypted under the staged key so it is
        // readable after commitStagedLocalDBKey(). Falls back to 0 (sensitive) for blobs written
        // before this field was added — any blob contact had a finite visibleThroughDepth.
        let depth = record.visibleThroughDepth ?? 0
        restored.visibleThroughDepth = try AES.GCM.seal(
            JSONEncoder().encode(depth), using: stagedKey, authenticating: aad
        ).combined

        if let attrs = record.signedAttributes, !attrs.isEmpty {
            restored.signedAttributes = try AES.GCM.seal(
                attrs, using: stagedKey, authenticating: aad
            ).combined
        }
    }
}
