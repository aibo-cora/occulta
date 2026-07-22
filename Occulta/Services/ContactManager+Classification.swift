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
    ///
    /// Always runs the group cleanup pass afterward — see `cleanUpGroupDuressMembership(hiddenIdentifiers:)`.
    func saveClassification(safeIDs: Set<String>) throws {
        let contacts = try self.fetchAllContacts()
        let depth    = self.security.currentDepth
        var hiddenIdentifiers: Set<String> = []
        for contact in contacts {
            guard self.security.isDisplayable(contact) else { continue }
            let depthValue = safeIDs.contains(contact.identifier) ? Int.max : depth
            contact.visibleThroughDepth = try JSONEncoder().encode(depthValue).encrypt()
            if depthValue != Int.max { hiddenIdentifiers.insert(contact.identifier) }
        }
        for identifier in hiddenIdentifiers {
            Message.Draft.purge(recipientID: identifier, in: self.modelContext)
        }
        try self.modelContext.save()

        try self.cleanUpGroupDuressMembership(hiddenIdentifiers: hiddenIdentifiers)
    }

    /// Sets a single contact's visibility relative to `security.currentDepth`.
    ///
    /// Sensitive → `encrypt(currentDepth)`: visible through the current layer, hidden at the next.
    /// Safe      → `encrypt(Int.max)`: visible at all depths.
    ///
    /// Always runs the group cleanup pass afterward — see `cleanUpGroupDuressMembership(hiddenIdentifiers:)`.
    func setVisibility(for identifier: String, isSensitive: Bool) throws {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
        )
        guard let contact = try? self.modelContext.fetch(descriptor).first else { return }
        let depth = self.security.currentDepth
        contact.visibleThroughDepth = try JSONEncoder().encode(
            isSensitive ? depth : Int.max
        ).encrypt()

        if isSensitive {
            Message.Draft.purge(recipientID: identifier, in: self.modelContext)
        }

        try self.modelContext.save()

        try self.cleanUpGroupDuressMembership(hiddenIdentifiers: isSensitive ? [identifier] : [])
    }

    /// Cleans up group duress membership after a classification change.
    ///
    /// When `hiddenIdentifiers` is non-empty and we're at depth 0 — the one depth
    /// guaranteed not to be under coercion, since duress PINs never route there — those
    /// specific identifiers are removed from every group's duress-depth (1...)
    /// membership (`Group.purgeMembersFromDuressDepths(_:)`). A contact hidden this way
    /// may already be a stale, invisible member of some group's duress-depth array
    /// (added back when they were still visible there); `encryptGroupBundle`'s
    /// `isDisplayable` filter already keeps that stale entry from ever being sent to or
    /// shown, so this is a hygiene pass on top of that, not a security fix — it just
    /// stops the stale slot from permanently consuming capacity. Deliberately targeted,
    /// not a full wipe: a user may have put real effort into building distinct
    /// multi-layer decoy membership per group, and hiding one contact must not destroy
    /// every other member's presence in every group's duress-depth arrays too.
    ///
    /// Otherwise every group's ciphertext is still refreshed with fresh nonces and
    /// unchanged content (`Group.refreshCiphertext()`). This must run unconditionally: a
    /// classification save has to produce the identical observable footprint — every
    /// group's ciphertext changes — no matter the depth or outcome. Skipping the refresh
    /// whenever no real purge happens would itself be a keyless, forensically-visible
    /// signal for "was this classification done at depth 0" — a raw ciphertext diff
    /// doesn't need the key to see which rows changed, only whether they did.
    ///
    /// Reclassification performed from a duress depth never triggers the real purge —
    /// that depth's non-coercion status can't be guaranteed the way depth 0's can, and
    /// depths beyond it may hold deliberately pre-built decoy content for a separate,
    /// future coercion scenario that a same-depth or shallower action shouldn't destroy.
    private func cleanUpGroupDuressMembership(hiddenIdentifiers: Set<String>) throws {
        let purgeForReal = !hiddenIdentifiers.isEmpty && self.security.currentDepth == 0
        try self.forEachGroup { group in
            if purgeForReal {
                try group.purgeMembersFromDuressDepths(hiddenIdentifiers)
            } else {
                try group.refreshCiphertext()
            }
        }
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
