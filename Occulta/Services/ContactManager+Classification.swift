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
    ///
    /// **Intentionally has no production callers. Do not wire it back into the inbound path.**
    ///
    /// It used to back `passSecurityControl` in `OccultaApp`, which rejected any inbound bundle
    /// from a contact not visible at the current depth. That rejection was itself a
    /// duress-detection oracle: it is reachable *only* when `isRestricted == true`, so a coercer
    /// who sends a probe from an identity they know is paired with the device learns whether
    /// Secure Mode is active — one probe is close to conclusive, two remove essentially all
    /// doubt. Removed in `b1f9045` ("no bundle is ever rejected for restriction state"), with
    /// `2958593` making the queued-file drain behave identically on a duress unlock so the two
    /// paths could not differ either. Full reasoning, including the content-confidentiality cost
    /// that was accepted in exchange, is in
    /// `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`.
    ///
    /// Kept, with its tests, because the semantics are still the right definition of "visible to
    /// me right now" and a future caller may legitimately need them — but any use that can
    /// produce a *sender-dependent, restriction-gated* observable reopens that oracle. Read the
    /// doc before adding one.
    ///
    /// Note this is not the same as UI-side visibility filtering, which is alive and correct:
    /// `ContactsListV2`, `GroupDetailV3`, `Vault+Tab` and `ContactClassification` all filter on
    /// `isVisible(atDepth:)`. What was removed is rejecting *inbound bundles* on that basis.
    func isSafeContact(_ identifier: String) -> Bool {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
        )
        guard let contact = try? self.modelContext.fetch(descriptor).first else { return false }
        return contact.isVisible(atDepth: self.security.currentDepth)
    }

    /// Returns true if the contact is marked a global trustee at the current depth
    /// (`globalTrusteeDepth == currentDepth`, exact match — not a ceiling, unlike
    /// visibleThroughDepth). A trustee designation made at one depth is never surfaced
    /// at any other depth.
    func isGlobalTrustee(_ identifier: String) -> Bool {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
        )
        guard let contact = try? self.modelContext.fetch(descriptor).first,
              let data    = contact.globalTrusteeDepth,
              let plain   = data.decrypt(),
              let value   = try? JSONDecoder().decode(Int.self, from: plain)
        else { return false }
        return value == self.security.currentDepth
    }

    /// Identifiers of every contact marked a global trustee at the current depth.
    /// Restricted to displayable contacts, matching the filter every other
    /// trustee-facing list already applies (Gap 2 items 1-2).
    ///
    /// Derives the local-DB key once and reuses it across every contact, instead of
    /// once per contact per field — the dominant cost here is the Keychain/Secure
    /// Enclave round trip inside key derivation, not the AES operation itself, and the
    /// derived key is identical on every call until the local-DB key is rotated.
    func globalTrusteeIdentifiers() -> Set<String> {
        guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else { return [] }
        return self.globalTrusteeIdentifiers(usingKey: key)
    }

    /// Same as `globalTrusteeIdentifiers()` but decrypts with an already-derived key
    /// instead of deriving one internally. For callers already holding a key for the
    /// same pass (e.g. a screen that also needs `mlkemEligibleContacts(usingKey:)`).
    func globalTrusteeIdentifiers(usingKey key: SymmetricKey) -> Set<String> {
        let depth = self.security.currentDepth
        let contacts = (try? self.fetchAllContacts()) ?? []
        return Set(contacts.compactMap { contact in
            (contact.isVisible(atDepth: depth, usingKey: key)
                && contact.isGlobalTrustee(atDepth: depth, usingKey: key))
                ? contact.identifier : nil
        })
    }

    /// Contacts with a verified ML-KEM key, visible at the current depth. Derives the
    /// local-DB key once and reuses it across every contact — same reasoning as
    /// `globalTrusteeIdentifiers()`.
    func mlkemEligibleContacts() -> [Contact.Profile] {
        guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else { return [] }
        return self.mlkemEligibleContacts(usingKey: key)
    }

    /// Same as `mlkemEligibleContacts()` but decrypts with an already-derived key
    /// instead of deriving one internally. For callers already holding a key for the
    /// same pass (e.g. a screen that also needs `globalTrusteeIdentifiers(usingKey:)`).
    func mlkemEligibleContacts(usingKey key: SymmetricKey) -> [Contact.Profile] {
        let depth = self.security.currentDepth
        let contacts = (try? self.fetchAllContacts()) ?? []
        return contacts
            .filter { $0.isVisible(atDepth: depth, usingKey: key) }
            .filter { $0.contactPublicKeys?.last(where: { $0.expiredOn == nil })?.quantumKeyMaterialEncrypted != nil }
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
            guard contact.isVisible(atDepth: depth) else { continue }
            let depthValue = safeIDs.contains(contact.identifier) ? Int.max : depth
            contact.visibleThroughDepth = try JSONEncoder().encode(depthValue).encrypt()
            if depthValue != Int.max { hiddenIdentifiers.insert(contact.identifier) }
        }
        for identifier in hiddenIdentifiers {
            Message.Draft.purge(recipientID: identifier, in: self.modelContext)
        }
        try self.modelContext.save()

        // Checkpoint after the group purge, not before: cleanUpGroupDuressMembership
        // does its own separate save() for the group re-encryption, and checkpointStore()
        // exists specifically to flush purge-adjacent writes immediately — running it
        // before that save would leave the group write uncovered until whatever
        // unrelated checkpoint happens next (SecurityReview2026-07-24, finding #10).
        try self.cleanUpGroupDuressMembership(hiddenIdentifiers: hiddenIdentifiers)
        self.security.checkpointStore()
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

        // See saveClassification's identical comment above — checkpoint after the
        // group purge's own save, not before, so it's actually covered.
        try self.cleanUpGroupDuressMembership(hiddenIdentifiers: isSensitive ? [identifier] : [])
        self.security.checkpointStore()
    }

    /// Marks `selectedIDs` as global trustees at the current depth; every other
    /// displayable contact is stamped -1 (not a trustee at this depth). Exact-match,
    /// current-depth only — the single mechanism at every depth, including depth 0
    /// (`GlobalShardConfig` is orphaned as of item 3's consolidation, see the
    /// shard-custody bug doc).
    func saveGlobalTrusteeDepth(selectedIDs: Set<String>) throws {
        let contacts = try self.fetchAllContacts()
        let depth    = self.security.currentDepth
        for contact in contacts {
            guard contact.isVisible(atDepth: depth) else { continue }
            let value = selectedIDs.contains(contact.identifier) ? depth : -1
            contact.globalTrusteeDepth = try JSONEncoder().encode(value).encrypt()
        }
        try self.modelContext.save()
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

        // Derived once and reused across every group and every depth in the pass below,
        // instead of once per slot — the dominant cost here is the Keychain/Secure
        // Enclave round trip inside key derivation, not the AES operation itself, and
        // the derived key is identical on every call until the local-DB key is rotated.
        // Failure must abort the whole pass rather than proceed with a missing key:
        // silently skipping the mandatory ciphertext refresh on some or all groups would
        // itself be a forensic tell (see the doc comment below).
        guard let key = try Manager.Key().createHybridLocalEncryptionKey() else {
            throw GroupError.keyUnavailable
        }

        try self.forEachGroup { group in
            if purgeForReal {
                try group.purgeMembersFromDuressDepths(hiddenIdentifiers, usingKey: key)
            } else {
                try group.refreshCiphertext(usingKey: key)
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

        // Same restore for the global-trustee stamp. Falls back to -1 (not a trustee)
        // for blobs written before this field was added.
        let trusteeDepth = record.globalTrusteeDepth ?? -1
        restored.globalTrusteeDepth = try AES.GCM.seal(
            JSONEncoder().encode(trusteeDepth), using: stagedKey, authenticating: aad
        ).combined

        // Write the originDepth sentinel directly, not restored from the blob — a
        // duress-origin contact is exempt from blob-sealing entirely (activateSecureMode's
        // Step 4 short-circuit), so anything reaching this function has originDepth == 0
        // by construction. There is no captured value to restore here.
        restored.originDepth = try AES.GCM.seal(
            JSONEncoder().encode(0), using: stagedKey, authenticating: aad
        ).combined

        if let attrs = record.signedAttributes, !attrs.isEmpty {
            restored.signedAttributes = try AES.GCM.seal(
                attrs, using: stagedKey, authenticating: aad
            ).combined
        }
    }
}
