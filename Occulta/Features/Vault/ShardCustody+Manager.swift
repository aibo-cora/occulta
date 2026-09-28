//
//  ShardCustody+Manager.swift
//  Occulta
//
//  Inbound router for ShardOperation traffic + manifest reconciliation.
//
//  Two roles, one router:
//    - Trustee path: accept .distribute / .replace from the owner; store as encrypted
//      CustodyShard rows; return mismatch-fingerprint shards as .handback on every
//      outbound bundle.
//    - Owner path: receive .handback from trustees; include custodyManifest (IDs held)
//      in every outbound 1:1 bundle; keep each depth's backup-key pieces delivered
//      (`distributeBackup`, `reconcileBackupPieces`).
//
//  No implicit revoke: the owner's `expectedShards` list, and the trustee deleting what
//  it didn't name, were removed (`bugs.md` Bug 141). A removed trustee's piece is revoked
//  by splitting a new backup key instead.
//
//  Manifest reconciliation replaces the old Pending{Revoke,Acknowledge,Return,
//  ReturnAcknowledge,NotFound} models. State is a complete snapshot re-sent on every
//  bundle — missed updates are healed by the next exchange, not by queuing.
//

import Foundation
import SwiftData
import CryptoKit

@Observable
@MainActor
final class ShardCustodyManager {

    // MARK: - Dependencies

    private let modelContainer: ModelContainer
    private let modelContext:   ModelContext
    private let keyManager:     any KeyManagerProtocol

    // MARK: - Init

    init(modelContainer: ModelContainer, keyManager: any KeyManagerProtocol) {
        self.modelContainer = modelContainer
        self.modelContext   = ModelContext(modelContainer)
        self.keyManager     = keyManager
    }

    // MARK: - Inbound dispatch

    /// Route real (already de-padded, if applicable) shard-protocol fields to
    /// per-role handlers.
    ///
    /// Takes the three fields explicitly rather than a whole `SealedPayload` so a
    /// group-bundle caller can pass per-recipient fields (already stripped of tier
    /// padding by `ContactManager.openGroup`) through the same path a 1:1 caller
    /// uses with a `SealedPayload`'s own fields — this method has no notion of
    /// padding at all.
    ///
    /// Returns `true` when any shard-protocol field was present — caller must not
    /// render the bundle as a regular message basket.
    @discardableResult
    func handleInbound(
        shardOperations:  [OccultaBundle.ShardOperation]?,
        custodyManifest:  [UUID]?,
        senderPublicKey:  Data,
        senderIdentifier: String,
        vaultManager:     VaultManager
    ) -> Bool {
        let hasOps      = (shardOperations?.isEmpty == false)
        let hasManifest = custodyManifest != nil

        guard hasOps || hasManifest else { return false }

        for op in shardOperations ?? [] {
            do {
                switch op.kind {
                case .distribute:
                    try self.handleDistribute(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .replace:
                    try self.handleReplace(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .handback:
                    try self.handleHandback(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier, vaultManager: vaultManager)
                case .unsupported:
                    break
                }
            } catch {
                #if DEBUG
                debugPrint("ShardCustodyManager dispatch failed for \(op.kind): \(error)")
                #endif
            }
        }

        if let manifest = custodyManifest {
            do { try self.processInboundManifest(manifest, from: senderIdentifier) }
            catch {
                #if DEBUG
                debugPrint("ShardCustodyManager processInboundManifest failed: \(error)")
                #endif
            }
        }

        return true
    }

    // MARK: - Trustee path: inbound

    /// `.distribute` — owner sent a shard to hold (first distribution).
    ///
    /// Verifies the ECDSA signature, deduplicates, stores the shard, then deletes
    /// any mismatch-fingerprint shards for this contact (Case 8 cleanup).
    private func handleDistribute(op: OccultaBundle.ShardOperation, senderPublicKey: Data, senderIdentifier: String) throws {
        guard let attribute = op.attribute, attribute.category == .shard else {
            throw CustodyError.invalidPayload
        }
        guard attribute.verify(against: senderPublicKey) else {
            throw CustodyError.signatureRejected
        }

        let alreadyStored = (try? self.decryptAllCustodyShards()
            .contains { $0.payload.signedAttribute.id == attribute.id }) ?? false
        guard !alreadyStored else { return }

        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rowID   = UUID()
        let newFP   = Self.fingerprint(of: senderPublicKey)
        let payload = CustodyShard.Payload(
            ownerKeyFingerprint:    newFP,
            ownerContactIdentifier: senderIdentifier,
            signedAttribute:        attribute
        )
        let combined = try self.sealRow(payload, using: custodyKey, id: rowID)
        self.modelContext.insert(CustodyShard(id: rowID, encryptedPayload: combined))

        try self.deleteMismatchShards(for: senderIdentifier, newFingerprint: newFP, using: custodyKey)
        try self.modelContext.save()
    }

    /// `.replace` — owner sent a replacement shard; store the new one and delete the old.
    ///
    /// Insert-then-delete ordering ensures the shard is never lost even if the delete fails.
    private func handleReplace(op: OccultaBundle.ShardOperation, senderPublicKey: Data, senderIdentifier: String) throws {
        guard let attribute = op.attribute, attribute.category == .shard,
              let oldID = op.attributeID else {
            throw CustodyError.invalidPayload
        }
        guard attribute.verify(against: senderPublicKey) else {
            throw CustodyError.signatureRejected
        }

        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rowID   = UUID()
        let newFP   = Self.fingerprint(of: senderPublicKey)
        let payload = CustodyShard.Payload(
            ownerKeyFingerprint:    newFP,
            ownerContactIdentifier: senderIdentifier,
            signedAttribute:        attribute
        )
        let combined = try self.sealRow(payload, using: custodyKey, id: rowID)
        self.modelContext.insert(CustodyShard(id: rowID, encryptedPayload: combined))

        // One pass: the replaced shard, plus any of this owner's shards under an old key.
        try self.deleteCustodyShards(using: custodyKey) { payload in
            payload.ownerContactIdentifier == senderIdentifier
                && (payload.signedAttribute.id == oldID || payload.ownerKeyFingerprint != newFP)
        }
        try self.modelContext.save()
    }

    /// Delete all CustodyShard rows for `contactIdentifier` whose fingerprint ≠ `newFingerprint`.
    private func deleteMismatchShards(for contactIdentifier: String, newFingerprint: Data, using custodyKey: SymmetricKey) throws {
        try self.deleteCustodyShards(using: custodyKey) { payload in
            payload.ownerContactIdentifier == contactIdentifier && payload.ownerKeyFingerprint != newFingerprint
        }
    }

    /// Deletes every custody row whose payload matches `shouldDelete` and, when anything was
    /// deleted, re-seals every other readable row with a fresh nonce and the same content.
    /// Without the re-seal, two snapshots taken across a deletion show exactly which row went
    /// while every other row stays byte-identical (`bugs.md` Bug 130). Rows that don't decrypt
    /// are left alone: not deleted, not re-sealed. Doesn't save; the caller does.
    ///
    /// Every other path that deletes custody rows goes through here, so they can't drift apart
    /// again. `purgeCustody` keeps its own loop because it re-seals on every purge, even one
    /// that deletes nothing.
    @discardableResult
    private func deleteCustodyShards(
        using custodyKey: SymmetricKey,
        where shouldDelete: (CustodyShard.Payload) -> Bool
    ) throws -> Bool {
        let decoded = try self.decryptAllCustodyShards(using: custodyKey)
        guard decoded.contains(where: { shouldDelete($0.payload) }) else { return false }

        for shard in decoded {
            if shouldDelete(shard.payload) {
                self.modelContext.delete(shard.row)
            } else {
                shard.row.encryptedPayload = try self.sealRow(shard.payload, using: custodyKey, id: shard.row.id)
            }
        }
        return true
    }

    // MARK: - Owner path: inbound

    /// `.handback` — trustee returned one of our shards, either after a same-key
    /// re-pairing or after detecting a fingerprint mismatch (identity rotation).
    ///
    /// Branch A — direct verify — still runs, and still means something when it
    /// succeeds: `attribute` verifying against our own current identity key proves
    /// content authenticity, that this exact value is genuinely what we signed at
    /// distribution. That's real and worth checking; transport authentication
    /// cannot substitute for it.
    ///
    /// **Branch B (trustee attestation) is gone — `bugs.md` Bug 125, 2026-09-19.**
    /// It never verified content authenticity either; the attester controlled both
    /// the shard value and the attestation hashed over it, so it could only ever
    /// prove "a recognized identity vouches for this" — sender authenticity, which
    /// the bundle's own transport (a 1:1 exchange, session key derivable only by
    /// the two real parties, `senderProof`-authenticated) already establishes
    /// before this function is ever called. Once Branch A fails — which happens
    /// for every genuine trustee too, the moment the owner's identity rotates,
    /// since the key that signed the original shard no longer exists anywhere —
    /// there was never a way to recover content authenticity, with or without an
    /// attestation. So Branch A failing now means accept, not "try a second,
    /// no-stronger check."
    ///
    /// Nothing checks that `attribute.entryID` names a real, live distribution: for a
    /// backup-key restore it can't, since the restoring phone is usually new and the
    /// record of what was distributed was on the lost one. `acceptReturnedShard` banks a
    /// shard under any `entryID`. What scopes this instead (`bugs.md` Bug 125, 2026-09-26
    /// note):
    /// - one slot per `(entryID, sender)`, with the sender resolved from the transport,
    ///   so no single contact can supply a threshold alone (Bug 94 remedy 2);
    /// - `restoreBackup` counts only senders visible at the current depth, and refuses a
    ///   depth that already has a backup key (Bug 94 remedy 1);
    /// - a reconstructed key counts only if it opens the `.occbak` the owner chose to
    ///   open, so shards alone restore nothing;
    /// - a per-entry key is only finalised for an entry this device split, against that
    ///   entry's own stored ciphertext.
    ///
    /// Acceptance is not gated on any restore being under way; a BEK restore
    /// shard is only banked here. `restoreBackup` decides, when the owner opens the
    /// `.occbak`, which banked shards count: only those from contacts visible at that
    /// depth (`RECOVERY_BUFFER_LAYERING.md` §9.4).
    private func handleHandback(
        op: OccultaBundle.ShardOperation,
        senderPublicKey: Data,
        senderIdentifier: String,
        vaultManager: VaultManager
    ) throws {
        guard let attribute = op.attribute, attribute.category == .shard else {
            throw CustodyError.invalidPayload
        }

        // Branch A's own result no longer gates acceptance — see the doc comment
        // above. Still attempted for the real, non-redundant thing it proves when
        // it succeeds (content authenticity), even though nothing downstream
        // currently distinguishes "verified" from "accepted on trust" — that
        // distinction is available to build on later without re-deriving it.
        if let ownKey = try? self.keyManager.retrieveIdentity() {
            _ = attribute.verify(against: ownKey)
        }

        try vaultManager.acceptReturnedShard(
            attribute,
            senderIdentifier: senderIdentifier
        )
    }

    // MARK: - Manifest reconciliation

    /// Process trustee's `custodyManifest` — the IDs of all shards they currently hold.
    ///
    /// For each queued piece the manifest lists: insert a `PotentiallyLostShard` watch
    /// row (present) and drop the queued row. Then set `isAbsent` on this contact's watch
    /// rows — true when absent from this manifest, false when present.
    ///
    /// Statuses aren't touched here: this runs at whatever depth is current, with the
    /// vault maybe locked, and a piece belongs to one depth's record. Each depth reads the
    /// watch rows in its own `reconcileBackupPieces` (`bugs.md` Bug 141).
    func processInboundManifest(_ manifest: [UUID], from senderIdentifier: String) throws {
        let manifestSet = Set(manifest)

        guard let custodyKey = try? self.keyManager.deriveShardCustodyKey() else { return }
        let distributeRows = (try? self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())) ?? []

        let inFlightIDs: Set<UUID> = Set(distributeRows.compactMap {
            guard let payload = try? self.openRow($0.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: $0.id),
                  payload.contactIdentifier == senderIdentifier else { return nil }
            return payload.signedAttribute.id
        })

        // Delivered: watch the piece from now on, and stop sending it.
        for inFlightId in inFlightIDs where manifestSet.contains(inFlightId) {
            let rowID = UUID()
            if let combined = try? self.sealRow(
                PotentiallyLostShard.Payload(attributeID: inFlightId, contactIdentifier: senderIdentifier, isAbsent: false),
                using: custodyKey, id: rowID
            ) {
                self.modelContext.insert(PotentiallyLostShard(id: rowID, encryptedPayload: combined))
            }
            try? self.deletePendingDistribute(attributeID: inFlightId, using: custodyKey, rows: distributeRows)
        }

        // Update absence flag on all watched shards for this contact.
        let watchedRows = (try? self.modelContext.fetch(FetchDescriptor<PotentiallyLostShard>())) ?? []
        var changed = false
        for row in watchedRows {
            guard var payload = try? self.openRow(row.encryptedPayload, as: PotentiallyLostShard.Payload.self, using: custodyKey, id: row.id),
                  payload.contactIdentifier == senderIdentifier else { continue }
            let absent = !manifestSet.contains(payload.attributeID)
            guard payload.isAbsent != absent else { continue }
            payload.isAbsent = absent
            if let combined = try? self.sealRow(payload, using: custodyKey, id: row.id) {
                row.encryptedPayload = combined
                changed = true
            }
        }
        if changed { try? self.modelContext.save() }
    }

    // MARK: - Outbound: build shard operations

    /// Build the outbound ShardOperation list for `contactIdentifier`.
    ///
    /// Owner side: `.distribute` / `.replace` from PendingShardDistribute rows.
    /// Trustee side: `.handback` for mismatch-fingerprint shards (signals key rotation).
    func buildShardOperations(for contactIdentifier: String, currentContactPublicKey: Data?) throws -> [OccultaBundle.ShardOperation] {
        // Derived once and passed to both halves below — pendingDistributeOps and
        // mismatchHandbackOps each independently derived this same shard custody key, so a
        // single call here (invoked once per group member when encrypting a group bundle) was
        // paying two Secure Enclave round trips for one key.
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        var ops = [OccultaBundle.ShardOperation]()
        ops += try self.pendingDistributeOps(for: contactIdentifier, usingKey: custodyKey)
        if let pubKey = currentContactPublicKey {
            ops += try self.mismatchHandbackOps(for: contactIdentifier, currentFP: Self.fingerprint(of: pubKey), usingKey: custodyKey)
        }
        return ops
    }

    private func pendingDistributeOps(for contactIdentifier: String, usingKey custodyKey: SymmetricKey) throws -> [OccultaBundle.ShardOperation] {
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())
        return rows.compactMap { row in
            guard let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id),
                  payload.contactIdentifier == contactIdentifier else { return nil }
            return OccultaBundle.ShardOperation(
                kind:        payload.oldAttributeID != nil ? .replace : .distribute,
                attribute:   payload.signedAttribute,
                attributeID: payload.oldAttributeID
            )
        }
    }

    /// Returns `.handback` ops for mismatch-fingerprint shards.
    ///
    /// Included on every outbound bundle to the owner until they redistribute with
    /// a new fingerprint, which triggers `deleteMismatchShards` in `handleDistribute`.
    /// No attestation attached — `bugs.md` Bug 125 removed that mechanism; the owner
    /// accepts a mismatch-fingerprint handback on the strength of the bundle's own
    /// transport authentication now, not a second signature this device used to build.
    private func mismatchHandbackOps(for contactIdentifier: String, currentFP: Data, usingKey custodyKey: SymmetricKey) throws -> [OccultaBundle.ShardOperation] {
        let candidates = try self.decryptAllCustodyShards(using: custodyKey)
            .filter { $0.payload.ownerContactIdentifier == contactIdentifier && $0.payload.ownerKeyFingerprint != currentFP }
        guard !candidates.isEmpty else { return [] }

        return candidates.map { OccultaBundle.ShardOperation(kind: .handback, attribute: $0.payload.signedAttribute) }
    }

    // MARK: - Outbound: build manifest fields

    /// IDs of all shards currently held for `ownerIdentifier`. Sent in every outbound 1:1
    /// bundle; group bundles carry none (`RecipientPayload.shardMetadataAttempted`).
    func buildCustodyManifest(for ownerIdentifier: String) throws -> [UUID] {
        return try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == ownerIdentifier }
            .map    { $0.payload.signedAttribute.id }
    }

    // MARK: - Trustee display

    /// How many shards this device holds per owner, keyed by owner contact identifier.
    ///
    /// Accepts the raw rows from the view's `@Query` to avoid a second ModelContext
    /// fetch — the `@Query` context is always in sync with the persistent store.
    /// Returns an empty array when decryption fails.
    func heldShards(from rows: [CustodyShard]) -> [(ownerContactIdentifier: String?, count: Int)] {
        guard let custodyKey = try? self.keyManager.deriveShardCustodyKey() else { return [] }
        var groups: [String?: Int] = [:]
        for row in rows {
            guard let payload = try? self.openRow(row.encryptedPayload, as: CustodyShard.Payload.self, using: custodyKey, id: row.id)
            else { continue }
            groups[payload.ownerContactIdentifier, default: 0] += 1
        }
        return groups.map { ($0.key, $0.value) }
    }

    // MARK: - Shard distribute queuing (owner → trustee)

    /// Queue a `.distribute` or `.replace` op for `contactIdentifier`.
    ///
    /// One row per `attributeID`; idempotent. `replacing` non-nil → `.replace` op.
    /// Row is deleted only when the trustee's `custodyManifest` confirms the ID
    /// (not on send), enabling automatic retry on bundle loss.
    func queueDistribute(attribute: SignedAttribute, for contactIdentifier: String, replacing oldAttributeID: UUID? = nil) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let existing = try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())
        let alreadyQueued = existing.contains {
            (try? self.openRow($0.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: $0.id))?.signedAttribute.id == attribute.id
        }
        guard !alreadyQueued else { return }

        let rowID    = UUID()
        let combined = try self.sealRow(
            PendingShardDistribute.Payload(contactIdentifier: contactIdentifier, signedAttribute: attribute, oldAttributeID: oldAttributeID),
            using: custodyKey, id: rowID
        )
        self.modelContext.insert(PendingShardDistribute(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    // MARK: - Backup-key distribution (owner, one depth)

    /// Whether distributing to `recipients` leaves out anyone in `currentDepth`'s current
    /// backup-key record, whatever their piece's status. A left-out trustee may still hold a
    /// piece of the current key, so the split must use a new key (`bugs.md` Bugs 141, 144).
    ///
    /// The one place that decides it: `distributeBackup` applies it, and the setup screen
    /// asks it whether to warn before a distribution replaces the key.
    func distributionDropsTrustee(recipients: [String], currentDepth: Int, vaultManager: VaultManager) -> Bool {
        let current = (try? vaultManager.backupShardMetadata(currentDepth: currentDepth))?.shards ?? []
        return Self.dropsTrustee(current, recipients: recipients)
    }

    private static func dropsTrustee(_ records: [ShardRecord], recipients: [String]) -> Bool {
        records.contains { !recipients.contains($0.contactIdentifier) }
    }

    /// Re-split `currentDepth`'s backup key for `recipients` and queue one piece each:
    /// `.replace` for a trustee who held one, `.distribute` otherwise.
    ///
    /// Splits a freshly generated key instead when the distribution leaves out anyone in the
    /// current record (`distributionDropsTrustee`): only a new secret stops a left-out
    /// trustee's piece from working with k−1 others of the old split (`bugs.md` Bugs 141, 144).
    ///
    /// In this order, so a failure at any step heals at the next reconcile:
    /// 1. the previous split's queued and watch rows are deleted and saved (`bugs.md` Bug 142),
    ///    found by the piece IDs in this depth's own record — a removed trustee never receives
    ///    a stale piece, even if a later step fails;
    /// 2. the new split is persisted;
    /// 3. its pieces are queued in one save.
    ///
    /// A failure after step 1 leaves pending pieces with nothing queued, which
    /// `reconcileBackupPieces` re-sends. Reads and writes only this depth's row.
    func distributeBackup(threshold: Int, recipients: [String], currentDepth: Int, vaultManager: VaultManager) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let previous    = try vaultManager.backupShardMetadata(currentDepth: currentDepth)?.shards ?? []
        let previousIDs = Dictionary(previous.map { ($0.contactIdentifier, $0.attributeID) }, uniquingKeysWith: { $1 })
        let newKey      = Self.dropsTrustee(previous, recipients: recipients)

        try self.deleteQueuedAndWatchRows(forAttributeIDs: Set(previous.map(\.attributeID)), using: custodyKey)

        let attributes = try vaultManager.prepareBackupShards(
            threshold: threshold, recipients: recipients, newKey: newKey, currentDepth: currentDepth
        )

        for (recipient, attribute) in zip(recipients, attributes) {
            let rowID    = UUID()
            let combined = try self.sealRow(
                PendingShardDistribute.Payload(contactIdentifier: recipient, signedAttribute: attribute, oldAttributeID: previousIDs[recipient]),
                using: custodyKey, id: rowID
            )
            self.modelContext.insert(PendingShardDistribute(id: rowID, encryptedPayload: combined))
        }
        try self.modelContext.save()
    }

    /// Bring `currentDepth`'s backup-key piece statuses up to date with what trustees have
    /// reported, and re-send when a trustee no longer has a piece. Does nothing while the
    /// vault is locked.
    ///
    /// Per pending or confirmed piece in this depth's own record:
    /// - trustee's contact deleted (not in `liveContacts`) → `.lost`;
    /// - trustee is `changedContact` (their identity key just changed) → re-send;
    /// - watch row says the trustee holds it, status pending → `.confirmed`;
    /// - watch row says it's missing, not queued → re-send;
    /// - confirmed with no watch row (confirmed before watch rows persisted) → add one;
    /// - pending with neither a queued row nor a watch row (an interrupted
    ///   distribution) → re-send.
    ///
    /// A re-send re-splits the **same** key for the same trustees at the same threshold
    /// (`distributeBackup`); the owner keeps no split coefficients, so one trustee's piece
    /// can't be re-created alone. Skipped while any trustee in the record is lost or no
    /// longer a contact: leaving them out would have to split a new key, which breaks every
    /// exported backup, so that is the owner's call from the setup screen (`bugs.md` Bug 144).
    /// The erosion warning shows meanwhile.
    ///
    /// Reads and writes only this depth's backup-key row (`bugs.md` Bug 141). Watch and
    /// queued rows are depth-blind; this matches them by the piece IDs this depth's own
    /// record holds, and leaves every other row alone.
    func reconcileBackupPieces(
        currentDepth: Int, keyChangedFor changedContact: String? = nil, liveContacts: Set<String>, vaultManager: VaultManager
    ) {
        guard vaultManager.isUnlocked,
              let meta       = try? vaultManager.backupShardMetadata(currentDepth: currentDepth),
              let custodyKey = try? self.keyManager.deriveShardCustodyKey()
        else { return }

        let queuedIDs: Set<UUID> = Set(((try? self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())) ?? []).compactMap {
            (try? self.openRow($0.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: $0.id))?.signedAttribute.id
        })
        var watchAbsent: [UUID: Bool] = [:]
        for row in (try? self.modelContext.fetch(FetchDescriptor<PotentiallyLostShard>())) ?? [] {
            guard let payload = try? self.openRow(row.encryptedPayload, as: PotentiallyLostShard.Payload.self, using: custodyKey, id: row.id)
            else { continue }
            watchAbsent[payload.attributeID] = payload.isAbsent
        }

        var statusChanges: [UUID: ShardStatus] = [:]
        var resend = false
        var insertedWatch = false

        for record in meta.shards where record.status == .pending || record.status == .confirmed {
            let id = record.attributeID
            guard liveContacts.contains(record.contactIdentifier) else {
                statusChanges[id] = .lost
                continue
            }
            if record.contactIdentifier == changedContact {
                resend = true
                continue
            }
            switch (record.status, watchAbsent[id]) {
            case (.pending, false?):
                statusChanges[id] = .confirmed
            case (_, true?) where !queuedIDs.contains(id):
                resend = true
            case (.confirmed, nil):
                let rowID = UUID()
                if let combined = try? self.sealRow(
                    PotentiallyLostShard.Payload(attributeID: id, contactIdentifier: record.contactIdentifier, isAbsent: false),
                    using: custodyKey, id: rowID
                ) {
                    self.modelContext.insert(PotentiallyLostShard(id: rowID, encryptedPayload: combined))
                    insertedWatch = true
                }
            case (.pending, nil) where !queuedIDs.contains(id):
                resend = true
            default:
                break
            }
        }

        if insertedWatch { try? self.modelContext.save() }
        try? vaultManager.setBackupShardStatuses(statusChanges, currentDepth: currentDepth)

        guard resend,
              meta.shards.allSatisfy({ ($0.status == .pending || $0.status == .confirmed) && liveContacts.contains($0.contactIdentifier) })
        else { return }
        try? self.distributeBackup(
            threshold: meta.threshold, recipients: meta.shards.map(\.contactIdentifier),
            currentDepth: currentDepth, vaultManager: vaultManager
        )
    }

    /// Deletes every queued distribution and watch row whose piece is in `attributeIDs`.
    private func deleteQueuedAndWatchRows(forAttributeIDs attributeIDs: Set<UUID>, using custodyKey: SymmetricKey) throws {
        guard !attributeIDs.isEmpty else { return }
        var deletedAny = false
        for row in try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>()) {
            guard let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id),
                  attributeIDs.contains(payload.signedAttribute.id) else { continue }
            self.modelContext.delete(row)
            deletedAny = true
        }
        for row in try self.modelContext.fetch(FetchDescriptor<PotentiallyLostShard>()) {
            guard let payload = try? self.openRow(row.encryptedPayload, as: PotentiallyLostShard.Payload.self, using: custodyKey, id: row.id),
                  attributeIDs.contains(payload.attributeID) else { continue }
            self.modelContext.delete(row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    // MARK: - Global shard config (read-only — orphaned as of item 3's consolidation)

    /// Read-only, and only for `DatabaseMigration.migrateGlobalShardConfigToPerContact`
    /// — the one-time migration onto `Contact.Profile.globalTrusteeDepth`, the single
    /// trustee mechanism at every depth. No app code writes `GlobalShardConfig` anymore;
    /// once that migration has run for a given store, this always returns nil.
    func globalShardConfig() throws -> GlobalShardConfig.Payload? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<GlobalShardConfig>())
        for row in rows {
            if let payload = try? self.openRow(row.encryptedPayload, as: GlobalShardConfig.Payload.self, using: custodyKey, id: row.id) {
                return payload
            }
        }
        return nil
    }

    // MARK: - Contact deletion cleanup

    /// Removes every trace of a deleted contact from shard-custody state: any
    /// `CustodyShard` this device holds on their behalf, any `PendingShardDistribute`
    /// still owed to them, and any `PotentiallyLostShard` watch row for them. Called
    /// from `ContactManager.deleteContact`.
    ///
    /// Global-trustee status (`Contact.Profile.globalTrusteeDepth`) needs no purge step
    /// here — it lives on the contact's own row, which is soft-deleted (not hard-
    /// deleted) by `deleteContact`, and every read of `globalTrusteeDepth` already
    /// excludes rows with a non-nil `deletionToken`. The designation becomes
    /// unreachable the moment the contact is deleted, with nothing separate to purge.
    ///
    /// Unconditional, not depth-gated: unlike `Group`'s duress-depth membership,
    /// nothing here holds separate per-depth decoy content. A deleted contact is
    /// invalid everywhere, and removing their rows from these three stores touches
    /// nothing else — the same shape of operation as `Group.purgeMember(_:)`, which is
    /// likewise ungated for the same reason.
    ///
    /// Every surviving row in all three stores is also re-sealed with a fresh nonce,
    /// same content — mirrors `GlobalShardConfig`'s unconditional resave and
    /// `Group.refreshCiphertext()`. Without this, a raw-DB examiner comparing two
    /// snapshots across a deletion would see exactly which rows disappeared and find
    /// every surviving row byte-for-byte identical — cleanly separating "touched by
    /// this purge" from "untouched," a diff-based tell distinct from (and cheaper to
    /// close than) the owner-identity encryption this store already has. Rows that
    /// fail to decrypt are left untouched, same as before — not deleted, not re-sealed.
    ///
    /// Derives the shard-custody key once and reuses it across all three steps below,
    /// rather than once per step.
    func purgeCustody(for identifier: String) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        // 1. CustodyShard — shards this device holds on behalf of the deleted owner.
        for decoded in try self.decryptAllCustodyShards(using: custodyKey) {
            if decoded.payload.ownerContactIdentifier == identifier {
                self.modelContext.delete(decoded.row)
            } else {
                decoded.row.encryptedPayload = try self.sealRow(decoded.payload, using: custodyKey, id: decoded.row.id)
            }
        }

        // 2. PendingShardDistribute — shards queued to be sent to the deleted contact.
        let distributeRows = try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())
        for row in distributeRows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id)
            else { continue }
            if payload.contactIdentifier == identifier {
                self.modelContext.delete(row)
            } else {
                row.encryptedPayload = try self.sealRow(payload, using: custodyKey, id: row.id)
            }
        }

        // 3. PotentiallyLostShard — watch rows for the deleted contact.
        let lostRows = try self.modelContext.fetch(FetchDescriptor<PotentiallyLostShard>())
        for row in lostRows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PotentiallyLostShard.Payload.self, using: custodyKey, id: row.id)
            else { continue }
            if payload.contactIdentifier == identifier {
                self.modelContext.delete(row)
            } else {
                row.encryptedPayload = try self.sealRow(payload, using: custodyKey, id: row.id)
            }
        }

        try self.modelContext.save()
    }

    // MARK: - Private helpers

    enum CustodyError: Error {
        case invalidPayload
        case signatureRejected
        case keyDerivationFailed
        case encryptionFailed
    }

    private func sealRow<T: Codable>(_ payload: T, using key: SymmetricKey, id: UUID) throws -> Data {
        let bytes  = try JSONEncoder().encode(payload)
        let sealed = try AES.GCM.seal(bytes, using: key, nonce: AES.GCM.Nonce(), authenticating: Self.rowAAD(id: id))
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        return combined
    }

    private func openRow<T: Codable>(_ data: Data, as type: T.Type, using key: SymmetricKey, id: UUID) throws -> T {
        let box       = try AES.GCM.SealedBox(combined: data)
        let plaintext = try AES.GCM.open(box, using: key, authenticating: Self.rowAAD(id: id))
        return try JSONDecoder().decode(type, from: plaintext)
    }

    private struct DecodedCustodyShard {
        let row:     CustodyShard
        let payload: CustodyShard.Payload
    }

    private func decryptAllCustodyShards() throws -> [DecodedCustodyShard] {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        return try self.decryptAllCustodyShards(using: custodyKey)
    }

    /// Same as `decryptAllCustodyShards()` but reuses an already-derived key —
    /// for callers (like `purgeCustody(for:)`) that need it alongside other steps
    /// sharing the same derivation.
    private func decryptAllCustodyShards(using custodyKey: SymmetricKey) throws -> [DecodedCustodyShard] {
        let rows = try self.modelContext.fetch(FetchDescriptor<CustodyShard>())
        var out  = [DecodedCustodyShard]()
        out.reserveCapacity(rows.count)
        for row in rows {
            guard let payload = try? self.openRow(row.encryptedPayload, as: CustodyShard.Payload.self, using: custodyKey, id: row.id)
            else { continue }
            out.append(DecodedCustodyShard(row: row, payload: payload))
        }
        return out
    }

    private func deletePendingDistribute(attributeID: UUID, using custodyKey: SymmetricKey, rows: [PendingShardDistribute]) throws {
        var deletedAny = false
        for row in rows {
            guard let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id),
                  payload.signedAttribute.id == attributeID else { continue }
            self.modelContext.delete(row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    private static func fingerprint(of publicKey: Data) -> Data {
        Data(SHA256.hash(data: publicKey))
    }

    private static func rowAAD(id: UUID) -> Data {
        id.uuidString.data(using: .utf8)!
    }
}
