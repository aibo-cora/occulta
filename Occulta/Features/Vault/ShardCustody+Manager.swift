//
//  ShardCustody+Manager.swift
//  Occulta
//
//  Inbound router for ShardOperation traffic + manifest reconciliation.
//
//  Two roles, one router:
//    - Trustee path: accept .distribute / .replace from the owner; store as encrypted
//      CustodyShard rows; return mismatch-fingerprint shards as .handback on every
//      outbound bundle; delete same-fingerprint shards absent from owner's expectedShards.
//    - Owner path: receive .handback from trustees; include custodyManifest (IDs held)
//      in every outbound bundle; include expectedShards (IDs expected) in every
//      outbound bundle to trigger implicit revoke.
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
        expectedShards:   [UUID]?,
        senderPublicKey:  Data,
        senderIdentifier: String,
        vaultManager:     VaultManager,
        currentDepth:     Int
    ) -> Bool {
        let hasOps      = (shardOperations?.isEmpty == false)
        let hasManifest = custodyManifest != nil
        let hasExpected = expectedShards  != nil

        guard hasOps || hasManifest || hasExpected else { return false }

        for op in shardOperations ?? [] {
            do {
                switch op.kind {
                case .distribute:
                    try self.handleDistribute(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .replace:
                    try self.handleReplace(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .handback:
                    try self.handleHandback(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier, vaultManager: vaultManager, currentDepth: currentDepth)
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
            do { try self.processInboundManifest(manifest, from: senderIdentifier, vaultManager: vaultManager) }
            catch {
                #if DEBUG
                debugPrint("ShardCustodyManager processInboundManifest failed: \(error)")
                #endif
            }
        }
        if let expected = expectedShards {
            do { try self.processExpectedShards(expected, from: senderIdentifier, senderPublicKey: senderPublicKey) }
            catch {
                #if DEBUG
                debugPrint("ShardCustodyManager processExpectedShards failed: \(error)")
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

        try self.deleteMismatchShards(for: senderIdentifier, newFingerprint: newFP)
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

        let allShards = try self.decryptAllCustodyShards()
        for decoded in allShards
            where decoded.payload.signedAttribute.id == oldID
               && decoded.payload.ownerContactIdentifier == senderIdentifier {
            self.modelContext.delete(decoded.row)
        }
        try self.deleteMismatchShards(for: senderIdentifier, newFingerprint: newFP)
        try self.modelContext.save()
    }

    /// Delete all CustodyShard rows for `contactIdentifier` whose fingerprint ≠ `newFingerprint`.
    private func deleteMismatchShards(for contactIdentifier: String, newFingerprint: Data) throws {
        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.ownerContactIdentifier == contactIdentifier
               && decoded.payload.ownerKeyFingerprint != newFingerprint {
            self.modelContext.delete(decoded.row)
        }
    }

    // MARK: - Owner path: inbound

    /// `.handback` — trustee returned one of our shards after detecting a fingerprint mismatch.
    ///
    /// Two ways to accept (Bug 94 remedy 2):
    ///
    ///   **Branch A — direct verify.** `attribute` verifies against our own current
    ///   identity key. Unrotated case: same-device reinstall, or a device that never
    ///   lost its Enclave key. Can only ever be genuine — forging it means breaking
    ///   ECDSA or stealing the SE key — so no further check is needed.
    ///
    ///   **Branch B — trustee attestation.** Direct verification fails (rotated
    ///   identity — a genuinely new or erased device can't verify a signature made
    ///   by a key that no longer exists), but `op.attestation` verifies against
    ///   `senderPublicKey` and hashes to exactly `attribute.signingPayload()`. The
    ///   trustee checked `attribute` against their own retained copy of our old key
    ///   (something only a genuine trustee could ever have) and vouched for it with
    ///   their current identity, which we can verify because we just re-paired with
    ///   them over UWB regardless.
    ///
    /// Neither branch is gated on `isRestorePending` here — that used to be the
    /// escape hatch for the rotated case, and it accepted *any* unverified shard
    /// whenever a restore happened to be pending, from anyone. Acceptance is now
    /// itself the authentication; what's still pending-gated is what happens next,
    /// inside `acceptReturnedShard` (BEK storage) and its own per-entry check
    /// (distribution-metadata storage) — deliberately two different gates, not one
    /// loosened uniformly, since a fresh device can't know the expected BEK
    /// `distributionID` any more precisely than "is a restore armed."
    private func handleHandback(
        op: OccultaBundle.ShardOperation,
        senderPublicKey: Data,
        senderIdentifier: String,
        vaultManager: VaultManager,
        currentDepth: Int
    ) throws {
        guard let attribute = op.attribute, attribute.category == .shard else {
            throw CustodyError.invalidPayload
        }

        if let ownKey = try? self.keyManager.retrieveIdentity(), attribute.verify(against: ownKey) {
            // Branch A.
        } else if let attestation = op.attestation,
                  attestation.category == .attestation,
                  attestation.entryID == attribute.entryID,
                  attestation.verify(against: senderPublicKey),
                  attestation.value == Data(SHA256.hash(data: attribute.signingPayload())) {
            // Branch B.
        } else {
            throw CustodyError.signatureRejected
        }

        try vaultManager.acceptReturnedShard(
            attribute,
            attestation: op.attestation,
            senderIdentifier: senderIdentifier,
            currentDepth: currentDepth
        )
    }

    // MARK: - Manifest reconciliation

    /// Process trustee's `custodyManifest` — the IDs of all shards they currently hold.
    ///
    /// Confirm in-flight shards whose IDs appear in the manifest (direct vault update
    /// if unlocked, queued via PendingShardStatusUpdate if locked). Insert a
    /// PotentiallyLostShard row for each newly confirmed shard so future absence
    /// can be detected at vault unlock.
    ///
    /// Update the isAbsent flag on all existing PotentiallyLostShard rows for this
    /// contact — true when absent from this manifest, false when present. VaultManager
    /// processes absent rows and marks them .lost the next time the vault unlocks.
    func processInboundManifest(_ manifest: [UUID], from senderIdentifier: String, vaultManager: VaultManager) throws {
        let manifestSet = Set(manifest)

        guard let custodyKey = try? self.keyManager.deriveShardCustodyKey() else { return }
        let distributeRows = (try? self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())) ?? []

        let inFlightIDs: Set<UUID> = Set(distributeRows.compactMap {
            guard let payload = try? self.openRow($0.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: $0.id),
                  payload.contactIdentifier == senderIdentifier else { return nil }
            return payload.signedAttribute.id
        })

        // Confirm in-flight shards that appear in the manifest.
        for inFlightId in inFlightIDs where manifestSet.contains(inFlightId) {
            do {
                try vaultManager.updateShardStatus(attributeID: inFlightId, to: .confirmed)
            } catch VaultManager.VaultError.locked {
                try? self.queueShardStatusUpdate(attributeID: inFlightId, newStatus: .confirmed)
            } catch {}

            // Record delivery so future absence can be caught at vault unlock.
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

    /// Process owner's `expectedShards` — IDs the owner expects this trustee to hold.
    ///
    /// Deletes same-fingerprint shards absent from the list (implicit revoke).
    /// Mismatch-fingerprint shards are immune — only cleared by a new `.distribute`
    /// with the owner's updated fingerprint (Invariant 1 from SHARD_PROTOCOL_CASES.md).
    func processExpectedShards(_ expectedIDs: [UUID], from ownerIdentifier: String, senderPublicKey: Data) throws {
        let expectedSet   = Set(expectedIDs)
        let currentFP     = Self.fingerprint(of: senderPublicKey)
        var deletedAny    = false

        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.ownerContactIdentifier == ownerIdentifier
               && decoded.payload.ownerKeyFingerprint == currentFP
               && !expectedSet.contains(decoded.payload.signedAttribute.id) {
            self.modelContext.delete(decoded.row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    // MARK: - Outbound: build shard operations

    /// Build the outbound ShardOperation list for `contactIdentifier`.
    ///
    /// Owner side: `.distribute` / `.replace` from PendingShardDistribute rows.
    /// Trustee side: `.handback` for mismatch-fingerprint shards (signals key rotation).
    func buildShardOperations(for contactIdentifier: String, currentContactPublicKey: Data?) throws -> [OccultaBundle.ShardOperation] {
        var ops = [OccultaBundle.ShardOperation]()
        ops += try self.pendingDistributeOps(for: contactIdentifier)
        if let pubKey = currentContactPublicKey {
            ops += try self.mismatchHandbackOps(for: contactIdentifier, currentFP: Self.fingerprint(of: pubKey))
        }
        return ops
    }

    private func pendingDistributeOps(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation] {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
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
    /// Each op carries an attestation when this device can produce one (Bug 94
    /// remedy 2) — `attestation(for:)` returns nil on any failure, which is the
    /// safe default: the op still goes out, just without a Branch B path.
    private func mismatchHandbackOps(for contactIdentifier: String, currentFP: Data) throws -> [OccultaBundle.ShardOperation] {
        return try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == contactIdentifier && $0.payload.ownerKeyFingerprint != currentFP }
            .map    { OccultaBundle.ShardOperation(
                kind:        .handback,
                attribute:   $0.payload.signedAttribute,
                attestation: self.attestation(for: $0.payload)
            ) }
    }

    /// Vouch for `payload.signedAttribute` with this device's *current* identity key,
    /// but only after independently verifying it against the owner's *retained old*
    /// key — the check the owner's own new device structurally cannot perform, since
    /// SE identity keys are non-exportable and die with the device they were created
    /// on. Returns nil (no attestation, not a throw) whenever any step fails: no
    /// matching key on file, the retained key doesn't decrypt, or the original
    /// signature doesn't verify against it. A missing attestation just means this
    /// op falls back to Branch A only — never a reason to treat the shard as invalid
    /// here, since Branch A remains valid whenever the owner's identity hasn't
    /// rotated at all.
    private func attestation(for payload: CustodyShard.Payload) -> SignedAttribute? {
        guard let ownerIdentifier = payload.ownerContactIdentifier else { return nil }

        let contacts = (try? self.modelContext.fetch(
            FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.identifier == ownerIdentifier })
        )) ?? []
        guard let owner = contacts.first else { return nil }

        let crypto = Manager.Crypto(keyManager: self.keyManager)
        let matchingKey = owner.contactPublicKeys?.first { record in
            guard let material = try? crypto.decrypt(data: record.material) else { return false }
            return Self.fingerprint(of: material) == payload.ownerKeyFingerprint
        }
        guard
            let matchingKey,
            let retainedOldKey = try? crypto.decrypt(data: matchingKey.material)
        else { return nil }

        guard payload.signedAttribute.verify(against: retainedOldKey) else { return nil }

        let hash      = Data(SHA256.hash(data: payload.signedAttribute.signingPayload()))
        let attrID    = UUID()
        let createdAt = Date()
        let signingPayload = SignedAttribute.signingPayload(
            id: attrID, category: .attestation, value: hash,
            entryID: payload.signedAttribute.entryID, createdAt: createdAt
        )
        guard let signature = try? self.keyManager.signData(signingPayload) else { return nil }

        return SignedAttribute(
            id: attrID, label: "shard-attestation", value: hash, category: .attestation,
            signature: signature, createdAt: createdAt, entryID: payload.signedAttribute.entryID
        )
    }

    // MARK: - Outbound: build manifest fields

    /// IDs of all shards currently held for `ownerIdentifier`. Sent in every outbound bundle.
    func buildCustodyManifest(for ownerIdentifier: String) throws -> [UUID] {
        return try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == ownerIdentifier }
            .map    { $0.payload.signedAttribute.id }
    }

    /// IDs the owner expects `trusteeIdentifier` to hold. Sent in every outbound bundle.
    ///
    /// Throws `CustodyError.keyDerivationFailed` when the vault is locked. Callers use
    /// `try?` so the field is omitted (nil) from the bundle — an empty array would signal
    /// "expect nothing" and cause the trustee to delete all shards they hold.
    ///
    /// Includes `.pending` and `.confirmed` shards only — `.lost` and `.revoked` are
    /// already terminal and must not be re-sent (they would un-revoke on the trustee).
    func buildExpectedShards(for trusteeIdentifier: String, vaultManager: VaultManager) throws -> [UUID] {
        guard vaultManager.isUnlocked else { throw CustodyError.keyDerivationFailed }
        return vaultManager.shardRecordsForTrustee(trusteeIdentifier)
            .filter { $0.status == .pending || $0.status == .confirmed }
            .map    { $0.attributeID }
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

    private func queueShardStatusUpdate(attributeID: UUID, newStatus: ShardStatus) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rowID    = UUID()
        let combined = try self.sealRow(PendingShardStatusUpdate.Payload(attributeID: attributeID, newStatus: newStatus), using: custodyKey, id: rowID)
        self.modelContext.insert(PendingShardStatusUpdate(id: rowID, encryptedPayload: combined))
        
        try self.modelContext.save()
    }

    private static func fingerprint(of publicKey: Data) -> Data {
        Data(SHA256.hash(data: publicKey))
    }

    private static func rowAAD(id: UUID) -> Data {
        id.uuidString.data(using: .utf8)!
    }
}
