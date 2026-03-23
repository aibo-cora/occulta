//
//  Contact+Model+Prekeys.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation
import SwiftData
import CryptoKit

// MARK: - Prekey storage and sender identification on Contact.Profile

extension Contact.Profile {
    // MARK: - Inbound prekeys (their keys, for encrypting TO them)

    /// Remove and return the oldest inbound prekey blob (FIFO).
    ///
    /// Returns nil when exhausted — caller falls back to long-term path
    /// and should have a pending batch ready to attach.
    func popOldestPrekeyData() -> Data? {
        guard var current = self.contactPrekeys, !current.isEmpty else { return nil }
        let oldest          = current.removeFirst()
        self.contactPrekeys = current
        return oldest
    }

    /// Merge a new inbound prekey batch into the store.
    ///
    /// ## Semantics: prune dead entries, then append — never blind replace.
    ///
    /// Blind replace caused the original bug: valid unused prekeys were discarded
    /// whenever a higher-sequence batch arrived. This implementation:
    ///   1. Prunes entries whose `sequence < incomingSequence - 1`.
    ///      Those private keys are already gone from the sender's SE (they prune
    ///      `seq < currentSequence - 1` automatically in `generateBatch`).
    ///      Keeping them would waste pop slots on keys that can never be used.
    ///   2. Appends the new blobs so unconsumed prekeys from the previous batch
    ///      are not discarded — they are still valid and the sender still holds
    ///      their private keys.
    ///
    /// Blobs that fail decryption are kept defensively in case of transient
    /// local key state issues.
    ///
    /// - Parameters:
    ///   - blobs:     New inbound prekey blobs (local-key AES-GCM encrypted).
    ///   - sequence:  The `PrekeySyncBatch.sequence` of the incoming batch.
    ///   - decryptor: Closure to decrypt a blob to its raw bytes. Non-throwing;
    ///                return nil on failure.
    func syncInboundPrekeys(
        _ blobs: [Data],
        sequence: Int,
        decryptor: (Data) -> Data?
    ) {
        guard sequence > self.contactPrekeySequence else { return }

        // Prune entries that are provably dead: their private keys have been
        // deleted from the sender's SE (sequence < incomingSequence - 1).
        if var existing = self.contactPrekeys, !existing.isEmpty {
            existing = existing.filter { blob in
                guard
                    let raw    = decryptor(blob),
                    let prekey = try? JSONDecoder().decode(Prekey.self, from: raw)
                else { return true }                          // keep if unreadable
                return prekey.sequence >= sequence - 1
            }
            existing.append(contentsOf: blobs)
            self.contactPrekeys = existing
        } else {
            self.contactPrekeys = blobs
        }

        self.contactPrekeySequence = sequence
    }

    // MARK: - Outbound prekeys (our keys, for lookup when they encrypt to us)

    /// Append freshly generated own-prekey blobs.
    ///
    /// Append (not replace) because multiple batches may be in flight.
    func appendOwnPrekeys(_ blobs: [Data]) {
        if self.ownPrekeys == nil { self.ownPrekeys = [] }
        self.ownPrekeys?.append(contentsOf: blobs)
    }

    /// Find the own-prekey blob whose decrypted `Prekey.id` matches `id`.
    ///
    /// Does NOT remove the blob. Call `removeOwnPrekeyData` only after
    /// successful open — failure leaves it in place for retry.
    func findOwnPrekeyData(id: String, decryptor: (Data) throws -> Data?) -> Data? {
        guard let entries = self.ownPrekeys else { return nil }
        for entry in entries {
            guard
                let raw    = try? decryptor(entry),
                let prekey = try? JSONDecoder().decode(Prekey.self, from: raw),
                prekey.id == id
            else { continue }
            return entry
        }
        return nil
    }

    /// Remove a specific own-prekey blob after successful decryption.
    func removeOwnPrekeyData(_ blob: Data) {
        self.ownPrekeys?.removeAll { $0 == blob }
    }

    /// Remove own-prekey blobs whose sequence is strictly less than `threshold`.
    ///
    /// Mirrors SE pruning: called with the same threshold as `generateBatch`
    /// (`currentSequence - 1`) so dead blobs don't accumulate in SwiftData.
    ///
    /// Blobs that fail decryption are kept defensively.
    func pruneOwnPrekeys(olderThan threshold: Int, decryptor: (Data) -> Data?) {
        guard threshold > 0, var entries = self.ownPrekeys, !entries.isEmpty else { return }
        entries = entries.filter { blob in
            guard
                let raw    = decryptor(blob),
                let prekey = try? JSONDecoder().decode(Prekey.self, from: raw)
            else { return true }
            return prekey.sequence >= threshold
        }
        self.ownPrekeys = entries
    }

    // MARK: - Pending outbound batch

    /// Persist `batch` as the pending outbound batch for this contact.
    ///
    /// Called when a new batch is generated. The batch rides every subsequent
    /// outbound message until `clearPendingBatch` is called.
    func storePendingBatch(_ batch: OccultaBundle.PrekeySyncBatch) throws {
        self.pendingOutboundBatch = try JSONEncoder().encode(batch)
    }

    /// Return the pending outbound batch, or nil if none is waiting.
    func loadPendingBatch() -> OccultaBundle.PrekeySyncBatch? {
        guard let data = self.pendingOutboundBatch else { return nil }
        
        return try? JSONDecoder().decode(OccultaBundle.PrekeySyncBatch.self, from: data)
    }

    /// Clear the pending outbound batch.
    ///
    /// Called when we receive cryptographic proof that the contact received
    /// our batch — i.e., when `removeOwnPrekeyData` fires (they used one of
    /// our prekeys to encrypt a message back to us).
    func clearPendingBatch() {
        self.pendingOutboundBatch = nil
    }

    /// Whether a batch is currently waiting for delivery confirmation.
    var hasPendingBatch: Bool { self.pendingOutboundBatch != nil }

    // MARK: - Stock

    var availableInboundPrekeyCount: Int { self.contactPrekeys?.count ?? 0 }
    var hasPrekeyAvailable:          Bool { availableInboundPrekeyCount > 0 }
    var ownPrekeysCount:             Int  { self.ownPrekeys?.count ?? 0 }

    // MARK: - Sender identification

    /// SHA-256(contactPublicKey || bundle.fingerprintNonce) == bundle.senderFingerprint.
    /// O(1) per contact — no trial ECDH.
    func isLikelySender(of bundle: OccultaBundle, contactPublicKey: Data) -> Bool {
        let candidate = OccultaBundle.SecrecyContext.fingerprint(
            for:   contactPublicKey,
            nonce: bundle.fingerprintNonce
        )
        return candidate == bundle.senderFingerprint
    }
}
