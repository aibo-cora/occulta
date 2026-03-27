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
    /// Init an empty object that we can change as we start using Forward Secrecy.
    func configureForwardSecrecy() throws {
        if let _ = self.forwardSecrecyEncrypted {
            return
        } else {
            let secrecy = ForwardSecrecy()
            
            try self.update(secrecy: secrecy)
        }
    }
    /// Decrypting forward secrecy struct.
    var plainTextForwardSecrecy: ForwardSecrecy? {
        get throws {
            guard
                let forwardSecrecyEncrypted,
                let decrypted = forwardSecrecyEncrypted.decrypt()
            else {
                return nil
            }
            
            let secrecy = try JSONDecoder().decode(ForwardSecrecy.self, from: decrypted)
            
            return secrecy
        }
    }
    /// Encrypting forward secrecy and updating it for a contact.
    private func update(secrecy: ForwardSecrecy) throws {
        let encoded = try JSONEncoder().encode(secrecy)
        let encrypted = try encoded.encrypt()
        
        self.forwardSecrecyEncrypted = encrypted
    }
    
    // MARK: - Inbound prekeys (their keys, for encrypting TO them)

    /// Remove and return the oldest inbound prekey blob (FIFO).
    ///
    /// Returns nil when exhausted — caller falls back to long-term path
    /// and should have a pending batch ready to attach.
    func popOldestPrekeyData() throws -> Data? {
        guard
            var secrecy = try self.plainTextForwardSecrecy,
            var current = secrecy.contactPrekeys, !current.isEmpty
        else {
            debugPrint("popOldestPrekeyData: no prekeys available")
            
            return nil
        }
        
        let oldest = current.removeFirst()
        
        secrecy.contactPrekeys = current.isEmpty ? nil : current
        
        debugPrint("popOldestPrekeyData: popped one, remaining: \(current.count)")
        
        try self.update(secrecy: secrecy)
        
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
    ///   - blobs:     New inbound prekey blobs (plaintext).
    ///   - sequence:  The `PrekeySyncBatch.sequence` of the incoming batch.
    ///   - decryptor: Closure to decrypt a blob to its raw bytes. Non-throwing;
    ///                return nil on failure.
    func syncInboundPrekeys(_ blobs: [Data], sequence: Int) throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        
        let currentSeq = secrecy.contactPrekeySequence ?? -1
        
        debugPrint("syncInboundPrekeys called - sequence: \(sequence), current: \(currentSeq), prekeys count: \(secrecy.contactPrekeys?.count ?? 0)")

        // Allow == sequence (idempotent) — only reject older batches
        guard sequence >= currentSeq else {
            debugPrint("syncInboundPrekeys: sequence \(sequence) < current \(currentSeq) → skipping (older batch)")
            
            return
        }

        var target = secrecy.contactPrekeys ?? []

        // Prune only provably dead entries (sequence < incoming - 1)
        if !target.isEmpty {
            target = target.filter { blob in
                guard
                    let prekey = try? JSONDecoder().decode(Prekey.self, from: blob)
                else { return true } // keep unreadable defensively
                
                return prekey.sequence >= sequence - 1
            }
        }

        target.append(contentsOf: blobs)
        
        secrecy.contactPrekeys = target.isEmpty ? nil : target
        secrecy.contactPrekeySequence = sequence

        debugPrint("syncInboundPrekeys SUCCESS: now \(target.count) prekeys, sequence = \(sequence)")
        
        try self.update(secrecy: secrecy)
    }

    // MARK: - Outbound prekeys (our keys, for lookup when they encrypt to us)

    /// Append freshly generated own-prekey blobs, plain text.
    ///
    /// Append (not replace) because multiple batches may be in flight.
    func appendOwnPrekeys(_ blobs: [Data]) throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        
        if secrecy.ownPrekeys == nil {
            secrecy.ownPrekeys = blobs
        } else {
            secrecy.ownPrekeys?.append(contentsOf: blobs)
        }
        
        try self.update(secrecy: secrecy)
    }

    /// Find the own-prekey blob whose decrypted `Prekey.id` matches `id`.
    ///
    /// Does NOT remove the blob. Call `removeOwnPrekeyData` only after
    /// successful open — failure leaves it in place for retry.
    func findOwnPrekeyData(id: String) throws -> Data? {
        guard
            let secrecy = try self.plainTextForwardSecrecy,
            let entries = secrecy.ownPrekeys,
            entries.isEmpty == false
        else {
            return nil
        }
        
        for entry in entries {
            let prekey = try JSONDecoder().decode(Prekey.self, from: entry)
            
            guard
                prekey.id == id
            else {
                continue
            }
            
            return entry
        }
        
        return nil
    }

    /// Remove a specific own-prekey blob after successful decryption.
    func removeOwnPrekeyData(_ blob: Data) throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        
        secrecy.ownPrekeys?.removeAll { $0 == blob }
        
        try self.update(secrecy: secrecy)
    }

    /// Remove own-prekey blobs whose sequence is strictly less than `threshold`.
    ///
    /// Mirrors SE pruning: called with the same threshold as `generateBatch`
    /// (`currentSequence - 1`) so dead blobs don't accumulate in SwiftData.
    ///
    /// Blobs that fail decryption are kept defensively.
    func pruneOwnPrekeys(olderThan threshold: Int) throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy,
            threshold > 0,
            let entries = secrecy.ownPrekeys,
            entries.isEmpty == false
        else {
            return
        }
        
        let filtered = entries.filter { encoded in
            guard
                let prekey = try? JSONDecoder().decode(Prekey.self, from: encoded)
            else { return true }
            
            return prekey.sequence >= threshold
        }
        
        secrecy.ownPrekeys = filtered
        
        try self.update(secrecy: secrecy)
    }

    // MARK: - Pending outbound batch

    /// Called when a new batch is generated. The batch rides every subsequent
    /// outbound message until `clearPendingBatch` is called.
    /// - Parameters:
    ///   - batch:Ppending outbound batch for this contact.
    ///   - sequence: New sequence #.
    func store(batch: OccultaBundle.PrekeySyncBatch, sequence: Int?) throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        
        let encoded = try JSONEncoder().encode(batch)
        
        secrecy.pendingOutboundBatch = encoded
        secrecy.outboundPrekeySequence = sequence
        
        try self.update(secrecy: secrecy)
        
        debugPrint("Stored new batch of prekeys: \(batch.prekeys.count), sequence: \(String(describing: sequence))")
    }

    /// Return the pending outbound batch, or nil if none is waiting.
    func loadPendingBatch() throws -> OccultaBundle.PrekeySyncBatch? {
        guard
            let secrecy = try self.plainTextForwardSecrecy,
            let encoded = secrecy.pendingOutboundBatch
        else {
            return nil
        }
        
        let batch = try JSONDecoder().decode(OccultaBundle.PrekeySyncBatch.self, from: encoded)
        
        return batch
    }

    /// Clear the pending outbound batch.
    ///
    /// Called when we receive cryptographic proof that the contact received
    /// our batch — i.e., when `removeOwnPrekeyData` fires (they used one of
    /// our prekeys to encrypt a message back to us).
    func clearPendingBatch() throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        
        secrecy.pendingOutboundBatch = nil
        
        try self.update(secrecy: secrecy)
    }

    /// Whether a batch is currently waiting for delivery confirmation.
    var hasPendingBatch: Bool {
        let secrecy = try? self.plainTextForwardSecrecy
        
        return secrecy?.pendingOutboundBatch != nil
    }

    // MARK: - Stock

    var availableInboundPrekeyCount: Int  {
        let secrecy = try? self.plainTextForwardSecrecy
        
        return secrecy?.contactPrekeys?.count ?? 0
    }
    
    var hasPrekeyAvailable: Bool {
        self.availableInboundPrekeyCount > 0
    }
    
    var ownPrekeysCount: Int {
        let secrecy = try? self.plainTextForwardSecrecy
        
        return secrecy?.ownPrekeys?.count ?? 0
    }

    // MARK: - Sender identification

    /// SHA-256(contactPublicKey || bundle.fingerprintNonce) == bundle.senderFingerprint.
    /// O(1) per contact — no trial ECDH.
    func isLikelySender(of bundle: OccultaBundle, contactPublicKey: Data) -> Bool {
        let candidate = OccultaBundle.SecrecyContext.fingerprint(for: contactPublicKey, nonce: bundle.fingerprintNonce)
        
        return candidate == bundle.senderFingerprint
    }
}
