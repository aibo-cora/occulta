//
//  Contact+Model+Prekeys.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation
import SwiftData
import CryptoKit

extension Contact.Profile {
    // MARK: - Inbound prekeys (their keys, for encrypting TO them)

    /// Remove and return the oldest inbound prekey blob (FIFO).
    ///
    /// Returns nil when the inbound store is exhausted — caller falls back to
    /// the long-term key path and should attach a fresh batch in the bundle.
    func popOldestPrekeyData() -> Data? {
        guard var current = self.contactPrekeys, !current.isEmpty else { return nil }
        
        let oldest          = current.removeFirst()
        self.contactPrekeys = current
        
        return oldest
    }

    /// Replace the inbound prekey store with a new batch.
    ///
    /// Accepted only when `sequence > contactPrekeySequence` — prevents stale
    /// or duplicate batch replay.
    ///
    /// Replace semantics are intentional: when a higher-sequence batch arrives,
    /// the older keys will soon be pruned from the sender's SE anyway.
    func syncInboundPrekeys(_ blobs: [Data], sequence: Int) {
        guard sequence > self.contactPrekeySequence else { return }
        
        self.contactPrekeys        = blobs
        self.contactPrekeySequence = sequence
    }

    // MARK: - Outbound prekeys (our keys, for lookup when they encrypt back to us)

    /// Append freshly generated own-prekey blobs.
    ///
    /// Uses append (not replace) because multiple batches may be in flight:
    /// they might use a key from batch N while we have already generated batch N+1.
    /// All own prekeys must remain findable until individually consumed.
    func appendOwnPrekeys(_ blobs: [Data]) {
        if self.ownPrekeys == nil { self.ownPrekeys = [] }
        
        self.ownPrekeys?.append(contentsOf: blobs)
    }

    /// Find the own-prekey blob whose decrypted `Prekey.id` matches `id`.
    ///
    /// This is how we find our SE private key when they encrypt to us:
    /// their bundle contains the prekey ID; we search our own store to
    /// reconstruct the SE tag.
    ///
    /// Does NOT remove the blob — call `removeOwnPrekeyData` only after successful open.
    /// Decrypt errors per-entry are swallowed silently.
    func findOwnPrekeyData(id: String, decryptor: (Data) throws -> Data?) -> Data? {
        guard let entries = self.ownPrekeys else { return nil }
        
        for entry in entries {
            guard
                let decrypted = try? decryptor(entry),
                let prekey    = try? JSONDecoder().decode(Prekey.self, from: decrypted),
                prekey.id == id
            else { continue }
            
            return entry
        }
        return nil
    }

    /// Remove a specific own-prekey blob after successful decryption.
    ///
    /// Never called on decryption failure — leaving the blob in place allows
    /// retry on legitimate duplicate delivery.
    func removeOwnPrekeyData(_ blob: Data) {
        self.ownPrekeys?.removeAll { $0 == blob }
    }

    /// Remove own-prekey blobs whose sequence is strictly less than `threshold`.
    ///
    /// Must be called after `PrekeyManager.generateBatch` with the same threshold
    /// the SE uses for pruning (`currentSequence - 1`).
    ///
    /// Without this, ownPrekeys accumulates dead blobs indefinitely: the SE private
    /// keys for old sequences are pruned, making those blobs permanently unusable,
    /// but they remain in SwiftData growing the array on every new batch.
    ///
    /// Blobs that cannot be decrypted are kept defensively — do not remove what
    /// we cannot read, in case the local encryption key state is temporarily
    /// inconsistent.
    func pruneOwnPrekeys(olderThan threshold: Int, decryptor: (Data) throws -> Data?) {
        guard threshold > 0, var entries = self.ownPrekeys, !entries.isEmpty else { return }
        
        entries = entries.filter { blob in
            guard
                let decrypted = try? decryptor(blob),
                let prekey    = try? JSONDecoder().decode(Prekey.self, from: decrypted)
            else { return true }     // keep if unreadable — defensive
            
            return prekey.sequence >= threshold
        }
        
        self.ownPrekeys = entries
    }

    // MARK: - Stock

    var availableInboundPrekeyCount: Int { self.contactPrekeys?.count ?? 0 }

    /// Whether we have their prekeys available for forward-secret encryption.
    var hasPrekeyAvailable: Bool { self.availableInboundPrekeyCount > 0 }

    var ownPrekeysCount: Int { self.ownPrekeys?.count ?? 0 }

    // MARK: - Sender identification

    /// Check whether this contact is the sender of `bundle`.
    ///
    /// SHA-256(contactPublicKey || bundle.fingerprintNonce) compared against
    /// bundle.senderFingerprint. O(1) per contact — no trial ECDH.
    func isLikelySender(of bundle: OccultaBundle, contactPublicKey: Data) -> Bool {
        let candidate = OccultaBundle.SecrecyContext.fingerprint(for: contactPublicKey, nonce: bundle.fingerprintNonce)
        
        return candidate == bundle.senderFingerprint
    }
}
