//
//  Contact+Model+Prekeys.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation
import SwiftData

// MARK: - Prekey storage and sender identification on Contact.Profile

extension Contact.Profile {

    // MARK: - Prekey sync (replace, not append)

    /// Sync an inbound ``PrekeySyncBatch`` onto this contact's prekey store.
    ///
    /// ## Replace semantics
    /// If `batch.sequence > contactPrekeySequence`:
    /// - Replace `contactPrekeys` entirely with the new batch
    /// - Update `contactPrekeySequence` to `batch.sequence`
    /// - Prune our own SE private keys from the old sequence (see below)
    ///
    /// If `batch.sequence <= contactPrekeySequence`:
    /// - Ignore — duplicate delivery or stale batch
    ///
    /// ## Why we prune our own SE keys here
    /// When this contact sends us a new prekey batch (seq N), it means they
    /// have discarded their old prekeys (seq N-1). Any of our SE private keys
    /// corresponding to that contact's old public keys will never be used to
    /// decrypt a bundle. We prune them to avoid accumulation.
    ///
    /// We keep seq N-1 as a one-step safety buffer in case a bundle encrypted
    /// with the old batch arrives out of order.
    ///
    /// - Parameters:
    ///   - batch:         The ``PrekeySyncBatch`` from `bundle.secrecy.prekeyBatch`.
    ///   - cryptoOps:     Crypto manager for encrypting each `Prekey` before storage.
    ///   - prekeyManager: Used to prune our own SE keys from old sequences.
    func syncPrekeyBatch(
        _ batch: OccultaBundle.PrekeySyncBatch,
        using cryptoOps: Manager.Crypto,
        prekeyManager: Manager.PrekeyManager
    ) throws {
        let storedSequence = self.contactPrekeySequence

        // Ignore stale or duplicate batches.
        guard batch.sequence > storedSequence else { return }

        // Encrypt each Prekey before storage — consistent with how all key
        // material is handled in the app.
        let encrypted: [Data] = try batch.prekeys.compactMap { prekey in
            let encoded = try JSONEncoder().encode(prekey)
            return try cryptoOps.encrypt(data: encoded)
        }

        // Replace entirely — do not append.
        self.contactPrekeys      = encrypted
        self.contactPrekeySequence = batch.sequence

        // Prune our own SE private keys from sequences older than storedSequence.
        // storedSequence was the last batch this contact had — keys from that
        // batch are still valid as a one-step buffer. Anything older is orphaned.
        if storedSequence > 0 {
            prekeyManager.pruneSequences(olderThan: storedSequence)
        }
    }

    // MARK: - Prekey consumption

    /// Remove and return the oldest prekey from this contact's store, decrypted.
    ///
    /// Returns `nil` if the store is empty — caller should trigger the fallback path.
    ///
    /// - Parameter cryptoOps: Crypto manager for decrypting stored key material.
    /// - Returns: The oldest ``Prekey``, or `nil` if the store is empty.
    func popOldestPrekey(using cryptoOps: Manager.Crypto) throws -> Prekey? {
        guard
            var current = self.contactPrekeys,
            !current.isEmpty
        else { return nil }

        let encryptedEntry = current.removeFirst()
        self.contactPrekeys = current

        guard let decrypted = try cryptoOps.decrypt(data: encryptedEntry) else {
            return nil
        }

        return try JSONDecoder().decode(Prekey.self, from: decrypted)
    }

    /// Number of prekeys currently stored for this contact.
    var storedPrekeyCount: Int {
        self.contactPrekeys?.count ?? 0
    }

    /// Whether this contact has prekeys available for forward-secret encryption.
    var hasPrekeyAvailable: Bool {
        self.storedPrekeyCount > 0
    }

    // MARK: - Sender identification

    /// Check whether this contact is the sender of a given bundle.
    ///
    /// Computes SHA-256(contact.longTermPublicKey || bundle.secrecy.fingerprintNonce)
    /// and compares against `bundle.secrecy.senderFingerprint`.
    ///
    /// O(1) per contact — caller iterates contacts until a match (O(n) total).
    /// Called before decryption — no trial ECDH required.
    ///
    /// - Parameters:
    ///   - bundle:     The received ``OccultaBundle``.
    ///   - cryptoOps:  Crypto manager for decrypting stored key material.
    /// - Returns: `true` if this contact's fingerprint matches the bundle's.
    func isLikelySender(
        of bundle: OccultaBundle,
        using cryptoOps: Manager.Crypto
    ) -> Bool {
        guard
            let keyRecord        = self.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
            let contactPublicKey = try? cryptoOps.decrypt(data: keyRecord.material)
        else { return false }

        let candidate = OccultaBundle.SecrecyContext.fingerprint(
            for: contactPublicKey,
            nonce: bundle.secrecy.fingerprintNonce
        )

        // Data == is constant-time in Swift — safe against timing side-channels.
        return candidate == bundle.secrecy.senderFingerprint
    }
}
