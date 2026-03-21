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

    // MARK: - Raw prekey store access

    /// Remove and return the oldest raw encrypted prekey blob from the store.
    ///
    /// Returns the encrypted `Data` blob — the caller decrypts it.
    /// Returns `nil` if the store is empty.
    func popOldestPrekeyData() -> Data? {
        guard
            var current = self.contactPrekeys,
            !current.isEmpty
        else { return nil }

        let oldest      = current.removeFirst()
        self.contactPrekeys = current
        
        return oldest
    }

    /// Replace the contact's prekey store entirely with new encrypted blobs.
    ///
    /// Only replaces if `sequence > contactPrekeySequence` (newer batch).
    /// Ignores stale or duplicate batches silently.
    ///
    /// The caller is responsible for:
    /// - Encrypting each `Prekey` before building `blobs`.
    /// - Calling `PrekeyManager.pruneSequences(olderThan:contactID:)` after
    ///   this call to clean up old SE keys.
    ///
    /// - Parameters:
    ///   - blobs:    Encrypted `Prekey` blobs to store. Must match the `prekeys`
    ///               array from a ``PrekeySyncBatch``, each AES-GCM encrypted.
    ///   - sequence: The `PrekeySyncBatch.sequence` of the incoming batch.
    func syncPrekeyData(_ blobs: [Data], sequence: Int) {
        guard sequence > self.contactPrekeySequence else { return }
        
        self.contactPrekeys        = blobs
        self.contactPrekeySequence = sequence
    }

    /// Find and return the raw encrypted blob whose decrypted Prekey.id matches `id`.
    ///
    /// Does NOT remove the blob from the store. The caller removes it separately
    /// via `removePrekeyData(_:)` after successful decryption.
    ///
    /// Decrypt errors for individual entries are silently skipped — a failed
    /// decrypt means "not this entry," not "abort the search."
    ///
    /// - Parameters:
    ///   - id:        The `prekeyID` from `bundle.secrecy.prekeyID`.
    ///   - decryptor: Closure that decrypts a raw blob. May throw — errors are swallowed.
    /// - Returns: The matching encrypted blob, or `nil` if not found.
    func findPrekeyData(id: String, decryptor: (Data) throws -> Data?) -> Data? {
        guard let entries = self.contactPrekeys else { return nil }

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

    /// Remove a specific encrypted prekey blob from the store.
    ///
    /// Called by ContactManager after a successful decrypt to clean up the
    /// consumed prekey from local storage.
    ///
    /// - Parameter blob: The exact encrypted blob to remove (identity comparison).
    func removePrekeyData(_ blob: Data) {
        self.contactPrekeys?.removeAll { $0 == blob }
    }

    // MARK: - Stock

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
    /// Computes SHA-256(contactPublicKey || bundle.fingerprintNonce)
    /// and compares it against `bundle.senderFingerprint`.
    ///
    /// The caller (ContactManager) decrypts the stored key material and passes
    /// the raw public key here — no manager reference needed on the model.
    ///
    /// O(1) per contact. `Data ==` is constant-time — safe against timing side-channels.
    ///
    /// - Parameters:
    ///   - bundle:           The received ``OccultaBundle``.
    ///   - contactPublicKey: The contact's long-term public key in x963 format,
    ///                       already decrypted by the caller.
    /// - Returns: `true` if the fingerprint matches.
    func isLikelySender(of bundle: OccultaBundle, contactPublicKey: Data) -> Bool {
        let candidate = OccultaBundle.SecrecyContext.fingerprint(for: contactPublicKey, nonce: bundle.fingerprintNonce)
        
        return candidate == bundle.senderFingerprint
    }
}
