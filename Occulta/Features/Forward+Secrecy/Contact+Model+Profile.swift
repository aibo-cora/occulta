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

    // MARK: - Prekey store (raw encrypted blobs)
    //
    // These methods operate on already-encrypted Data blobs.
    // ContactManager is responsible for encrypt/decrypt before and after calling these.

    /// Remove and return the oldest encrypted prekey blob from the store.
    ///
    /// Returns the raw encrypted `Data` — the caller decrypts it.
    /// Returns `nil` if the store is empty.
    func popOldestPrekeyData() -> Data? {
        guard
            var current = self.contactPrekeys,
            !current.isEmpty
        else {
            return nil
        }

        let oldest = current.removeFirst()
        self.contactPrekeys = current

        return oldest
    }

    /// Append a batch of already-encrypted prekey blobs to the store.
    ///
    /// The caller encrypts each `Prekey` before passing the blobs here.
    func appendPrekeyData(_ blobs: [Data]) {
        var current = self.contactPrekeys ?? []
        current.append(contentsOf: blobs)
        
        self.contactPrekeys = current
    }

    /// Number of prekeys currently stored for this contact.
    var storedPrekeyCount: Int {
        self.contactPrekeys?.count ?? 0
    }

    /// Whether this contact has any prekeys available for forward-secret encryption.
    var hasPrekeyAvailable: Bool {
        self.storedPrekeyCount > 0
    }

    // MARK: - Sender identification

    /// Check whether this contact is the sender of a given bundle.
    ///
    /// Computes SHA-256(contact.longTermPublicKey || bundle.secrecy.fingerprintNonce)
    /// and compares it against `bundle.secrecy.senderFingerprint`.
    ///
    /// O(1) per contact — the caller iterates contacts until a match is found (O(n) total).
    /// Identification happens before decryption — no trial ECDH operations required.
    ///
    /// - Parameters:
    ///   - bundle:     The received ``OccultaBundle``.
    ///   - cryptoOps:  Crypto manager for decrypting stored key material.
    /// - Returns: `true` if this contact's fingerprint matches the bundle's sender fingerprint.
    func isLikelySender(of bundle: OccultaBundle, using cryptoOps: Manager.Crypto) -> Bool {
        guard
            let keyRecord        = self.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
            let contactPublicKey = try? cryptoOps.decrypt(data: keyRecord.material)
        else {
            return false
        }

        let candidate = OccultaBundle.SecrecyContext.fingerprint(
            for: contactPublicKey,
            nonce: bundle.secrecy.fingerprintNonce
        )

        // Data == is constant-time in Swift — safe against timing side-channels.
        return candidate == bundle.secrecy.senderFingerprint
    }
}
