//
//  Prekey.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation

/// The public half of a prekey pair — what gets sent to contacts inside message bundles.
///
/// The private half lives in the Secure Enclave tagged `"prekey.<id>"` and is managed
/// exclusively by ``Prekey.Manager``. This struct is a value type and is never
/// persisted directly — it is JSON-encoded and AES-GCM encrypted before storage in
/// `Contact.Profile.contactPrekeys`.
///
/// ## Lifecycle
/// ```
/// Generated    →  private key in SE, public Prekey sent in outbound bundle
/// Stored       →  recipient stores [Prekey] on the sender's Contact.Profile
/// Consumed     →  recipient picks oldest Prekey, uses publicKey for ECDH,
///                 removes from local store
/// Deleted      →  sender's private key deleted from SE immediately after
///                 successful decryption by the other side
/// ```
nonisolated
struct Prekey: Codable, Equatable {

    // MARK: - Fields

    /// Unique identifier for this prekey.
    ///
    /// Also serves as the Secure Enclave keychain tag suffix: `"prekey.<id>"`.
    /// Included in outbound bundles as `OccultaBundle.prekeyID` so the recipient
    /// can tell the sender which SE key to delete after successful decryption.
    let id: String

    /// x963 uncompressed public key (04 || X || Y, 65 bytes).
    ///
    /// Safe to transmit unencrypted. Knowledge of the public key alone does not
    /// help an attacker — forward secrecy comes from deleting the private half.
    let publicKey: Data

    // MARK: - Init

    /// Create a new prekey with a random UUID identifier.
    init(publicKey: Data) {
        self.id = UUID().uuidString
        self.publicKey = publicKey
    }

    // MARK: - Secure Enclave tag

    /// The keychain application tag used to store and retrieve the private key.
    var seTag: String { Prekey.seTag(for: self.id) }

    static func seTag(for id: String) -> String {
        "prekey.\(id)"
    }
}
