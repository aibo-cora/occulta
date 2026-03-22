//
//  Prekey.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation

/// The public half of a prekey pair — what gets sent to a contact inside message bundles.
///
/// Each `Prekey` is generated exclusively for one contact. The `contactID` field
/// is embedded in the SE tag, so Alice's prekey pools for Bob and Jake are
/// completely isolated — no cross-contact consumption is possible.
///
/// ## SE tag format
/// ```
/// "prekey.<contactID>.<sequence>.<uuid>"
///
/// e.g. "prekey.C3A1B2-...<contactID>....3.550e8400-...<uuid>"
/// ```
///
/// ## Lifecycle
/// ```
/// Generated    →  private key in SE tagged "prekey.<contactID>.<seq>.<id>"
///                 public Prekey sent in outbound PrekeySyncBatch to that contact only
/// Stored       →  recipient stores [Prekey] on sender's Contact.Profile
/// Consumed     →  recipient picks oldest Prekey, uses publicKey for ECDH,
///                 removes from local store
/// Deleted      →  sender's private key deleted from SE on successful decrypt
/// Pruned       →  when a newer sequence arrives, SE keys from old sequences
///                 for this contactID are deleted
/// ```
nonisolated
struct Prekey: Codable, Equatable {

    // MARK: - Fields

    /// Unique identifier for this prekey within its batch.
    let id: String

    /// The contact this prekey was generated for.
    ///
    /// Scopes the SE tag to a specific contact's pool. A prekey generated
    /// for Bob cannot be accidentally consumed when decrypting for Jake.
    let contactID: String

    /// The batch generation this prekey belongs to.
    ///
    /// Monotonically increasing per contact. Each new batch for the same
    /// contact increments this counter independently of other contacts.
    let sequence: Int

    /// x963 uncompressed public key (04 || X || Y, 65 bytes).
    ///
    /// Safe to transmit unencrypted. Forward secrecy comes from deleting
    /// the private half — not from hiding the public key.
    let publicKey: Data

    // MARK: - SE tag

    /// The keychain application tag for this prekey's private key.
    ///
    /// Format: `"prekey.<contactID>.<sequence>.<id>"`
    var seTag: String {
        Prekey.seTag(for: id, contactID: contactID, sequence: sequence)
    }

    static func seTag(for id: String, contactID: String, sequence: Int) -> String {
        "prekey.\(contactID).\(sequence).\(id)"
    }

    /// Tag prefix for all prekeys for a given contact and sequence.
    /// Used for sequence-based pruning: query SE by this prefix, delete all matches.
    static func seTagPrefix(contactID: String, sequence: Int) -> String {
        "prekey.\(contactID).\(sequence)."
    }

    /// Tag prefix for ALL prekeys for a given contact, regardless of sequence.
    /// Used when a contact is deleted — clean up the entire pool.
    static func seTagPrefix(contactID: String) -> String {
        "prekey.\(contactID)."
    }
}
