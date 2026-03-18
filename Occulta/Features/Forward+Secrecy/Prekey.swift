//
//  Prekey.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation

/// The public half of a prekey pair — what gets sent to contacts inside message bundles.
///
/// The private half lives in the Secure Enclave tagged `"prekey.<sequence>.<id>"`.
/// The `sequence` field groups all prekeys generated in the same batch together,
/// enabling sequence-based pruning of orphaned SE keys.
///
/// ## SE tag format
/// ```
/// "prekey.<sequence>.<uuid>"
///
/// e.g. "prekey.3.550e8400-e29b-41d4-a716-446655440000"
/// ```
///
/// ## Lifecycle
/// ```
/// Generated    →  private key in SE tagged "prekey.<seq>.<id>"
///                 public Prekey (with sequence) sent in outbound PrekeySyncBatch
/// Stored       →  recipient stores [Prekey] on sender's Contact.Profile
/// Consumed     →  recipient picks oldest Prekey, uses publicKey for ECDH,
///                 removes from local store
/// SE pruned    →  when a newer batch (seq+1) arrives, recipient deletes all
///                 SE private keys from the old sequence
/// ```
nonisolated
struct Prekey: Codable, Equatable {

    // MARK: - Fields

    /// Unique identifier for this prekey within its batch.
    ///
    /// Combined with `sequence` to form the SE tag: `"prekey.<sequence>.<id>"`.
    let id: String

    /// The batch generation this prekey belongs to.
    ///
    /// Monotonically increasing per device. Incremented each time a new batch
    /// is generated. Used to prune orphaned SE private keys when a newer batch
    /// supersedes an older one.
    let sequence: Int

    /// x963 uncompressed public key (04 || X || Y, 65 bytes).
    ///
    /// Safe to transmit unencrypted. Forward secrecy comes from deleting the
    /// corresponding private key after use — not from hiding the public key.
    let publicKey: Data

    // MARK: - SE tag

    /// The keychain application tag for this prekey's private key.
    ///
    /// Format: `"prekey.<sequence>.<id>"`
    var seTag: String {
        Prekey.seTag(for: id, sequence: sequence)
    }

    static func seTag(for id: String, sequence: Int) -> String {
        "prekey.\(sequence).\(id)"
    }

    /// Tag prefix for all prekeys in a given sequence.
    /// Used for batch pruning: `SecItemCopyMatching` by tag prefix.
    static func seTagPrefix(for sequence: Int) -> String {
        "prekey.\(sequence)."
    }
}
