//
//  CardState.swift
//  Occulta
//

import Foundation

/// What a contact's card field holds (`Docs/Features/Introduction Cards/SPEC.md` §5). Stored sealed,
/// through `CardStateCodec`; the tier is computed from it and never stored.
///
/// The `Data` the cases call blobs are `dataRepresentation` of Secure Enclave keys. They exist nowhere
/// else, so overwriting the field with `.empty` deletes the keys.
nonisolated
enum CardState: Codable, Equatable {

    /// No card: a contact that never had one, or one that was cancelled, cleared or discarded.
    case empty

    /// Bob: a card out and unused.
    /// - `card`: the 1,770 bytes, for "Share card…" again.
    /// - `agreementKey`, `signingKey`, `mlkemKey`: his Enclave blobs.
    case issued(card: Data, agreementKey: Data, signingKey: Data, mlkemKey: Data, expiresAt: Date)

    /// Carol: until she opens Bob's first message.
    /// - `peerCard`: Bob's 1,770 bytes, which hold his card keys and ML-KEM key and give the digest her
    ///   introduction signs.
    /// - `agreementKey`, `signingKey`, `mlkemKey`: her Enclave blobs.
    /// - `ss1`, `ct1`: her one encapsulation to Bob's ML-KEM key.
    /// - `sentFirstMessage`: set on her first send; decides the sweep (§6.4).
    case imported(
        peerCard: Data, agreementKey: Data, signingKey: Data, mlkemKey: Data,
        ss1: Data, ct1: Data, expiresAt: Date, sentFirstMessage: Bool
    )

    /// Both sides, until the meeting or a discard.
    /// - `agreementKey`, `signingKey`: own Enclave blobs.
    /// - `peerAgreementKey`, `peerSigningKey`: the peer's public keys; Bob's come from Carol's introduction, which
    ///   a later bootstrap message must repeat.
    /// - `quantum`: the full material, held from the start (Bob at redemption, Carol when she opens Bob's first
    ///   message), so Carol's ML-KEM blob is gone by then.
    /// - `bootstrapOpen`: still sending bootstrap (§4.2).
    /// - `isIssuer`: Bob. Decides which bootstrap slots this side opens and whether it checks introductions.
    case conversation(
        agreementKey: Data, signingKey: Data, peerAgreementKey: Data, peerSigningKey: Data,
        quantum: QuantumKeyMaterial, bootstrapOpen: Bool, isIssuer: Bool
    )

    /// Carol waiting on or holding a card conversation, or Bob in one: the contacts the §8 hard blocks apply to
    /// (vault trustee, shard content, payment cards, identity challenge, Presence Verification and groups refuse
    /// them), and the ones the card section replaces "No key yet" for.
    var isCardContact: Bool {
        switch self {
        case .imported, .conversation: true
        case .empty, .issued:          false
        }
    }
}
