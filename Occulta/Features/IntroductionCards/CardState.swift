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
    /// - `peerAgreementKey`, `peerSigningKey`: the peer's public keys.
    /// - `mlkemKey`: Carol's blob, until she holds `ss2`.
    /// - `quantum`: full material once held.
    /// - `bootstrapOpen`: still sending bootstrap (§4.2).
    /// - `peerIntroduction`: Bob: Carol's introduction, to check duplicates.
    case conversation(
        agreementKey: Data, signingKey: Data, peerAgreementKey: Data, peerSigningKey: Data,
        mlkemKey: Data?, quantum: QuantumKeyMaterial?, bootstrapOpen: Bool, peerIntroduction: Data?
    )
}
