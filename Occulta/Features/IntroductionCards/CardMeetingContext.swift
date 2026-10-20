//
//  CardMeetingContext.swift
//  Occulta
//
//  What the key exchange needs from a contact's card field for the meeting check
//  (`Docs/Features/Introduction Cards/SPEC.md` §7), as plain values so `ExchangeManager` depends on neither
//  SwiftData nor `ContactManager`. `ContactManager.cardMeetingContext(for:)` builds it when the exchange starts.
//

import Foundation
import OccultaFormats

/// The meeting check's verdict, shown only after the ceremony's own confirmation succeeds.
nonisolated
enum CardMeetingVerdict: Equatable {
    /// No verdict is shown: the field shows none (`empty`, `issued`, `imported` before a first send), the
    /// exchange was classical-only, or there was no ceremony.
    case none
    /// The peer's proof verifies: W-12.
    case match
    /// Anything else where a verdict is shown: a filler, a bad signature, or no proof message: W-11.
    case mismatch
}

struct CardMeetingContext {

    /// Signs the proof payload (`CardMeeting.proofPayload`) with the card signing key, raw `r ‖ s`. Nil when the
    /// field holds no card signing key (`empty`): a filler is sent instead, so the message is the same length.
    var sign: ((Data) throws -> Data)?

    /// The key the peer's proof is checked against: the signing key inside `peerCard` (`imported` after a first
    /// send) or `peerSigningKey` (`conversation`). Nil where SPEC §7's table shows no verdict.
    var peerSigningKey: Data?

    static let none = CardMeetingContext(sign: nil, peerSigningKey: nil)

    /// The verdict for an exchange that produced `result`, where `ourIdentity` is the identity key we sent.
    /// `.none` without a hybrid result (no transcript) or where the table shows nothing.
    static func verdict(context: CardMeetingContext, result: ExchangeManager.HybridExchangeResult?, ourIdentity: Data?, peerProof: Data?) -> CardMeetingVerdict {
        guard let key = context.peerSigningKey, let result, let ourIdentity else { return .none }
        let transcript = CardMeeting.transcript(
            identityKeys: (ourIdentity, result.peerP256PublicKey),
            nonces: (result.ourNonce, result.peerNonce),
            mlkemCiphertexts: (result.ourCiphertext, result.peerCiphertext)
        )
        guard let peerProof,
              CardMeeting.verifyProof(peerProof, transcript: transcript, signerIdentityKey: result.peerP256PublicKey, signingKey: key)
        else { return .mismatch }
        return .match
    }
}
