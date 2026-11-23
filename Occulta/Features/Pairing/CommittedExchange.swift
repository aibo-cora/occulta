//
//  CommittedExchange.swift
//  Occulta
//
//  What an exchange's words and routing key are derived over once both phones have committed to their nonces and
//  revealed them (Bug 198): both nonces and the transcript of every message before the reveal. One value, made once when the
//  peer's reveal has opened its commitment, and carried by everything that derives from it, so that no two derivations can
//  hold different nonces.
//

import Foundation

nonisolated
struct CommittedExchange: Equatable {
    let ourNonce: Data
    let peerNonce: Data
    /// `ExchangeCommitment.transcript` of the messages before the reveal.
    let transcript: Data
}
