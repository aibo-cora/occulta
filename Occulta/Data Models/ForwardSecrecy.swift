//
//  ForwardSecrecy.swift
//  Occulta
//
//  Created by Yura on 3/25/26.
//

import Foundation

nonisolated
struct ForwardSecrecy: Codable {
    /// Plain text prekey public keys received from this contact.
    var contactPrekeys: [Data]? = []
    /// Sequence number of the last prekey batch received FROM this contact.
    /// Replace incoming batch only when sequence > this value.
    var contactPrekeySequence: Int? = nil
    /// Our own public prekeys we generated and sent to this contact.
    /// When they encrypt to us using one of these prekeys, we search here by
    /// Prekey.id to reconstruct the SE tag and find our private key.
    /// Append-only; entries are removed individually as they are consumed.
    var ownPrekeys: [Data]? = []
    /// Sequence number of the last prekey batch generated FOR this contact.
    /// Read and incremented by PrekeyManager.generateBatch(contactID:currentSequence:).
    /// Caller writes the returned nextSequence back here after each encrypt call.
    var outboundPrekeySequence: Int? = nil
    /// The outbound prekey batch Alice is trying to deliver to Bob.
    /// Sent with every message until Alice decrypts a FS bundle from Bob
    /// that used one of her prekeys — proof of receipt.
    var pendingOutboundBatch: Data? = nil
}
