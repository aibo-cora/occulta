//
//  ForwardSecrecy.swift
//  Occulta
//
//  Created by Yura on 3/25/26.
//

import Foundation

nonisolated
/// Locally encrypted metadata carrying our contact's prekeys.
struct ForwardSecrecy: Codable {
    // MARK: From Contact
    
    /// Plain text prekey public keys received from this contact.
    var encodedPrekeys: [Data]? = []
    /// Date when `encodedPrekeys` were generated at.
    /// When we get a new batch, we need to compare the 2 to make sure we don't append duplicates or old prekeys that have been consumed already.
    var latestPrekeysGeneratedAt: Date?  = nil
    
    // MARK: For Contact
    
    /// The outbound prekey batch Alice is trying to deliver to Bob.
    /// Sent with every message until Alice decrypts a FS bundle from Bob
    /// that used one of her prekeys — proof of receipt.
    var pendingOutboundBatch: Data? = nil
}
