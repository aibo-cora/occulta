//
//  Message.swift
//  Maverick
//
//  Created by Yura on 12/1/25.
//

import Foundation
import SwiftData

class Message: Identifiable, Codable {
    /// Hash of the sender's public key, to match contact when user taps on file or link to opens the app.
    var id: String
    /// Sender's public key hash.
    var origin: Data
    /// Indended recipients. Hash of their public key.
    var recipients: [Data]
    /// Encrypted payload.
    var content: Data?
    
    /// Create a message for transport.
    /// - Parameters:
    ///   - id: Identifier.
    ///   - origin: Sender's hash.
    ///   - recipients: Recipients' hashes.
    ///   - content: Encrypted payload.
    init(id: String, origin: Data, recipients: [Data], content: Data) {
        self.id = id
        self.origin = origin
        self.recipients = recipients
        self.content = content
    }
}
