//
//  Message.swift
//  Maverick
//
//  Created by Yura on 12/1/25.
//

import Foundation
import SwiftData

class Message: Identifiable, Codable {
    var id = UUID()
    /// Hash of the sender's public key, to match contact when user taps on file or link to opens the app.
    var origin: Data?
    /// Indended recipients. Hash of their public key.
    ///
    /// I am sending this message to you, but you can only decrypt it if you have all the recipients added.
    var recipients: [Data]?
    /// Encrypted payload.
    var content: Data
    
    /// Create a message for transport.
    /// - Parameters:
    ///   - id: Identifier.
    ///   - origin: Sender's hash.
    ///   - recipients: Recipients' hashes.
    ///   - content: Encrypted payload.
    init(origin: Data?, recipients: [Data]?, content: Data) {
        self.origin = origin
        self.recipients = recipients
        self.content = content
    }
}

struct File: Identifiable, Codable {
    var id = UUID()
    
    let content: Data?
    let format: Format?
    
    var date: String?
    
    struct Metadata: Codable {
        var name: String?
        var `extension`: String?
    }

    enum Format: Codable {
        case contacts, text, document(Metadata), link
    }
}
