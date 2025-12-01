//
//  Message.swift
//  Maverick
//
//  Created by Yura on 12/1/25.
//

import Foundation
import SwiftData

@Model
class Message: Identifiable {
    /// Hash of the sender's public key, to match contact when user taps on file or link to opens the app.
    var id: String
    /// Indended recipients.
    var recipients: [String]
    /// Payload.
    var content: Data
    
    init(id: String, recipients: [String], content: Data) {
        self.id = id
        self.recipients = recipients
        self.content = content
    }
}
