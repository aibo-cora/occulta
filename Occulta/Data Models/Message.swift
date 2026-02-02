//
//  Message.swift
//  Occulta
//
//  Created by Yura on 12/1/25.
//

import Foundation
import SwiftData

extension Contact {
    @Model
    class Message: Identifiable {
        var id: String = UUID().uuidString
        /// Encrypted ID of the owner of this message.
        var origin: String?
        /// Indended recipients. Hash of their public key.
        ///
        /// I am sending this message to you, but you can only decrypt it if you have all the recipients added.
        var recipients: [Data]?
        /// Encrypted payload.
        var content: Data?
        
        /// Create a message for transport.
        /// - Parameters:
        ///   - id: Identifier.
        ///   - origin: Sender's hash.
        ///   - recipients: Recipients' hashes.
        ///   - content: Encrypted payload.
        init(origin: String?, recipients: [Data]?, content: Data) {
            self.origin = origin
            self.recipients = recipients
            self.content = content
        }
    }
}
