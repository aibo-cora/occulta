//
//  Database.swift
//  Maverick
//
//  Created by Yura on 12/9/25.
//

import Foundation

struct Database: Codable {
    /// Encrypted database of our contacts.
    var contacts: Data?
    /// Sender's public key.
    var sender: String?
    /// Recipient's public key.
    var recipient: String?
}
