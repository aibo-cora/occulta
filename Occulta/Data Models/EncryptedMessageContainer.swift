//
//  MultiRecipientBundle.swift
//  Occulta
//
//  Created by Yura on 3/12/26.
//

import Foundation

/// Container holding an encrypted message and the ephemeral public key to derive a decryption key.
struct EncryptedMessageContainer: Codable {

    // MARK: - Fields

    /// Protocol version. Increment if the layout changes.
    let version: Version

    /// The message or file encrypted once with the random session key K.
    /// Format: AES-GCM combined (nonce || ciphertext || tag).
    var ciphertext: Data?
    /// Short lived ephemeral public key for shared key computation.
    var ephemeral: Data?
    /// Message owner ID, encrypted.
    var encryptedOwnerID: Data?

    // MARK: - Constants

    static let currentVersion: Version = .v2

    // MARK: - Serialisation

    /// Serialise the bundle to Data for sharing (AirDrop, email, etc.).
    func encode() throws -> Data {
        try JSONEncoder().encode(self)
    }

    /// Deserialise a bundle received from a contact.
    static func decode(from data: Data) throws -> EncryptedMessageContainer {
        try JSONDecoder().decode(EncryptedMessageContainer.self, from: data)
    }
    
    enum Version: String, Codable {
        case v1
        /// Encrypted file contains an ephemeral key to derive the decryption key.
        case v2
    }
}
