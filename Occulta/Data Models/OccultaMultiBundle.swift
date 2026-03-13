//
//  MultiRecipientBundle.swift
//  Occulta
//
//  Created by Yura on 3/12/26.
//

import Foundation

/// A self-contained encrypted bundle addressed to one or more recipients.
///
/// Layout:
/// ```
/// OccultaMultiBundle {
///     version    : "v2"
///     ciphertext : Data          // message/file encrypted once with random session key K
///     capsules   : [Data]        // one per recipient — order randomised, no labels
/// }
/// ```
///
/// Each capsule is:
/// ```
/// AES-GCM.seal(K_bytes, using: HKDF(ECDH(ourKey, recipientPublicKey))).combined
/// ```
///
/// Decryption: trial-open every capsule with every candidate shared key.
/// A 128-bit GCM tag makes false positives astronomically unlikely (p ≈ 2⁻¹²⁸).
struct MultiRecipientBundle: Codable {

    // MARK: - Fields

    /// Protocol version. Increment if the layout changes.
    let version: Version

    /// The message or file encrypted once with the random session key K.
    /// Format: AES-GCM combined (nonce || ciphertext || tag).
    let ciphertext: Data

    /// One opaque capsule per recipient, in randomised order.
    /// Each capsule = AES-GCM.seal(K_bytes, using: sharedKey_recipient).combined
    /// No recipient identifiers — any holder of a valid private key may trial-decrypt.
    let capsules: [Data]

    // MARK: - Constants

    static let currentVersion: Version = .v2

    // MARK: - Serialisation

    /// Serialise the bundle to Data for sharing (AirDrop, email, etc.).
    func encode() throws -> Data {
        try JSONEncoder().encode(self)
    }

    /// Deserialise a bundle received from a contact.
    static func decode(from data: Data) throws -> MultiRecipientBundle {
        try JSONDecoder().decode(MultiRecipientBundle.self, from: data)
    }
    
    enum Version: String, Codable {
        case v1
        case v2
    }
}
