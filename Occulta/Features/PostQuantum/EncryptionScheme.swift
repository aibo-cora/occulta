//
//  EncryptionScheme.swift
//  Occulta
//
//  Tracks the key derivation path used to encrypt a Contact.Profile's fields.
//  Stored as a raw Int on Contact.Profile for SwiftData compatibility.
//

import Foundation

enum EncryptionScheme: Int, Codable {
    /// Original: ECDH(identity_SE_key, G) → HKDF. No AAD.
    case v1_identityDerived = 1
    /// Hybrid PQ: HKDF(ECDH(localDB_SE_key, G) || random_keychain) + AAD.
    case v2_hybridPQ = 2

    /// Authenticated additional data for AES-GCM seal/open.
    ///
    /// Security invariant: including the scheme version in AAD prevents a
    /// downgrade attack where an attacker replaces v2 ciphertext with v1
    /// ciphertext (which had no AAD). GCM will reject the mismatch.
    var aad: Data {
        var version = UInt8(self.rawValue)
        
        return Data(bytes: &version, count: 1)
    }
}
