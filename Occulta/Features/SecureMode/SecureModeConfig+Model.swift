//
//  SecureModeConfig+Model.swift
//  Occulta
//

import Foundation
import SwiftData

/// Persisted Secure Mode configuration.
///
/// Each verifier is a two-layer sealed box:
///   outer = AES-GCM(seKey, innerBox)
///   inner = AES-GCM(HKDF(PBKDF2(pin, salt), label), knownSentinel)
///
/// Verification requires the device SE key (outer) + correct PIN (inner).
/// An offline attacker who extracts the SwiftData file cannot brute-force PINs
/// without SE hardware access.
@Model
final class SecureModeConfig {
    /// Two-layer sealed verifier for the normal PIN.
    var sealedNormalVerifier: Data
    /// Two-layer sealed verifier for the duress PIN.
    var sealedDuressVerifier: Data
    /// 32-byte PBKDF2 salt. Not secret — stored plaintext.
    var salt: Data
    /// Number of consecutive duress PIN entries before full wipe.
    var wipeThreshold: Int
    /// Whether the activation sequence has been completed (sensitive data removed from SwiftData).
    var isActivated: Bool = false
    /// Encrypted JSON-encoded [String] of contact identifiers marked as safe.
    /// Nil until the user classifies at least one contact.
    var safeContactIDsEncrypted: Data? = nil

    init(sealedNormalVerifier: Data, sealedDuressVerifier: Data, salt: Data, wipeThreshold: Int) {
        self.sealedNormalVerifier = sealedNormalVerifier
        self.sealedDuressVerifier = sealedDuressVerifier
        self.salt                 = salt
        self.wipeThreshold        = wipeThreshold
    }

    // MARK: - Safe contact membership

    /// Decrypts the safe-ID blob and checks membership. Plaintext lives only for the
    /// duration of this call — nothing is retained by the caller.
    func isSafeContact(_ identifier: String) -> Bool {
        guard
            let encrypted = self.safeContactIDsEncrypted,
            let decrypted = encrypted.decrypt(),
            let ids       = try? JSONDecoder().decode([String].self, from: decrypted)
        else { return false }
        return ids.contains(identifier)
    }

    /// Encodes and encrypts a new set of safe contact identifiers, replacing the existing blob.
    func updateSafeContacts(_ ids: Set<String>) throws {
        let data = try JSONEncoder().encode(Array(ids))
        self.safeContactIDsEncrypted = try data.encrypt()
    }
}
