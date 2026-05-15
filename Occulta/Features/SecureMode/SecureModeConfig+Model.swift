//
//  SecureModeConfig+Model.swift
//  Occulta
//
//  Each verifier is a two-layer sealed box:
//    outer = AES-GCM(seKey, innerBox)
//    inner = AES-GCM(HKDF(PBKDF2(pin, salt), label), knownSentinel)
//
//  Verification requires the device SE key (outer) + correct PIN (inner).
//  An offline attacker who extracts the SwiftData file cannot brute-force PINs
//  without SE hardware access.
//

import Foundation
import SwiftData

@Model
final class SecureModeConfig {
    /// Two-layer sealed verifier for the normal PIN.
    var sealedNormalVerifier: Data
    /// Two-layer sealed verifier for the duress PIN. Nil in .pinOnly state.
    var sealedDuressVerifier: Data?
    /// 32-byte PBKDF2 salt. Not secret — stored plaintext.
    var salt: Data
    /// Number of consecutive duress PIN entries before full wipe.
    var wipeThreshold: Int
    /// True once configurePIN() has completed.
    var isPINEnabled: Bool
    /// True once activateSecureMode() has completed (key rotation done).
    var isSecureModeActivated: Bool
    /// Encrypted JSON-encoded [String] of contact identifiers marked as safe.
    /// Nil until the user classifies at least one contact.
    var safeContactIDsEncrypted: Data?

    init(sealedNormalVerifier: Data, salt: Data) {
        self.sealedNormalVerifier  = sealedNormalVerifier
        self.sealedDuressVerifier  = nil
        self.salt                  = salt
        self.wipeThreshold         = 3
        self.isPINEnabled          = true
        self.isSecureModeActivated = false
        self.safeContactIDsEncrypted = nil
    }

    // MARK: - Safe contact membership

    func isSafeContact(_ identifier: String) -> Bool {
        guard
            let encrypted = self.safeContactIDsEncrypted,
            let decrypted = encrypted.decrypt(),
            let ids       = try? JSONDecoder().decode([String].self, from: decrypted)
        else { return false }
        return ids.contains(identifier)
    }

    func updateSafeContacts(_ ids: Set<String>) throws {
        let data = try JSONEncoder().encode(Array(ids))
        self.safeContactIDsEncrypted = try data.encrypt()
    }
}
