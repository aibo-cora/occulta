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

    init(sealedNormalVerifier: Data, sealedDuressVerifier: Data, salt: Data, wipeThreshold: Int) {
        self.sealedNormalVerifier = sealedNormalVerifier
        self.sealedDuressVerifier = sealedDuressVerifier
        self.salt                 = salt
        self.wipeThreshold        = wipeThreshold
    }
}
