//
//  AppLayerConfig+Model.swift
//  Occulta
//

import Foundation
import SwiftData

@Model
final class AppLayerConfig {
    var sealedNormalVerifier: Data?
    var sealedDuressVerifier: Data?
    /// Encrypted Int — consecutive duress entries before wipe. Default 3.
    var wipeThresholdEncrypted: Data?

    /// Encoded lock-gate state. Always non-nil after the first config write.
    ///
    /// Packs both the current routing depth and whether the app-lock PIN overlay is
    /// active into a single AES-GCM encrypted blob using a signed-Int encoding scheme:
    ///
    /// - **N ≥ 0** — gate is *active* at depth N. Normal operation: the PIN overlay
    ///   is shown on scene activation and `Manager.Security.appLockEnabled` is `true`.
    /// - **-(N+1)** — gate is *inactive* at depth N. The user disabled the overlay
    ///   via `disablePINFromCurrentDepth` (typically under coercion) without removing
    ///   any verifiers. The depth filter still applies — depth-1 contacts and vault
    ///   entries remain hidden — but the app opens without demanding a PIN.
    ///
    /// Keeping this field always non-nil (written as `writeLockGate(depth:0, gateActive:true)`
    /// during first config creation) prevents a forensic tool from inferring the device's
    /// threat state from the mere presence or absence of the field.
    var persistedDepth: Data?

    init() {}

    // MARK: - Wipe threshold

    func wipeThreshold() -> Int {
        guard
            let encrypted = self.wipeThresholdEncrypted,
            let decrypted = encrypted.decrypt(),
            let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return 3 }
        return value
    }

    func setWipeThreshold(_ threshold: Int) throws {
        let data = try JSONEncoder().encode(threshold)
        self.wipeThresholdEncrypted = try data.encrypt()
    }

    // MARK: - Lock gate

    /// Decodes the persisted lock-gate state into a depth and an active-flag.
    ///
    /// Falls back to `(depth: 0, gateActive: true)` — the secure neutral default —
    /// when the field is absent or decryption fails. An unreadable or tampered
    /// `persistedDepth` field therefore always errs on the side of showing the PIN prompt.
    ///
    /// - Returns: A tuple where `depth` is the routing depth (0 = real layer,
    ///   1 = duress layer) and `gateActive` indicates whether the PIN overlay is
    ///   shown on scene activation.
    func readLockGate() -> (depth: Int, gateActive: Bool) {
        guard
            let data      = self.persistedDepth,
            let decrypted = data.decrypt(),
            let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return (0, true) }
        return value >= 0 ? (value, true) : (-(value + 1), false)
    }

    /// Encodes and persists a new lock-gate state using signed-Int encoding:
    /// `gateActive ? depth : -(depth + 1)`.
    ///
    /// - Parameters:
    ///   - depth: The depth at which depth-filtering and the gate will apply (0 or 1).
    ///   - gateActive: `true` to show the PIN overlay on next scene activation;
    ///     `false` to suppress it while keeping all verifiers and depth-filtering intact.
    func writeLockGate(depth: Int, gateActive: Bool) throws {
        let encoded = gateActive ? depth : -(depth + 1)
        self.persistedDepth = try JSONEncoder().encode(encoded).encrypt()
    }

}
