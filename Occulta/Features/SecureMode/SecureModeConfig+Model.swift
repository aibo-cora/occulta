//
//  AppLayerConfig+Model.swift
//  Occulta
//

import Foundation
import SwiftData

/// Routing depth — which contact layer the app is currently showing.
///
/// `.normal` (depth 0) — the real layer; all contacts visible.
/// `.duress` (depth 1) — the decoy layer; sensitive contacts filtered out.
enum RoutingDepth: Int, Codable {
    case normal = 0
    case duress = 1
}

@Model
final class AppLayerConfig {
    var sealedNormalVerifier: Data?
    var sealedDuressVerifier: Data?
    /// Encrypted Int — consecutive wrong-PIN entries before wipe. Default 3.
    var wipeThresholdEncrypted: Data?

    /// Encrypted `RoutingDepth`. Records which layer (real vs decoy) was active
    /// when config was last written, so `Manager.Security.init` can restore
    /// depth-filtering and `.duress` state after a process kill without
    /// re-authentication.
    ///
    /// Always non-nil after the first config write — a consistently present field
    /// prevents forensic tools from inferring the device's threat state from
    /// field presence or absence.
    ///
    /// Falls back to `.normal` on any decode failure — the safe default.
    var persistedDepth: Data?

    /// Encrypted Bool. `true` = PIN overlay shown on next foreground (normal operation).
    /// `false` = gate suppressed while all verifiers remain intact — the coercion path
    /// where the user called `disablePINFromCurrentDepth` so the app opens without
    /// demanding a PIN. Depth-filtering still applies when `false`.
    ///
    /// Always non-nil after the first config write.
    ///
    /// Falls back to `true` on any decode failure — always demand a PIN rather than
    /// silently opening the app.
    var pinEnabled: Data?

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

    // MARK: - Routing depth

    /// Decodes the persisted routing depth. Falls back to `.normal` on any decode failure.
    func readRoutingDepth() -> RoutingDepth {
        guard
            let data      = self.persistedDepth,
            let decrypted = data.decrypt(),
            let value     = try? JSONDecoder().decode(RoutingDepth.self, from: decrypted)
        else { return .normal }
        return value
    }

    func writeRoutingDepth(_ depth: RoutingDepth) throws {
        self.persistedDepth = try JSONEncoder().encode(depth).encrypt()
    }

    // MARK: - PIN enabled

    /// Decodes the persisted gate state. Falls back to `true` (PIN required) on any decode failure.
    func readPinEnabled() -> Bool {
        guard
            let data      = self.pinEnabled,
            let decrypted = data.decrypt(),
            let value     = try? JSONDecoder().decode(Bool.self, from: decrypted)
        else { return true }
        return value
    }

    func writePinEnabled(_ enabled: Bool) throws {
        self.pinEnabled = try JSONEncoder().encode(enabled).encrypt()
    }
}
