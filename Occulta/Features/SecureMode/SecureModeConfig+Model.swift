//
//  SecureModeConfig+Model.swift
//  Occulta
//

import Foundation
import SwiftData

@Model
final class SecureModeConfig {
    var sealedNormalVerifier: Data?
    var sealedDuressVerifier: Data?
    /// Encrypted Int — consecutive duress entries before wipe. Default 3.
    var wipeThresholdEncrypted: Data?
    var safeContactIDsEncrypted: Data?

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
