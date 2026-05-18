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

}
