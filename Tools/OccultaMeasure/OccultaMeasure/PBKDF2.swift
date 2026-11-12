//
//  PBKDF2.swift
//  OccultaMeasure
//
//  PBKDF2-HMAC-SHA256 through CommonCrypto, as the passphrase design calls for
//  (`Docs/v2.0.0/PASSPHRASE_ROLLOUT.md` §1.5, decided 2026-11-02).
//

import CommonCrypto
import Foundation

enum PBKDF2 {
    static let wordCount = 7
    static let wordlistSize: UInt16 = 2_048
    static let saltSize = 32
    static let outputSize = 32

    /// The phrase's word indices, two bytes each, big endian. The real encoding is not built yet; any password
    /// under HMAC's 64-byte block costs the same.
    static func password(wordIndices: [UInt16]) -> [UInt8] {
        wordIndices.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xff)] }
    }

    static func randomPassword() -> [UInt8] {
        self.password(wordIndices: (0..<Self.wordCount).map { _ in UInt16.random(in: 0..<Self.wordlistSize) })
    }

    static func derive(password: [UInt8], salt: [UInt8], iterations: UInt32) throws -> [UInt8] {
        let signed = password.map { Int8(bitPattern: $0) }
        var output = [UInt8](repeating: 0, count: Self.outputSize)

        let status = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2), signed, signed.count, salt, salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations, &output, output.count
        )
        guard status == kCCSuccess else {
            throw MeasureError("CCKeyDerivationPBKDF failed with \(status)")
        }
        return output
    }

    /// What CommonCrypto's own calibration says for `milliseconds`, to compare with the measured count.
    static func systemCalibration(milliseconds: UInt32) -> UInt32 {
        CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2), Self.wordCount * 2, Self.saltSize,
                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), Self.outputSize, milliseconds)
    }
}
