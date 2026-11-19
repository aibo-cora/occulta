//
//  MLKEMKeyCheck.swift
//  OccultaCore
//
//  CryptoKit's `MLKEM1024.PublicKey(rawRepresentation:)` checks only the length (observed on iOS 26.2): a
//  random or all-0xFF 1,568-byte key "parses" and `encapsulate()` then fails. FIPS 203 §7.2 defines a real
//  check, the modulus check, which this implements so a key is refused where it arrives and not at first use.
//

import Foundation

/// The FIPS 203 modulus check for an ML-KEM-1024 encapsulation key.
///
/// A host app runs it on a peer's ML-KEM-1024 encapsulation key where the key arrives (a scan, a
/// received message, an import) before storing it or encapsulating to it, so a malformed key is refused
/// there rather than failing later at `encapsulate()`.
public enum MLKEMKeyCheck {

    private static let keyByteCount          = 1_568
    /// ByteEncode12(t̂): 4 polynomials of 256 coefficients, 12 bits each = 4 × 384 bytes. ρ (32 bytes) follows.
    private static let encodedVectorByteCount = 1_536
    private static let modulus: UInt16        = 3_329

    /// True only if `key` is 1,568 bytes and every one of the 1,024 coefficients of its encoded vector is
    /// below q = 3329. Every 3 bytes b0, b1, b2 hold c0 = b0 | (b1 & 0x0F) << 8 and c1 = b1 >> 4 | b2 << 4.
    /// Pure: no allocation beyond a byte copy, no traps on any input.
    public static func isValidEncapsulationKey1024(_ key: Data) -> Bool {
        guard key.count == self.keyByteCount else { return false }

        let bytes = [UInt8](key)
        var index = 0
        while index < self.encodedVectorByteCount {
            let b0 = UInt16(bytes[index]), b1 = UInt16(bytes[index + 1]), b2 = UInt16(bytes[index + 2])
            let c0 = b0 | ((b1 & 0x0F) << 8)
            let c1 = (b1 >> 4) | (b2 << 4)
            guard c0 < self.modulus, c1 < self.modulus else { return false }
            index += 3
        }
        return true
    }
}
