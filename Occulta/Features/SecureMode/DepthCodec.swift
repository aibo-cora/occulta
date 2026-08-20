//
//  DepthCodec.swift
//  Occulta
//
//  Plaintext format for the encrypted duress-depth fields.
//

import Foundation

/// Single encode/decode point for the encrypted depth fields.
///
/// `Contact.Profile.visibleThroughDepth`, `.globalTrusteeDepth` and `.originDepth`
/// each store an `Int` sealed with AES-GCM. AES-GCM is length-preserving, so the
/// stored blob is always plaintext + 28 bytes — which leaves the *size* of the
/// plaintext readable with no key at all. Under the previous JSON format that was
/// Bug 85: `Int.max` spells as 19 bytes and an ordinary depth as 1, so blob length
/// alone partitioned safe contacts from hidden ones, straight out of the store file.
///
/// The format is therefore fixed-width: two bytes, always, for every value.
///
/// ## Wire format
///
/// ```
/// byte 0  0xFF          format tag
/// byte 1  0xFF          Int.max — always visible
///         0xFE          -1      — not a trustee
///         0x00…0xFD     a literal depth
/// ```
///
/// **Why a tag byte rather than a bare payload.** The read path has to accept the
/// legacy JSON format for as long as un-migrated rows exist, and a legacy plaintext
/// can also be one byte (`"0"`–`"9"`), so length alone cannot separate the two. The
/// tag can: legacy plaintexts are JSON integers, hence ASCII, hence they always begin
/// with `-` (0x2D) or a digit (0x30–0x39). `0xFF` cannot begin one. That keeps the
/// depth range independent of the encoding — an earlier sketch capped depths at 0x1F
/// purely so the byte could not collide with an ASCII digit, which tied a domain limit
/// to a coincidence of how JSON spells numbers.
///
/// **Encryption stays at the call sites.** This type maps `Int` ↔ plaintext `Data` and
/// nothing else — the sites differ in which key they seal under (canonical vs. staged)
/// and that distinction is theirs to keep.
enum DepthCodec {

    private static let tag:           UInt8 = 0xFF
    private static let alwaysVisible: UInt8 = 0xFF   // Int.max
    private static let notATrustee:   UInt8 = 0xFE   // -1

    /// Sealed length of every value written through this codec — tag + payload, plus
    /// AES-GCM's nonce(12) and tag(16).
    ///
    /// Derived, never a literal. A filler size sitting beside a format as a hardcoded number
    /// is exactly how `AppLayerConfig.fillerSize = 30` drifted from encodings producing 29
    /// and 37–38 (Bug 86). Bug 88's scrub of soft-deleted rows is a filler size for these
    /// fields, so it takes it from here rather than from a number observed in a log.
    static let sealedSize = 1 + 1 + 28

    /// Largest depth the payload byte carries literally. Far above
    /// `AppLayerConfig.maxVerifierCount` (32), which is the real structural limit on
    /// nesting — this is only the encoding's ceiling, deliberately not the domain's.
    static let maxEncodableDepth = 0xFD

    /// Encodes a depth value to plaintext, ready to seal. Always two bytes.
    ///
    /// **Total by design — it cannot throw and cannot trap.** `deactivateSecureMode`
    /// calls this between the staged-key creation ("point of no return begins") and
    /// `commitStagedLocalDBKey()`. A throw there is caught and rolled back, but a trap
    /// — which is what an unchecked `UInt8(_:)` conversion would produce — terminates
    /// the process with no catch running. Depth is not structurally bounded either:
    /// `applyVerifyState` increments `currentDepth` with no ceiling, and the 32-wide
    /// arrays merely no-op past their end. So out-of-range values must clamp, never trap.
    ///
    /// Clamping is fail-closed: a ceiling above `maxEncodableDepth` becomes
    /// `maxEncodableDepth`, hiding the contact deeper rather than exposing it. Values
    /// that large are unreachable in practice; the clamp exists so the function is total.
    static func encode(_ value: Int) -> Data {
        switch value {
        case Int.max:
            return Data([Self.tag, Self.alwaysVisible])
        case ..<0:
            // Only -1 is ever written (globalTrusteeDepth's "not a trustee").
            return Data([Self.tag, Self.notATrustee])
        case 0...Self.maxEncodableDepth:
            return Data([Self.tag, UInt8(value)])
        default:
            return Data([Self.tag, UInt8(Self.maxEncodableDepth)])
        }
    }

    /// Decodes a decrypted depth plaintext, or nil if it will not decode.
    ///
    /// Accepts both the fixed-width format and the legacy JSON one, for as long as
    /// un-migrated rows exist. See the type doc for why the two cannot be confused.
    ///
    /// Nil rather than a default: each field fails closed to a different value
    /// (`Int.max` for a visibility ceiling, `-1` for a trustee stamp, `0` for an origin
    /// stamp, `false` for a visibility check), and those choices are load-bearing
    /// security decisions belonging to the call sites, not to the format. Bug 87 is what
    /// happens when one of them resolves an unknown in the permissive direction.
    static func decode(_ plain: Data) -> Int? {
        guard plain.count == 2, plain[0] == Self.tag else {
            return try? JSONDecoder().decode(Int.self, from: plain)   // legacy row
        }
        switch plain[1] {
        case Self.alwaysVisible: return Int.max
        case Self.notATrustee:   return -1
        default:                 return Int(plain[1])
        }
    }
}
