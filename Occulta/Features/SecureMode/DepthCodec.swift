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
/// plaintext readable with no key at all. Bug 85: JSON spells `Int.max` as 19 bytes
/// and an ordinary depth as 1, so blob length alone partitions safe contacts from
/// hidden ones, straight out of the store file.
///
/// The fix is a fixed-width plaintext, and its precondition is that the format lives
/// in exactly one place. That place is this type. It currently emits the same JSON as
/// the inline calls it replaced, byte for byte, so routing the call sites through it
/// changes nothing on disk.
///
/// Encryption stays at the call sites. This type maps `Int` ↔ plaintext `Data` and
/// nothing else — the sites differ in which key they seal under (canonical vs. staged)
/// and that distinction is theirs to keep.
enum DepthCodec {

    /// Encodes a depth value to plaintext, ready to seal.
    ///
    /// Still JSON, byte-for-byte identical to the `JSONEncoder().encode(_:)` calls this
    /// replaced. The fixed-width format replaces this body once every site is routed here.
    static func encode(_ value: Int) throws -> Data {
        try JSONEncoder().encode(value)
    }

    /// Decodes a decrypted depth plaintext, or nil if it will not decode.
    ///
    /// Nil rather than a default: each field fails closed to a different value
    /// (`Int.max` for a visibility ceiling, `-1` for a trustee stamp, `0` for an origin
    /// stamp, `false` for a visibility check), and those choices are load-bearing
    /// security decisions belonging to the call sites, not to the format.
    static func decode(_ plain: Data) -> Int? {
        try? JSONDecoder().decode(Int.self, from: plain)
    }
}
