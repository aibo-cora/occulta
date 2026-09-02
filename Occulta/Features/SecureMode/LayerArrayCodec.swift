//
//  LayerArrayCodec.swift
//  Occulta
//
//  Plaintext format for AppLayerConfig's blob-metadata arrays.
//

import Foundation

/// Fixed-width plaintext for `AppLayerConfig.sealedBlobSlots` and `.layerSequenceNumbers`.
///
/// Both arrays are padded to 32 entries so that, in the field's own words, "array length is
/// forensically constant". Array *length* was made constant; element length was not — and
/// AES-GCM does not pad, so element length is readable from the store file with no key.
/// Since both arrays are indexed **by depth**, an element whose length differs from the
/// filler names an occupied depth. That is Bug 86.
///
/// ## Wire format
///
/// ```
/// byte 0     0xFF                format tag
/// bytes 1…4  UInt32 big-endian   payload
/// ```
///
/// Five plaintext bytes, hence `sealedSize` = 33 for every value either array can hold.
///
/// **Why one width for both arrays** rather than one each. A slot index needs one byte and a
/// sequence number four, so per-array widths would be tighter — but this bug *is* a drift
/// between a format and a filler constant, and two widths means two constants and two
/// chances to drift again. The cost is three wasted bytes per slot entry, 96 bytes across
/// the array.
///
/// **Why a tag byte.** The read path must accept the legacy JSON format for as long as
/// un-migrated rows exist, and a legacy sequence number is anywhere from 1 to 10 bytes, so
/// length alone cannot separate the two. Legacy plaintexts are JSON integers — ASCII — so
/// they begin with `-` (0x2D) or a digit (0x30–0x39); `0xFF` cannot begin one.
///
/// **Why this is not `DepthCodec`.** A depth fits a one-byte payload and a sequence number
/// does not. Widening `DepthCodec` would mean re-migrating seven already-converted fields,
/// and cross-field uniformity between a column and an array element buys nothing — nobody
/// compares them.
///
/// `pinEnabledPerDepth` is deliberately **not** a client of this type: it is already uniform
/// because its filler is a real `encode(UInt8(1))` rather than a hardcoded size, it sits
/// under a different key, and "no entry" is not a state it needs to represent. See Bug 86.
enum LayerArrayCodec {

    private static let tag: UInt8 = 0xFF

    /// Payload width, set by the widest value either array holds: `randomSequenceNumber()`
    /// returns `Int(UInt32)`, the full 32-bit range.
    static let payloadWidth = 4

    /// Sealed length of every element written through this codec — tag + payload, plus
    /// AES-GCM's nonce(12) and tag(16).
    ///
    /// **`AppLayerConfig.fillerSize` must be this value and not a literal.** A hardcoded 30
    /// beside a format that produced 29 and 37–38 is the entire bug; deriving it is what
    /// makes the drift unrepeatable.
    static let sealedSize = 1 + payloadWidth + 28

    /// Encodes a slot index or sequence number to plaintext. Always `1 + payloadWidth` bytes.
    ///
    /// Total by design — it cannot throw and cannot trap. Both call sites take an `Int`, and
    /// out-of-range input clamps rather than trapping on conversion, for the same reason
    /// `DepthCodec.encode` does: these run inside rotation, where a trap terminates the
    /// process with no catch running.
    static func encode(_ value: Int) -> Data {
        var out = Data([Self.tag])
        withUnsafeBytes(of: UInt32(clamping: value).bigEndian) { out.append(contentsOf: $0) }
        return out
    }

    /// Decodes a decrypted element, or nil if it will not decode.
    ///
    /// Accepts both the fixed-width format and the legacy JSON one. Nil rather than a
    /// default: for these arrays a value that will not decode means "no layer at this
    /// depth", and that reading belongs to the call sites, which already treat decryption
    /// failure as absence.
    static func decode(_ plain: Data) -> Int? {
        guard plain.count == 1 + Self.payloadWidth, plain.first == Self.tag else {
            guard let value = try? JSONDecoder().decode(Int.self, from: plain),
                  value >= 0, value <= Int(UInt32.max)
            else { return nil }
            return value                                        // legacy row
        }
        return Int(plain.dropFirst().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
    }
}
