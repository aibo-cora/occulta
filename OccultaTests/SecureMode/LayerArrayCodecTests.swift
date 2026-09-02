//
//  LayerArrayCodecTests.swift
//  OccultaTests
//
//  Phase 1 for Bug 86 — the codec, before it is wired to anything.
//
//  Needs no Secure Enclave: the property under test is the plaintext format, and the one
//  test that seals uses a locally generated SymmetricKey.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

@Suite("LayerArrayCodec — Bug 86 plaintext format")
struct LayerArrayCodecTests {

    /// Both arrays' domains, at their boundaries. `randomSlot()` returns 0–31 and
    /// `randomSequenceNumber()` returns `Int(UInt32)`, so the widest value is `UInt32.max`.
    private static let allWrittenValues: [Int] = [
        0, 1, 9, 10, 31,               // slot indices, both JSON digit-widths
        99, 1_000, 999_999_999,        // sequence numbers below the 10-digit mass
        3_000_000_000,                 // 76.7% of the distribution is 10 digits
        Int(UInt32.max),               // the boundary
    ]

    @Test("Plaintext length is identical for every value written")
    func plaintextLengthIsUniform() {
        let lengths = Set(Self.allWrittenValues.map { LayerArrayCodec.encode($0).count })
        #expect(lengths.count == 1, """
            LayerArrayCodec.encode produced \(lengths.sorted()) distinct lengths. A slot index \
            must be indistinguishable from a sequence number, and both from filler — the array \
            is indexed by depth, so any element that differs names an occupied depth.
            """)
    }

    @Test("Every value round-trips unchanged, including the 32-bit boundary")
    func everyValueRoundTrips() {
        for value in Self.allWrittenValues {
            #expect(LayerArrayCodec.decode(LayerArrayCodec.encode(value)) == value,
                    "\(value) did not survive the round-trip")
        }
    }

    /// The one that protects sensitive contacts: `layerSequenceNumbers` is validated on pop,
    /// and a mismatch makes `deactivateSecureMode` substitute an empty payload. A value that
    /// fails to round-trip is not a privacy regression, it is data loss.
    @Test("A dense sweep of the UInt32 range round-trips")
    func denseSweepRoundTrips() {
        var value: UInt32 = 1
        while value < UInt32.max / 2 {
            let asInt = Int(value)
            #expect(LayerArrayCodec.decode(LayerArrayCodec.encode(asInt)) == asInt,
                    "\(asInt) did not survive the round-trip")
            value = value &* 3 &+ 1
        }
        #expect(LayerArrayCodec.decode(LayerArrayCodec.encode(Int(UInt32.max))) == Int(UInt32.max))
    }

    /// `sealedSize` is what `AppLayerConfig.fillerSize` must become. A hardcoded 30 beside a
    /// format that produced 29 and 37–38 is the entire bug, so this pins the derivation
    /// against a real seal rather than trusting the arithmetic.
    @Test("sealedSize matches what sealing actually produces")
    func sealedSizeIsAccurate() throws {
        let key = SymmetricKey(size: .bits256)
        for value in Self.allWrittenValues {
            let sealed = try AES.GCM.seal(LayerArrayCodec.encode(value), using: key).combined
            #expect(sealed?.count == LayerArrayCodec.sealedSize,
                    "value \(value) sealed to \(sealed?.count ?? -1), not \(LayerArrayCodec.sealedSize)")
        }
    }

    // MARK: - Legacy format

    /// The dual-format read. Legacy plaintexts are JSON integers — ASCII — so none can begin
    /// with the 0xFF tag, which is what makes the formats separable when length cannot.
    @Test("Legacy JSON still decodes and cannot be confused with the new format")
    func legacyPlaintextsStillDecode() throws {
        for value in Self.allWrittenValues {
            let legacy = try JSONEncoder().encode(value)
            #expect(legacy.first != 0xFF, "a legacy plaintext must never begin with the format tag")
            #expect(LayerArrayCodec.decode(legacy) == value,
                    "legacy JSON for \(value) must still decode")
        }
    }

    /// Filler is random bytes, and the call sites already read "will not decode" as "no layer
    /// at this depth". The codec must not invent a value for input it cannot parse.
    @Test("decode reports failure rather than substituting a default")
    func decodeNeverSubstitutesADefault() {
        #expect(LayerArrayCodec.decode(Data()) == nil)
        #expect(LayerArrayCodec.decode(Data([0xA5, 0x5A, 0x3C])) == nil)
        #expect(LayerArrayCodec.decode(Data([0xFF, 0x00, 0x01])) == nil, "wrong payload width")
    }

    /// Runs inside rotation, where a trap terminates the process with no catch running.
    @Test("encode is total — no input traps")
    func encodeIsTotal() {
        #expect(LayerArrayCodec.encode(Int.max).count == 1 + LayerArrayCodec.payloadWidth)
        #expect(LayerArrayCodec.encode(Int.min).count == 1 + LayerArrayCodec.payloadWidth)
        #expect(LayerArrayCodec.encode(-1).count      == 1 + LayerArrayCodec.payloadWidth)

        // Clamping, not wrapping: an out-of-range value must not alias a valid one.
        #expect(LayerArrayCodec.decode(LayerArrayCodec.encode(Int.max)) == Int(UInt32.max))
        #expect(LayerArrayCodec.decode(LayerArrayCodec.encode(-1))      == 0)
    }
}
