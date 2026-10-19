//
//  IntroductionCard.swift
//  Occulta
//
//  The wire format of an introduction card (`Docs/Features/Introduction Cards/SPEC.md` §2).
//
//  A card is a fixed 1,768-byte blob with no magic bytes, no version byte and no file type, so
//  nothing about it says "Occulta" (Q-04). The domain label exists only inside the signing
//  payload, never in the file. No byte is the same from card to card outside the ML-KEM key
//  (decided 2026-10-19): the keys go without their `0x04` prefix, and the expiry is masked.
//
//  Layout:
//    0    ..< 64    card agreement public key, P-256 raw X ‖ Y
//    64   ..< 128   card signing public key, P-256 raw X ‖ Y
//    128  ..< 136   expiry, Unix seconds, UInt64 big-endian, XOR SHA-256(bytes 0 ..< 64)[0 ..< 8]
//    136  ..< 1704  ML-KEM-1024 encapsulation key
//    1704 ..< 1768  ECDSA P-256 signature, raw r ‖ s (not DER: DER varies in length)
//
//  In memory the two keys stay X9.63 (65 bytes), as every other key in the app; only the wire
//  form drops the prefix. The mask hides the expiry's constant leading zeros from a scanner, and
//  any phone recovers it from the agreement key just before it.
//

import Foundation
import CryptoKit

/// A card as it travels: the issuer's card keys, an expiry and a signature by the card signing key.
public struct IntroductionCard: Equatable, Sendable {

    public static let byteCount = 1_768
    /// Bytes of the layout the signature covers: everything before the signature.
    public static let signedByteCount = 1_704
    /// Domain separation for the signature. Appears in the signing payload only, never in the file.
    public static let signingLabel = Data("Occulta-introduction-card-v1".utf8)

    /// A P-256 public key on the wire: X ‖ Y, without X9.63's `0x04` prefix.
    private static let publicKeyByteCount = 64
    private static let mlkemKeyByteCount  = 1_568
    private static let signatureByteCount = 64
    /// The largest expiry that survives `Date` (a `Double`) and back without loss. A card past it is
    /// not recognised, so `recognize(_:)?.encoded` always equals its input.
    private static let maxWireSeconds: UInt64 = 1 << 53

    /// X9.63 P-256 public key, 65 bytes. Written as 64 bytes, without the prefix.
    public let agreementKey: Data
    /// X9.63 P-256 public key, 65 bytes. Written as 64 bytes, without the prefix.
    public let signingKey: Data
    /// Whole seconds on the wire; a fractional part is dropped by `encoded`.
    public let expiresAt: Date
    /// ML-KEM-1024 encapsulation key, 1,568 bytes.
    public let mlkemEncapsulationKey: Data
    /// Raw `r ‖ s`, 64 bytes, by `signingKey` over `signingPayload`.
    public let signature: Data

    /// Does not validate. A card built from wrong-sized parts encodes to the wrong length and
    /// `recognize(_:)` refuses it.
    public init(agreementKey: Data, signingKey: Data, expiresAt: Date, mlkemEncapsulationKey: Data, signature: Data) {
        self.agreementKey          = agreementKey
        self.signingKey            = signingKey
        self.expiresAt             = expiresAt
        self.mlkemEncapsulationKey = mlkemEncapsulationKey
        self.signature             = signature
    }

    // MARK: - Encoding

    /// The card's bytes: exactly `byteCount` for a card built from correctly sized parts.
    public var encoded: Data {
        var data = Self.signedLayout(
            agreementKey: self.agreementKey,
            signingKey: self.signingKey,
            expiresAt: self.expiresAt,
            mlkemEncapsulationKey: self.mlkemEncapsulationKey
        )
        data.append(self.signature)
        return data
    }

    /// SHA-256 of `encoded`. What an introduction binds itself to (`CardIntroduction`).
    public var digest: Data {
        Data(SHA256.hash(data: self.encoded))
    }

    /// What the card signing key signs: `signingLabel` ‖ the first `signedByteCount` bytes of the layout.
    public static func signingPayload(
        agreementKey: Data,
        signingKey: Data,
        expiresAt: Date,
        mlkemEncapsulationKey: Data
    ) -> Data {
        var payload = self.signingLabel
        payload.append(self.signedLayout(
            agreementKey: agreementKey,
            signingKey: signingKey,
            expiresAt: expiresAt,
            mlkemEncapsulationKey: mlkemEncapsulationKey
        ))
        return payload
    }

    private static func signedLayout(agreementKey: Data, signingKey: Data, expiresAt: Date, mlkemEncapsulationKey: Data) -> Data {
        // Negative, NaN and out-of-range dates clamp rather than trap.
        let seconds = expiresAt.timeIntervalSince1970
        let wire: UInt64 = if seconds.isFinite, seconds > 0 {
            seconds >= Double(self.maxWireSeconds) ? self.maxWireSeconds : UInt64(seconds)
        } else {
            0
        }

        let agreementWire = self.wireKey(agreementKey)
        var expiry = withUnsafeBytes(of: wire.bigEndian) { Data($0) }
        let mask = self.expiryMask(agreementWire: agreementWire)
        for index in expiry.indices { expiry[index] ^= mask[index] }

        var data = Data(capacity: self.byteCount)
        data.append(agreementWire)
        data.append(self.wireKey(signingKey))
        data.append(expiry)
        data.append(mlkemEncapsulationKey)
        return data
    }

    /// X9.63 to the wire form: the 64 bytes after the `0x04` prefix. A key of any other size is written as it
    /// is, so the card comes out the wrong length and `recognize(_:)` refuses it.
    private static func wireKey(_ x963: Data) -> Data {
        x963.count == self.publicKeyByteCount + 1 ? Data(x963.dropFirst()) : x963
    }

    /// What the expiry is XORed with: the first 8 bytes of SHA-256 of the agreement key as written.
    private static func expiryMask(agreementWire: Data) -> Data {
        Data(SHA256.hash(data: agreementWire).prefix(8))
    }

    // MARK: - Recognition

    /// Recognition (SPEC §2). A file is a card if and only if it is exactly `byteCount` bytes, both
    /// P-256 keys parse as points on the curve, the ML-KEM key passes the FIPS 203 modulus check (and CryptoKit's parse on iOS 26
    /// and later), and the signature verifies under `signingKey` over `signingPayload`.
    ///
    /// Returns nil otherwise. Never throws and never traps, whatever the input.
    public static func recognize(_ data: Data) -> IntroductionCard? {
        guard data.count == self.byteCount else { return nil }
        // Rebase: a `Data` slice keeps its parent's indices.
        let bytes = Data(data)

        let agreementEnd = self.publicKeyByteCount
        let signingEnd   = agreementEnd + self.publicKeyByteCount
        let expiryEnd    = signingEnd + 8
        let mlkemEnd     = expiryEnd + self.mlkemKeyByteCount
        let agreementWire = bytes.subdata(in: 0 ..< agreementEnd)
        let signingWire   = bytes.subdata(in: agreementEnd ..< signingEnd)
        let mlkemKey      = bytes.subdata(in: expiryEnd ..< mlkemEnd)
        let signature     = bytes.subdata(in: mlkemEnd ..< self.byteCount)

        let mask    = self.expiryMask(agreementWire: agreementWire)
        let seconds = zip(bytes.subdata(in: signingEnd ..< expiryEnd), mask).reduce(UInt64(0)) { ($0 << 8) | UInt64($1.0 ^ $1.1) }
        guard seconds <= self.maxWireSeconds else { return nil }

        // Parsed as X9.63, prefix restored: that parse checks the point is on the curve, which the raw one may not.
        guard let agreementPublicKey = try? P256.KeyAgreement.PublicKey(x963Representation: Data([0x04]) + agreementWire) else { return nil }
        guard let signingPublicKey = try? P256.Signing.PublicKey(x963Representation: Data([0x04]) + signingWire) else { return nil }
        guard self.parsesAsMLKEM1024(mlkemKey) else { return nil }

        guard let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return nil }
        let card = IntroductionCard(
            agreementKey: agreementPublicKey.x963Representation,
            signingKey: signingPublicKey.x963Representation,
            expiresAt: Date(timeIntervalSince1970: Double(seconds)),
            mlkemEncapsulationKey: mlkemKey,
            signature: signature
        )
        let payload = self.signingPayload(
            agreementKey: card.agreementKey,
            signingKey: card.signingKey,
            expiresAt: card.expiresAt,
            mlkemEncapsulationKey: mlkemKey
        )
        // CryptoKit hashes with SHA-256 itself: the payload is passed as is.
        guard signingPublicKey.isValidSignature(ecdsa, for: payload) else { return nil }
        return card
    }

    private static func parsesAsMLKEM1024(_ key: Data) -> Bool {
        // The modulus check on every iOS version: CryptoKit's own parse checks only the length.
        guard MLKEMKeyCheck.isValidEncapsulationKey1024(key) else { return false }
        if #available(iOS 26, *) {
            return (try? MLKEM1024.PublicKey(rawRepresentation: key)) != nil
        }
        return true
    }
}
