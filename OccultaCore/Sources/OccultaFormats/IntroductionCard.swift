//
//  IntroductionCard.swift
//  Occulta
//
//  The wire format of an introduction card (`Docs/Features/Introduction Cards/SPEC.md` §2).
//
//  A card is a fixed 1,770-byte blob with no magic bytes, no version byte and no file type, so
//  nothing about it says "Occulta" (Q-04). The domain label exists only inside the signing
//  payload, never in the file.
//
//  Layout:
//    0   ..< 65    card agreement public key, X9.63 P-256
//    65  ..< 130   card signing public key, X9.63 P-256
//    130 ..< 138   expiry, Unix seconds, UInt64 big-endian
//    138 ..< 1706  ML-KEM-1024 encapsulation key
//    1706 ..< 1770 ECDSA P-256 signature, raw r ‖ s (not DER: DER varies in length)
//

import Foundation
import CryptoKit

/// A card as it travels: the issuer's card keys, an expiry and a signature by the card signing key.
public struct IntroductionCard: Equatable, Sendable {

    public static let byteCount = 1_770
    /// Bytes of the layout the signature covers: everything before the signature.
    public static let signedByteCount = 1_706
    /// Domain separation for the signature. Appears in the signing payload only, never in the file.
    public static let signingLabel = Data("Occulta-introduction-card-v1".utf8)

    private static let publicKeyByteCount = 65
    private static let mlkemKeyByteCount  = 1_568
    private static let signatureByteCount = 64
    /// The largest expiry that survives `Date` (a `Double`) and back without loss. A card past it is
    /// not recognised, so `recognize(_:)?.encoded` always equals its input.
    private static let maxWireSeconds: UInt64 = 1 << 53

    /// X9.63 P-256 public key, 65 bytes.
    public let agreementKey: Data
    /// X9.63 P-256 public key, 65 bytes.
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

        var data = Data(capacity: self.byteCount)
        data.append(agreementKey)
        data.append(signingKey)
        withUnsafeBytes(of: wire.bigEndian) { data.append(contentsOf: $0) }
        data.append(mlkemEncapsulationKey)
        return data
    }

    // MARK: - Recognition

    /// Recognition (SPEC §2). A file is a card if and only if it is exactly `byteCount` bytes, both
    /// P-256 keys parse, the ML-KEM key passes the FIPS 203 modulus check (and CryptoKit's parse on iOS 26
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
        guard mlkemEnd == self.signedByteCount, mlkemEnd + self.signatureByteCount == self.byteCount else { return nil }

        let agreementKey = bytes.subdata(in: 0 ..< agreementEnd)
        let signingKey   = bytes.subdata(in: agreementEnd ..< signingEnd)
        let mlkemKey     = bytes.subdata(in: expiryEnd ..< mlkemEnd)
        let signature    = bytes.subdata(in: mlkemEnd ..< self.byteCount)

        let seconds = bytes.subdata(in: signingEnd ..< expiryEnd).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard seconds <= self.maxWireSeconds else { return nil }

        guard (try? P256.KeyAgreement.PublicKey(x963Representation: agreementKey)) != nil else { return nil }
        guard let signingPublicKey = try? P256.Signing.PublicKey(x963Representation: signingKey) else { return nil }
        guard self.parsesAsMLKEM1024(mlkemKey) else { return nil }

        guard let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return nil }
        let card = IntroductionCard(
            agreementKey: agreementKey,
            signingKey: signingKey,
            expiresAt: Date(timeIntervalSince1970: Double(seconds)),
            mlkemEncapsulationKey: mlkemKey,
            signature: signature
        )
        let payload = self.signingPayload(
            agreementKey: agreementKey,
            signingKey: signingKey,
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
