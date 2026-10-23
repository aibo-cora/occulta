//
//  CardIntroduction.swift
//  Occulta
//
//  The introduction a card's recipient sends in her first messages
//  (`Docs/Features/Introduction Cards/SPEC.md` §4.4).
//
//  It carries her own card keys and is signed by her card signing key over a payload that includes
//  the digest of the card she is answering, so it can't be replayed against another card. The
//  signature is DER, like the other signatures inside `RecipientPayload`.
//

import Foundation
import CryptoKit

/// Carol's card keys, bound to the card she imported.
public struct CardIntroduction: Codable, Equatable, Sendable {

    /// Domain separation for the signature.
    public static let signingLabel = Data("Occulta-card-introduction-v1".utf8)

    private static let digestByteCount  = 32

    /// Her card agreement public key, X9.63 P-256, 65 bytes.
    public let agreementKey: Data
    /// Her card signing public key, X9.63 P-256, 65 bytes.
    public let signingKey: Data
    /// Her ML-KEM-1024 encapsulation key, 1,568 bytes.
    public let mlkemEncapsulationKey: Data
    /// DER ECDSA P-256 signature by `signingKey` over `signingPayload`.
    public let signature: Data

    /// Does not validate; `verify(cardDigest:)` does.
    public init(agreementKey: Data, signingKey: Data, mlkemEncapsulationKey: Data, signature: Data) {
        self.agreementKey          = agreementKey
        self.signingKey            = signingKey
        self.mlkemEncapsulationKey = mlkemEncapsulationKey
        self.signature             = signature
    }

    /// `signingLabel` ‖ `cardDigest` (32) ‖ `agreementKey` ‖ `signingKey` ‖ `mlkemEncapsulationKey`.
    ///
    /// - Parameter cardDigest: `IntroductionCard.digest` of the card being answered.
    public static func signingPayload(cardDigest: Data, agreementKey: Data, signingKey: Data, mlkemEncapsulationKey: Data) -> Data {
        var payload = self.signingLabel
        payload.append(cardDigest)
        payload.append(agreementKey)
        payload.append(signingKey)
        payload.append(mlkemEncapsulationKey)
        return payload
    }

    /// Whether this introduction is well formed and `signature` is valid under `signingKey` for it, answering
    /// the card with `cardDigest`. False on any parse failure, never throws.
    ///
    /// Well formed: both keys parse as P-256 points and the ML-KEM key passes the FIPS 203 modulus check.
    public func verify(cardDigest: Data) -> Bool {
        guard cardDigest.count == Self.digestByteCount, MLKEMKeyCheck.isValidEncapsulationKey1024(self.mlkemEncapsulationKey) else { return false }
        guard (try? P256.KeyAgreement.PublicKey(x963Representation: self.agreementKey)) != nil else { return false }
        guard let key = try? P256.Signing.PublicKey(x963Representation: self.signingKey) else { return false }
        guard let ecdsa = try? P256.Signing.ECDSASignature(derRepresentation: self.signature) else { return false }

        let payload = Self.signingPayload(
            cardDigest: cardDigest,
            agreementKey: self.agreementKey,
            signingKey: self.signingKey,
            mlkemEncapsulationKey: self.mlkemEncapsulationKey
        )
        return key.isValidSignature(ecdsa, for: payload)
    }
}
