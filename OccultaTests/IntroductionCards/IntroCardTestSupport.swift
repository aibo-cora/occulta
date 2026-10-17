//
//  IntroCardTestSupport.swift
//  OccultaTests
//
//  Software-key fixtures shared by the introduction card suites. No Secure Enclave: a card's wire format,
//  rules and derivations don't depend on where its keys live (`Docs/Features/Introduction Cards/SPEC.md` §11).
//

import Testing
import CryptoKit
import Foundation

@testable import Occulta
@testable import OccultaFormats

/// Whole seconds, so a card's `expiresAt` survives `encoded` and `recognize(_:)` unchanged.
let cardTestExpiry = Date(timeIntervalSince1970: 1_800_000_000)

/// Builds a card signed by `signingPrivateKey` over the real signing payload.
/// The parts are not validated, so a test can sign a card whose ML-KEM key or agreement key is garbage.
func makeSignedCard(
    agreementKey: Data,
    signingPrivateKey: P256.Signing.PrivateKey,
    expiresAt: Date = cardTestExpiry,
    mlkemKey: Data
) throws -> IntroductionCard {
    let signingKey = signingPrivateKey.publicKey.x963Representation
    let payload = IntroductionCard.signingPayload(
        agreementKey: agreementKey, signingKey: signingKey, expiresAt: expiresAt, mlkemEncapsulationKey: mlkemKey
    )
    return IntroductionCard(
        agreementKey: agreementKey,
        signingKey: signingKey,
        expiresAt: expiresAt,
        mlkemEncapsulationKey: mlkemKey,
        signature: try signingPrivateKey.signature(for: payload).rawRepresentation
    )
}

/// A card with correctly sized, random parts and no valid signature. Enough for code that only reads
/// `agreementKey`, `expiresAt` or `digest`; `recognize(_:)` refuses it.
func makeShapedCard(agreementKey: Data = randomBytes(65), expiresAt: Date = cardTestExpiry) -> IntroductionCard {
    IntroductionCard(
        agreementKey: agreementKey,
        signingKey: randomBytes(65),
        expiresAt: expiresAt,
        mlkemEncapsulationKey: randomBytes(1_568),
        signature: randomBytes(64)
    )
}

/// A card with real keys and a valid signature, and the private halves that made it.
@available(iOS 26, *)
struct CardTestIssuer {
    let agreement: P256.KeyAgreement.PrivateKey
    let signing: P256.Signing.PrivateKey
    let mlkem: MLKEM1024.PrivateKey
    let card: IntroductionCard

    init(expiresAt: Date = cardTestExpiry) throws {
        self.agreement = P256.KeyAgreement.PrivateKey()
        self.signing   = P256.Signing.PrivateKey()
        self.mlkem     = try MLKEM1024.PrivateKey()
        self.card = try makeSignedCard(
            agreementKey: self.agreement.publicKey.x963Representation,
            signingPrivateKey: self.signing,
            expiresAt: expiresAt,
            mlkemKey: self.mlkem.publicKey.rawRepresentation
        )
    }
}

/// Bytewise lexicographic order, written out so a test doesn't lean on the code it checks.
func bytewiseLess(_ left: Data, _ right: Data) -> Bool {
    for (a, b) in zip(left, right) where a != b { return a < b }
    return left.count < right.count
}

/// 1,568 bytes that pass the FIPS 203 modulus check without being a key anyone holds: 1,024 random 12-bit
/// coefficients below 3329, packed three bytes to two coefficients, then a random 32-byte ρ.
func plausibleMLKEMKeyBytes() -> Data {
    var bytes: [UInt8] = []
    for _ in 0 ..< 512 {
        let c0 = UInt16.random(in: 0 ..< 3_329), c1 = UInt16.random(in: 0 ..< 3_329)
        bytes.append(UInt8(c0 & 0xFF))
        bytes.append(UInt8((c0 >> 8) | ((c1 & 0x0F) << 4)))
        bytes.append(UInt8(c1 >> 4))
    }
    return Data(bytes) + randomBytes(32)
}
