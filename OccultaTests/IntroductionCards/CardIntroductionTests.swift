//
//  CardIntroductionTests.swift
//  OccultaTests
//
//  Carol's introduction and its binding to the card she answers (`Docs/Features/Introduction Cards/SPEC.md` §4.4).
//  Software keys only.
//

import Testing
import CryptoKit
import Foundation

@testable import Occulta
@testable import OccultaFormats

@Suite("Card introduction — signature bound to the card digest (SPEC §4.4)")
struct CardIntroductionTests {

    /// Carol's side: her keys and an introduction signed for `cardDigest`.
    private struct Carol {
        let agreement = P256.KeyAgreement.PrivateKey()
        let signing   = P256.Signing.PrivateKey()
        /// Passes the FIPS 203 modulus check, which `verify` applies; whether it is a key anyone holds doesn't matter here.
        let mlkemKey  = plausibleMLKEMKeyBytes()

        func introduction(answering cardDigest: Data) throws -> CardIntroduction {
            let agreementKey = self.agreement.publicKey.x963Representation
            let signingKey   = self.signing.publicKey.x963Representation
            let payload = CardIntroduction.signingPayload(
                cardDigest: cardDigest, agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: self.mlkemKey
            )
            return CardIntroduction(
                agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: self.mlkemKey,
                signature: try self.signing.signature(for: payload).derRepresentation
            )
        }
    }

    /// A different field of the same introduction, with everything else as it was.
    private func replacing(
        _ introduction: CardIntroduction,
        agreementKey: Data? = nil, signingKey: Data? = nil, mlkemEncapsulationKey: Data? = nil, signature: Data? = nil
    ) -> CardIntroduction {
        CardIntroduction(
            agreementKey: agreementKey ?? introduction.agreementKey,
            signingKey: signingKey ?? introduction.signingKey,
            mlkemEncapsulationKey: mlkemEncapsulationKey ?? introduction.mlkemEncapsulationKey,
            signature: signature ?? introduction.signature
        )
    }

    // MARK: - Accepts

    @Test("It verifies for the digest of the card it answers")
    func verifiesForRightCard() throws {
        let digest = makeShapedCard().digest
        let intro  = try Carol().introduction(answering: digest)

        #expect(intro.verify(cardDigest: digest))
    }

    @Test("The signing payload is the label, the digest and the three keys, in that order")
    func payloadLayout() {
        let digest = randomBytes(32), agreement = randomBytes(65), signing = randomBytes(65), mlkem = randomBytes(1_568)
        let payload = CardIntroduction.signingPayload(
            cardDigest: digest, agreementKey: agreement, signingKey: signing, mlkemEncapsulationKey: mlkem
        )

        #expect(CardIntroduction.signingLabel == Data("Occulta-card-introduction-v1".utf8))
        #expect(payload == Data("Occulta-card-introduction-v1".utf8) + digest + agreement + signing + mlkem)
        #expect(payload.count == 28 + 32 + 65 + 65 + 1_568)
    }

    @Test("The signature is DER, not the card's raw form")
    func signatureIsDER() throws {
        let intro = try Carol().introduction(answering: makeShapedCard().digest)
        #expect((70 ... 72).contains(intro.signature.count))
        #expect(intro.signature.first == 0x30)
    }

    @Test("It survives a JSON round trip, as it will inside RecipientPayload")
    func codableRoundTrip() throws {
        let digest = makeShapedCard().digest
        let intro  = try Carol().introduction(answering: digest)
        let decoded = try JSONDecoder().decode(CardIntroduction.self, from: try JSONEncoder().encode(intro))

        #expect(decoded == intro)
        #expect(decoded.verify(cardDigest: digest))
    }

    // MARK: - Replay

    @Test("It does not verify against another card's digest: no replay to another card")
    func replayToAnotherCardFails() throws {
        let cardForBob   = makeShapedCard()
        let cardForDave  = makeShapedCard()
        let intro        = try Carol().introduction(answering: cardForBob.digest)

        #expect(intro.verify(cardDigest: cardForBob.digest), "control")
        #expect(!intro.verify(cardDigest: cardForDave.digest))
    }

    @Test("A card that differs in a single byte has a different digest, which fails")
    func digestOfEditedCardFails() throws {
        let card   = makeShapedCard()
        let intro  = try Carol().introduction(answering: card.digest)
        var edited = [UInt8](card.encoded)
        edited[900] ^= 0x01

        #expect(!intro.verify(cardDigest: Data(SHA256.hash(data: Data(edited)))))
    }

    // MARK: - Tampering

    @Test("Replacing any key, or flipping a byte of the ML-KEM key, fails")
    func tamperedKeysFail() throws {
        let digest = makeShapedCard().digest
        let intro  = try Carol().introduction(answering: digest)

        let otherAgreement = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let otherSigning   = P256.Signing.PrivateKey().publicKey.x963Representation
        var flippedMLKEM   = intro.mlkemEncapsulationKey
        flippedMLKEM[700] ^= 0x01
        var offCurve = intro.agreementKey
        offCurve[40] ^= 0x01

        #expect(!self.replacing(intro, agreementKey: otherAgreement).verify(cardDigest: digest), "another valid agreement key")
        #expect(!self.replacing(intro, agreementKey: offCurve).verify(cardDigest: digest), "an agreement key off the curve")
        #expect(!self.replacing(intro, signingKey: otherSigning).verify(cardDigest: digest), "another valid signing key")
        #expect(!self.replacing(intro, mlkemEncapsulationKey: flippedMLKEM).verify(cardDigest: digest), "a flipped ML-KEM byte")
        #expect(!self.replacing(intro, mlkemEncapsulationKey: plausibleMLKEMKeyBytes()).verify(cardDigest: digest), "another ML-KEM key")
    }

    @Test("A bad signature fails")
    func badSignatureFails() throws {
        let carol  = Carol()
        let digest = makeShapedCard().digest
        let intro  = try carol.introduction(answering: digest)

        var flipped = [UInt8](intro.signature)
        flipped[flipped.count - 5] ^= 0x01
        let raw = try P256.Signing.ECDSASignature(derRepresentation: intro.signature).rawRepresentation
        let byOther = try P256.Signing.PrivateKey().signature(for: Data("x".utf8)).derRepresentation

        #expect(!self.replacing(intro, signature: Data(flipped)).verify(cardDigest: digest), "a flipped byte")
        #expect(!self.replacing(intro, signature: raw).verify(cardDigest: digest), "raw r‖s where DER is expected")
        #expect(!self.replacing(intro, signature: byOther).verify(cardDigest: digest), "a signature over another message")
        #expect(!self.replacing(intro, signature: Data()).verify(cardDigest: digest), "empty")
        #expect(!self.replacing(intro, signature: randomBytes(71)).verify(cardDigest: digest), "random")
    }

    @Test("A signature by a key other than the one in the introduction fails")
    func signedByAnotherKeyFails() throws {
        let carol  = Carol()
        let digest = makeShapedCard().digest
        let agreementKey = carol.agreement.publicKey.x963Representation
        let signingKey   = carol.signing.publicKey.x963Representation
        let payload = CardIntroduction.signingPayload(
            cardDigest: digest, agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: carol.mlkemKey
        )
        let forged = CardIntroduction(
            agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: carol.mlkemKey,
            signature: try P256.Signing.PrivateKey().signature(for: payload).derRepresentation
        )

        #expect(!forged.verify(cardDigest: digest))
    }

    // MARK: - Lengths

    @Test("Wrong lengths fail, never trap")
    func wrongLengthsFail() throws {
        let digest = makeShapedCard().digest
        let intro  = try Carol().introduction(answering: digest)

        #expect(!intro.verify(cardDigest: Data(digest.dropLast())), "31-byte digest")
        #expect(!intro.verify(cardDigest: digest + Data([0])), "33-byte digest")
        #expect(!intro.verify(cardDigest: Data()), "empty digest")
        #expect(!self.replacing(intro, mlkemEncapsulationKey: Data(intro.mlkemEncapsulationKey.dropLast())).verify(cardDigest: digest), "1,567-byte ML-KEM key")
        #expect(!self.replacing(intro, mlkemEncapsulationKey: intro.mlkemEncapsulationKey + Data([0])).verify(cardDigest: digest), "1,569-byte ML-KEM key")
        #expect(!self.replacing(intro, mlkemEncapsulationKey: Data()).verify(cardDigest: digest))
        #expect(!self.replacing(intro, agreementKey: Data(intro.agreementKey.dropLast())).verify(cardDigest: digest), "64-byte agreement key")
        #expect(!self.replacing(intro, signingKey: Data(intro.signingKey.dropLast())).verify(cardDigest: digest), "64-byte signing key")
        #expect(!self.replacing(intro, agreementKey: Data(), signingKey: Data()).verify(cardDigest: digest))
    }

    // MARK: - The ML-KEM key must be a key

    @Test("A correctly signed introduction with a garbage ML-KEM key is refused")
    func garbageMLKEMKeyFails() throws {
        let carol  = Carol()
        let digest = makeShapedCard().digest
        let agreementKey = carol.agreement.publicKey.x963Representation
        let signingKey   = carol.signing.publicKey.x963Representation

        func signed(_ mlkem: Data) throws -> CardIntroduction {
            let payload = CardIntroduction.signingPayload(
                cardDigest: digest, agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: mlkem
            )
            return CardIntroduction(
                agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: mlkem,
                signature: try carol.signing.signature(for: payload).derRepresentation
            )
        }

        #expect(try signed(plausibleMLKEMKeyBytes()).verify(cardDigest: digest), "control: the same construction with a valid key")
        #expect(try !signed(Data(repeating: 0xFF, count: 1_568)).verify(cardDigest: digest), "all 0xFF")
        #expect(try !signed(randomBytes(1_568)).verify(cardDigest: digest), "random bytes")
    }
}
