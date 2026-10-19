//
//  IntroductionCardTests.swift
//  OccultaTests
//
//  The card's wire format and recognition rule (`Docs/Features/Introduction Cards/SPEC.md` §2, §11).
//  Software keys only: no Secure Enclave, so it runs on CI.
//

import Testing
import CryptoKit
import Foundation

import OccultaCore
@testable import Occulta
@testable import OccultaFormats

@Suite("Introduction card — wire format and recognition (SPEC §2)")
struct IntroductionCardTests {

    // MARK: - Encoding

    @available(iOS 26, *)
    @Test("A card encodes to exactly 1,768 bytes in the SPEC §2 layout")
    func encodesToLayout() throws {
        let issuer = try CardTestIssuer()
        let bytes  = issuer.card.encoded

        #expect(IntroductionCard.byteCount == 1_768)
        #expect(IntroductionCard.signedByteCount == 1_704)
        #expect(bytes.count == 1_768)
        #expect(Data(bytes[0 ..< 64]) == issuer.agreement.publicKey.rawRepresentation, "X ‖ Y, no 0x04 prefix")
        #expect(Data(bytes[64 ..< 128]) == issuer.signing.publicKey.rawRepresentation, "X ‖ Y, no 0x04 prefix")
        let mask = Data(SHA256.hash(data: Data(bytes[0 ..< 64])).prefix(8))
        let plain = Data([0, 0, 0, 0, 0x6B, 0x49, 0xD2, 0x00])
        #expect(Data(bytes[128 ..< 136]) == Data(zip(plain, mask).map { $0 ^ $1 }), "1,800,000,000 big-endian, masked")
        #expect(Data(bytes[136 ..< 1_704]) == issuer.mlkem.publicKey.rawRepresentation)
        #expect(Data(bytes[1_704 ..< 1_768]) == issuer.card.signature)
        #expect(issuer.card.signature.count == 64, "raw r‖s, not DER")
        #expect(issuer.card.agreementKey == issuer.agreement.publicKey.x963Representation, "in memory, X9.63")
    }

    @available(iOS 26, *)
    @Test("No byte outside the ML-KEM key is the same across cards made at the same moment")
    func noConstantBytes() throws {
        let cards = try (0 ..< 40).map { _ in try CardTestIssuer().card.encoded }
        let constant = (Array(0 ..< 136) + Array(1_704 ..< 1_768)).filter { offset in
            Set(cards.map { $0[offset] }).count == 1
        }
        #expect(constant.isEmpty, "offsets with the same byte in every card: \(constant)")
    }

    @available(iOS 26, *)
    @Test("The signing payload is the label followed by the first 1,704 bytes")
    func signingPayloadIsLabelPlusSignedLayout() throws {
        let issuer  = try CardTestIssuer()
        let card    = issuer.card
        let payload = IntroductionCard.signingPayload(
            agreementKey: card.agreementKey, signingKey: card.signingKey,
            expiresAt: card.expiresAt, mlkemEncapsulationKey: card.mlkemEncapsulationKey
        )

        #expect(IntroductionCard.signingLabel == Data("Occulta-introduction-card-v1".utf8))
        #expect(payload == IntroductionCard.signingLabel + card.encoded.prefix(1_704))
        #expect(payload.count == 28 + 1_704)
        #expect(!card.encoded.starts(with: IntroductionCard.signingLabel), "the label is never in the file")
    }

    @available(iOS 26, *)
    @Test("digest is the SHA-256 of the encoded bytes and differs between cards")
    func digestIsSHA256OfEncoding() throws {
        let first  = try CardTestIssuer().card
        let second = try CardTestIssuer().card

        #expect(first.digest == Data(SHA256.hash(data: first.encoded)))
        #expect(first.digest.count == 32)
        #expect(first.digest != second.digest)
    }

    @available(iOS 26, *)
    @Test("expiresAt keeps whole seconds only")
    func expiryKeepsWholeSeconds() throws {
        let fractional = Date(timeIntervalSince1970: 1_800_000_000.75)
        let issuer     = try CardTestIssuer(expiresAt: fractional)
        let recognized = try #require(IntroductionCard.recognize(issuer.card.encoded))

        #expect(recognized.expiresAt == Date(timeIntervalSince1970: 1_800_000_000))
        #expect(recognized.encoded == issuer.card.encoded)
    }

    // MARK: - Recognition

    @available(iOS 26, *)
    @Test("A valid card is recognised and round-trips byte for byte")
    func recognizeRoundTrips() throws {
        let issuer     = try CardTestIssuer()
        let recognized = try #require(IntroductionCard.recognize(issuer.card.encoded))

        #expect(recognized == issuer.card)
        #expect(recognized.encoded == issuer.card.encoded)
        #expect(recognized.digest == issuer.card.digest)
        #expect(recognized.expiresAt == cardTestExpiry)
    }

    @available(iOS 26, *)
    @Test("Recognition doesn't look at the expiry: an expired card is recognised, and refused at import")
    func expiredCardIsStillRecognised() throws {
        let issuer = try CardTestIssuer(expiresAt: Date(timeIntervalSince1970: 1_000))
        #expect(IntroductionCard.recognize(issuer.card.encoded) != nil)
    }

    @available(iOS 26, *)
    @Test("Flipping any single byte makes recognition fail, at every one of the 1,768 offsets")
    func anySingleByteFlipIsRefused() throws {
        let valid = try CardTestIssuer().card.encoded
        #expect(valid.count == 1_768)
        try #require(IntroductionCard.recognize(valid) != nil, "control: the unflipped card must be recognised")

        var accepted: [String] = []
        for mask: UInt8 in [0xFF, 0x01, 0x80] {
            for offset in 0 ..< valid.count {
                var bytes = [UInt8](valid)
                bytes[offset] ^= mask
                if IntroductionCard.recognize(Data(bytes)) != nil { accepted.append("offset \(offset) ^ \(mask)") }
            }
        }
        #expect(accepted.isEmpty, "recognised after a flip: \(accepted.prefix(10))")
    }

    @available(iOS 26, *)
    @Test("Wrong lengths, empty and all-zero inputs are refused")
    func wrongInputsAreRefused() throws {
        let valid = try CardTestIssuer().card.encoded

        #expect(IntroductionCard.recognize(Data(valid.dropLast())) == nil, "1,767 bytes")
        #expect(IntroductionCard.recognize(valid + Data([0])) == nil, "1,769 bytes")
        #expect(IntroductionCard.recognize(Data(valid.dropFirst())) == nil, "shifted by one")
        #expect(IntroductionCard.recognize(valid + valid) == nil, "two cards")
        #expect(IntroductionCard.recognize(Data()) == nil, "empty")
        #expect(IntroductionCard.recognize(Data(count: 1_768)) == nil, "all zero")
        #expect(IntroductionCard.recognize(Data(repeating: 0xFF, count: 1_768)) == nil, "all 0xFF")
        #expect(IntroductionCard.recognize(randomBytes(1_768)) == nil, "random")
        #expect(IntroductionCard.recognize(Data(count: 1_767)) == nil)
        #expect(IntroductionCard.recognize(Data(count: 1_769)) == nil)
        #expect(IntroductionCard.recognize(Data(count: 1_770)) == nil, "the old 1,770-byte size")
    }

    @available(iOS 26, *)
    @Test("A Data slice is recognised, whatever its start index")
    func sliceInputWorks() throws {
        let issuer = try CardTestIssuer()
        let framed = Data(repeating: 0xAA, count: 10) + issuer.card.encoded + Data(repeating: 0xBB, count: 5)
        let slice  = framed[10 ..< 1_778]

        #expect(slice.startIndex == 10)
        #expect(IntroductionCard.recognize(slice) == issuer.card)
        #expect(IntroductionCard.recognize(framed[9 ..< 1_777]) == nil, "a slice that is shifted by one byte")
        #expect(IntroductionCard.recognize(framed[10 ..< 1_777]) == nil, "a slice that is a byte short")
    }

    // MARK: - Fields the signature doesn't excuse

    @available(iOS 26, *)
    @Test("A correctly signed card whose ML-KEM key is all 0xFF is refused")
    func allOnesMLKEMKeyIsRefused() throws {
        // Every 12-bit coefficient is 4095, above the modulus 3329, so FIPS 203's key check fails.
        let card = try makeSignedCard(
            agreementKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            signingPrivateKey: P256.Signing.PrivateKey(),
            mlkemKey: Data(repeating: 0xFF, count: 1_568)
        )
        #expect(card.encoded.count == 1_768)
        #expect(IntroductionCard.recognize(card.encoded) == nil)
    }

    @available(iOS 26, *)
    @Test("A correctly signed card whose ML-KEM key is random bytes is refused")
    func randomMLKEMKeyIsRefused() throws {
        let card = try makeSignedCard(
            agreementKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            signingPrivateKey: P256.Signing.PrivateKey(),
            mlkemKey: randomBytes(1_568)
        )
        #expect(IntroductionCard.recognize(card.encoded) == nil)
    }

    @available(iOS 26, *)
    @Test("A correctly signed card with a real ML-KEM key is recognised: the control for the two above")
    func realMLKEMKeyIsRecognised() throws {
        let card = try makeSignedCard(
            agreementKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            signingPrivateKey: P256.Signing.PrivateKey(),
            mlkemKey: try MLKEM1024.PrivateKey().publicKey.rawRepresentation
        )
        #expect(IntroductionCard.recognize(card.encoded) != nil)
    }

    @available(iOS 26, *)
    @Test("A card that is recognised can be encapsulated to: recognition and import agree")
    func recognisedCardEncapsulates() throws {
        // Import encapsulates to the card's ML-KEM key (SPEC §6.3 step 4). A card that passes recognition but
        // can't be encapsulated to would fail there, after the file had been accepted as a card.
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let candidates = [Data(repeating: 0xFF, count: 1_568), randomBytes(1_568)]
        for key in candidates {
            let card = try makeSignedCard(
                agreementKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
                signingPrivateKey: P256.Signing.PrivateKey(), mlkemKey: key
            )
            if let recognised = IntroductionCard.recognize(card.encoded) {
                #expect(provider.encapsulate(peerPublicKeyData: recognised.mlkemEncapsulationKey) != nil,
                        "recognised, but encapsulation to its ML-KEM key fails")
            }
        }
    }

    @available(iOS 26, *)
    @Test("Swapping only the ML-KEM key fails recognition: the signature covers it (SPEC §11)")
    func swappingMLKEMKeyIsRefused() throws {
        let issuer = try CardTestIssuer()
        let other  = try MLKEM1024.PrivateKey().publicKey.rawRepresentation
        var bytes  = issuer.card.encoded
        bytes.replaceSubrange(136 ..< 1_704, with: other)

        #expect(bytes.count == 1_768)
        #expect(IntroductionCard.recognize(bytes) == nil)
    }

    @available(iOS 26, *)
    @Test("A card signed by a key other than the one it carries is refused")
    func signatureByAnotherKeyIsRefused() throws {
        let issuer = try CardTestIssuer()
        let card   = issuer.card
        let payload = IntroductionCard.signingPayload(
            agreementKey: card.agreementKey, signingKey: card.signingKey,
            expiresAt: card.expiresAt, mlkemEncapsulationKey: card.mlkemEncapsulationKey
        )
        let forged = IntroductionCard(
            agreementKey: card.agreementKey, signingKey: card.signingKey, expiresAt: card.expiresAt,
            mlkemEncapsulationKey: card.mlkemEncapsulationKey,
            signature: try P256.Signing.PrivateKey().signature(for: payload).rawRepresentation
        )
        #expect(IntroductionCard.recognize(forged.encoded) == nil)
    }

    @available(iOS 26, *)
    @Test("A signature over the payload without the domain label is refused")
    func unlabelledSignatureIsRefused() throws {
        let issuer = try CardTestIssuer()
        let card   = issuer.card
        let unlabelled = Data(card.encoded.prefix(1_704))
        let forged = IntroductionCard(
            agreementKey: card.agreementKey, signingKey: card.signingKey, expiresAt: card.expiresAt,
            mlkemEncapsulationKey: card.mlkemEncapsulationKey,
            signature: try issuer.signing.signature(for: unlabelled).rawRepresentation
        )
        #expect(IntroductionCard.recognize(forged.encoded) == nil)
    }

    @available(iOS 26, *)
    @Test("A signed card whose public key is not a point on the curve is refused")
    func keysOffTheCurveAreRefused() throws {
        let signing = P256.Signing.PrivateKey()
        let mlkem   = try MLKEM1024.PrivateKey().publicKey.rawRepresentation

        // Agreement key: right length and prefix, not a point.
        var offCurve = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        offCurve[64] ^= 0x01
        let badAgreement = try makeSignedCard(agreementKey: offCurve, signingPrivateKey: signing, mlkemKey: mlkem)
        #expect(IntroductionCard.recognize(badAgreement.encoded) == nil)

        // Zeros are not a point either.
        let zeros = try makeSignedCard(agreementKey: Data(count: 65), signingPrivateKey: signing, mlkemKey: mlkem)
        #expect(IntroductionCard.recognize(zeros.encoded) == nil)
    }

    @available(iOS 26, *)
    @Test("An expiry beyond 2^53 seconds is refused, so recognise-then-encode always reproduces the input")
    func absurdExpiryIsRefused() throws {
        let issuer = try CardTestIssuer()
        var bytes  = issuer.card.encoded
        // All-ones seconds, masked as the format writes them.
        let mask = Data(SHA256.hash(data: Data(bytes[0 ..< 64])).prefix(8))
        bytes.replaceSubrange(128 ..< 136, with: Data(mask.map { $0 ^ 0xFF }))

        // Re-sign so that only the expiry is wrong.
        let payload = IntroductionCard.signingLabel + bytes.prefix(1_704)
        let signature = try issuer.signing.signature(for: payload).rawRepresentation
        bytes.replaceSubrange(1_704 ..< 1_768, with: signature)

        #expect(bytes.count == 1_768)
        #expect(IntroductionCard.recognize(bytes) == nil)
    }

    @available(iOS 26, *)
    @Test("A negative expiry encodes as zero rather than trapping")
    func negativeExpiryClampsToZero() throws {
        let issuer = try CardTestIssuer(expiresAt: Date(timeIntervalSince1970: -5))
        #expect(issuer.card.encoded.count == 1_768)
        let mask = Data(SHA256.hash(data: Data(issuer.card.encoded[0 ..< 64])).prefix(8))
        #expect(Data(issuer.card.encoded[128 ..< 136]) == mask, "zero, masked")
        #expect(IntroductionCard.recognize(issuer.card.encoded)?.expiresAt == Date(timeIntervalSince1970: 0))
    }
}
