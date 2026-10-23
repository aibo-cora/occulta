//
//  CardMeetingTests.swift
//  OccultaTests
//
//  The meeting check's transcript and proof (`Docs/Features/Introduction Cards/SPEC.md` §7). Software keys only.
//

import Testing
import CryptoKit
import Foundation

@testable import Occulta
@testable import OccultaFormats

@Suite("Card meeting — transcript and proof (SPEC §7)")
struct CardMeetingTests {

    /// What both phones hold identically once the ceremony's ML-KEM step completes.
    private struct Ceremony {
        var idA = randomBytes(65), idB = randomBytes(65)
        var nonceA = randomBytes(16), nonceB = randomBytes(16)
        var ctA = randomBytes(1_568), ctB = randomBytes(1_568)

        /// The transcript as phone A computes it.
        var asA: Data {
            CardMeeting.transcript(identityKeys: (self.idA, self.idB), nonces: (self.nonceA, self.nonceB), mlkemCiphertexts: (self.ctA, self.ctB))
        }

        /// The transcript as phone B computes it: every pair the other way round.
        var asB: Data {
            CardMeeting.transcript(identityKeys: (self.idB, self.idA), nonces: (self.nonceB, self.nonceA), mlkemCiphertexts: (self.ctB, self.ctA))
        }
    }

    // MARK: - Transcript

    @Test("Both phones compute the same transcript, whichever is A")
    func bothPhonesAgree() {
        let ceremony = Ceremony()
        #expect(ceremony.asA == ceremony.asB)
        #expect(ceremony.asA.count == 32)
    }

    @Test("Swapping any one pair, or any combination, changes nothing")
    func everySwapCombinationAgrees() {
        let c = Ceremony()
        let reference = c.asA
        for mask in 0 ..< 8 {
            let ids    = mask & 1 == 0 ? (c.idA, c.idB) : (c.idB, c.idA)
            let nonces = mask & 2 == 0 ? (c.nonceA, c.nonceB) : (c.nonceB, c.nonceA)
            let cts    = mask & 4 == 0 ? (c.ctA, c.ctB) : (c.ctB, c.ctA)
            #expect(CardMeeting.transcript(identityKeys: ids, nonces: nonces, mlkemCiphertexts: cts) == reference, "swap mask \(mask)")
        }
    }

    @Test("The transcript is the hash of the label and the sorted pairs, each element framed by its UInt16 big-endian length")
    func transcriptDefinition() {
        let c = Ceremony()
        let framed = { (x: Data) -> Data in Data([UInt8(x.count >> 8), UInt8(x.count & 0xFF)]) + x }
        let sorted = { (x: Data, y: Data) in bytewiseLess(y, x) ? framed(y) + framed(x) : framed(x) + framed(y) }
        let expected = Data(SHA256.hash(
            data: Data("Occulta-card-meeting-v1".utf8) + sorted(c.idA, c.idB) + sorted(c.nonceA, c.nonceB) + sorted(c.ctA, c.ctB)
        ))
        #expect(CardMeeting.transcriptLabel == Data("Occulta-card-meeting-v1".utf8))
        #expect(c.asA == expected)
    }

    @Test("Elements can't be shifted between each other: (ab, c) and (a, bc) give different transcripts")
    func framingPreventsShifting() {
        let nonces = (randomBytes(16), randomBytes(16)), cts = (randomBytes(1_568), randomBytes(1_568))
        let make = { (ids: (Data, Data)) in CardMeeting.transcript(identityKeys: ids, nonces: nonces, mlkemCiphertexts: cts) }

        let a = Data("a".utf8), b = Data("b".utf8), c = Data("c".utf8)
        #expect(make((Data("ab".utf8), c)) != make((a, Data("bc".utf8))))
        #expect(make((Data("abc".utf8), Data())) != make((Data("ab".utf8), c)))
        #expect(make((a, b)) != make((Data(), Data("ab".utf8))), "an empty element is not nothing")

        // The same shift across pairs: a byte moved from the last id to the first nonce.
        let idA = randomBytes(65), idB = randomBytes(65), n1 = randomBytes(16), n2 = randomBytes(16)
        let moved = CardMeeting.transcript(
            identityKeys: (idA, idB + n1.prefix(1)), nonces: (Data(n1.dropFirst()), n2), mlkemCiphertexts: cts
        )
        let whole = CardMeeting.transcript(identityKeys: (idA, idB), nonces: (n1, n2), mlkemCiphertexts: cts)
        #expect(moved != whole)
    }

    @Test("Changing any single input changes the transcript")
    func anyInputChangeChangesTranscript() {
        let base = Ceremony()
        let reference = base.asA
        let flip = { (data: Data) -> Data in var bytes = [UInt8](data); bytes[bytes.count / 2] ^= 0x01; return Data(bytes) }

        var c = base; c.idA = flip(c.idA);       #expect(c.asA != reference, "idA")
        c = base;     c.idB = flip(c.idB);       #expect(c.asA != reference, "idB")
        c = base;     c.nonceA = flip(c.nonceA); #expect(c.asA != reference, "nonceA")
        c = base;     c.nonceB = flip(c.nonceB); #expect(c.asA != reference, "nonceB")
        c = base;     c.ctA = flip(c.ctA);       #expect(c.asA != reference, "ctA")
        c = base;     c.ctB = flip(c.ctB);       #expect(c.asA != reference, "ctB")
    }

    // MARK: - Proof

    @Test("The proof payload is the label, the transcript and the signer's identity key")
    func proofPayloadLayout() {
        let transcript = randomBytes(32), id = randomBytes(65)
        #expect(CardMeeting.proofLabel == Data("Occulta-card-meeting-proof-v1".utf8))
        #expect(CardMeeting.proofPayload(transcript: transcript, signerIdentityKey: id)
                == Data("Occulta-card-meeting-proof-v1".utf8) + transcript + id)
        #expect(CardMeeting.proofByteCount == 64)
    }

    private func proof(by signing: P256.Signing.PrivateKey, transcript: Data, signerIdentityKey: Data) throws -> Data {
        try signing.signature(for: CardMeeting.proofPayload(transcript: transcript, signerIdentityKey: signerIdentityKey)).rawRepresentation
    }

    @Test("A real proof verifies, each way, on both phones")
    func realProofVerifies() throws {
        let c = Ceremony()
        let aliceSigning = P256.Signing.PrivateKey(), bobSigning = P256.Signing.PrivateKey()

        // Each signs with its own card signing key and its own identity key in the payload.
        let proofFromAlice = try self.proof(by: aliceSigning, transcript: c.asA, signerIdentityKey: c.idA)
        let proofFromBob   = try self.proof(by: bobSigning, transcript: c.asB, signerIdentityKey: c.idB)
        #expect(proofFromAlice.count == 64)

        // Bob checks Alice's, Alice checks Bob's: the signer's identity key is the sender's.
        #expect(CardMeeting.verifyProof(proofFromAlice, transcript: c.asB, signerIdentityKey: c.idA, signingKey: aliceSigning.publicKey.x963Representation))
        #expect(CardMeeting.verifyProof(proofFromBob, transcript: c.asA, signerIdentityKey: c.idB, signingKey: bobSigning.publicKey.x963Representation))
    }

    @Test("A proof reflected back to its sender fails: it is checked against a different signer identity key")
    func reflectedProofFails() throws {
        let c = Ceremony()
        let aliceSigning = P256.Signing.PrivateKey()
        let proofFromAlice = try self.proof(by: aliceSigning, transcript: c.asA, signerIdentityKey: c.idA)

        // Alice receives her own proof back, and expects its signer to be Bob.
        #expect(!CardMeeting.verifyProof(proofFromAlice, transcript: c.asA, signerIdentityKey: c.idB, signingKey: aliceSigning.publicKey.x963Representation))
        // Under Bob's key, it was never his.
        #expect(!CardMeeting.verifyProof(proofFromAlice, transcript: c.asA, signerIdentityKey: c.idB, signingKey: P256.Signing.PrivateKey().publicKey.x963Representation))
    }

    @Test("A proof under the wrong signing key, or for another transcript, fails")
    func wrongKeyOrTranscriptFails() throws {
        let c = Ceremony()
        let signing = P256.Signing.PrivateKey()
        let real = try self.proof(by: signing, transcript: c.asA, signerIdentityKey: c.idA)

        #expect(CardMeeting.verifyProof(real, transcript: c.asA, signerIdentityKey: c.idA, signingKey: signing.publicKey.x963Representation), "control")
        #expect(!CardMeeting.verifyProof(real, transcript: c.asA, signerIdentityKey: c.idA, signingKey: P256.Signing.PrivateKey().publicKey.x963Representation), "another signing key")
        #expect(!CardMeeting.verifyProof(real, transcript: Ceremony().asA, signerIdentityKey: c.idA, signingKey: signing.publicKey.x963Representation), "another meeting")

        var flipped = [UInt8](real); flipped[10] ^= 0x01
        #expect(!CardMeeting.verifyProof(Data(flipped), transcript: c.asA, signerIdentityKey: c.idA, signingKey: signing.publicKey.x963Representation), "a flipped byte")
    }

    @Test("Wrong lengths, DER and unparseable keys fail, never trap")
    func malformedProofFails() throws {
        let c = Ceremony()
        let signing = P256.Signing.PrivateKey()
        let key = signing.publicKey.x963Representation
        let real = try self.proof(by: signing, transcript: c.asA, signerIdentityKey: c.idA)
        let der = try signing.signature(for: CardMeeting.proofPayload(transcript: c.asA, signerIdentityKey: c.idA)).derRepresentation

        #expect(!CardMeeting.verifyProof(Data(real.dropLast()), transcript: c.asA, signerIdentityKey: c.idA, signingKey: key), "63 bytes")
        #expect(!CardMeeting.verifyProof(real + Data([0]), transcript: c.asA, signerIdentityKey: c.idA, signingKey: key), "65 bytes")
        #expect(!CardMeeting.verifyProof(Data(), transcript: c.asA, signerIdentityKey: c.idA, signingKey: key), "empty")
        #expect(!CardMeeting.verifyProof(der, transcript: c.asA, signerIdentityKey: c.idA, signingKey: key), "DER")
        #expect(!CardMeeting.verifyProof(Data(count: 64), transcript: c.asA, signerIdentityKey: c.idA, signingKey: key), "zeros")
        #expect(!CardMeeting.verifyProof(real, transcript: c.asA, signerIdentityKey: c.idA, signingKey: Data()), "no key")
        #expect(!CardMeeting.verifyProof(real, transcript: c.asA, signerIdentityKey: c.idA, signingKey: randomBytes(65)), "not a point")
    }

    // MARK: - Filler

    @Test("A filler is 64 bytes, the length of a proof, and does not verify")
    func fillerIsProofSizedAndInvalid() throws {
        let c = Ceremony()
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let real = try self.proof(by: P256.Signing.PrivateKey(), transcript: c.asA, signerIdentityKey: c.idA)

        for _ in 0 ..< 50 {
            let filler = CardMeeting.filler()
            #expect(filler.count == 64)
            #expect(filler.count == real.count, "the same length as a real proof")
            #expect(!CardMeeting.verifyProof(filler, transcript: c.asA, signerIdentityKey: c.idA, signingKey: key))
        }
    }

    @Test("Fillers are random: distinct, and not zeros")
    func fillerIsRandom() {
        let fillers = (0 ..< 20).map { _ in CardMeeting.filler() }
        #expect(Set(fillers).count == 20)
        #expect(!fillers.contains(Data(count: 64)))
    }
}
