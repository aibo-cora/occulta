//
//  CardMeeting.swift
//  Occulta
//
//  The meeting check (`Docs/Features/Introduction Cards/SPEC.md` §7).
//
//  When two people who hold a card conversation meet and run the exchange, each signs a transcript
//  of the exchange with the card signing key. A valid proof says the person in front holds the
//  card conversation's keys.
//

import Foundation
import CryptoKit
import Security

public enum CardMeeting {

    public static let transcriptLabel = Data("Occulta-card-meeting-v1".utf8)
    public static let proofLabel      = Data("Occulta-card-meeting-proof-v1".utf8)
    /// A raw ECDSA P-256 signature, `r ‖ s`.
    public static let proofByteCount  = 64

    /// `T = SHA-256(transcriptLabel ‖ framed(sorted(idA, idB)) ‖ framed(sorted(nonceA, nonceB)) ‖ framed(sorted(ctA, ctB)))`,
    /// where every element is written as its length (UInt16 big-endian) ‖ its bytes, so inputs of varying
    /// length can't be shifted between elements to collide. Each pair is ordered lexicographically by its raw
    /// bytes, so both sides compute the same `T` whichever is "A". The pairs are values both sides hold
    /// identically once the ML-KEM step completes. An element is at most 65,535 bytes; a longer one is
    /// framed with that length and still hashed whole.
    public static func transcript(identityKeys: (Data, Data), nonces: (Data, Data), mlkemCiphertexts: (Data, Data)) -> Data {
        var input = self.transcriptLabel
        for pair in [identityKeys, nonces, mlkemCiphertexts] {
            let (first, second) = pair.1.lexicographicallyPrecedes(pair.0) ? (pair.1, pair.0) : (pair.0, pair.1)
            for element in [first, second] {
                withUnsafeBytes(of: UInt16(clamping: element.count).bigEndian) { input.append(contentsOf: $0) }
                input.append(element)
            }
        }
        return Data(SHA256.hash(data: input))
    }

    /// `proofLabel ‖ T ‖ signerIdentityKey`. The signer's identity key stops a proof being reflected
    /// back to its sender.
    public static func proofPayload(transcript: Data, signerIdentityKey: Data) -> Data {
        var payload = self.proofLabel
        payload.append(transcript)
        payload.append(signerIdentityKey)
        return payload
    }

    /// Whether `proof` (raw 64-byte `r ‖ s`) is a valid signature by `signingKey` (X9.63 P-256) over the
    /// proof payload. False for a filler, a wrong length or an unparseable key; never throws.
    public static func verifyProof(_ proof: Data, transcript: Data, signerIdentityKey: Data, signingKey: Data) -> Bool {
        guard proof.count == self.proofByteCount,
              let key = try? P256.Signing.PublicKey(x963Representation: signingKey),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: proof)
        else { return false }

        return key.isValidSignature(signature, for: self.proofPayload(transcript: transcript, signerIdentityKey: signerIdentityKey))
    }

    /// 64 random bytes, sent when there is no card conversation for the contact. Indistinguishable from `r ‖ s`.
    public static func filler() -> Data {
        var bytes = [UInt8](repeating: 0, count: self.proofByteCount)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            // Never send zeros, which would tell the person in front there is no proof. The system
            // generator is also cryptographically secure on Apple platforms.
            var generator = SystemRandomNumberGenerator()
            for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max, using: &generator) }
        }
        return Data(bytes)
    }
}
