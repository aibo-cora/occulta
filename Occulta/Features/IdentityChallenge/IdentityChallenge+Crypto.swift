//
//  IdentityChallenge+Crypto.swift
//  Occulta
//
//  Signing and verification helpers for the identity-challenge protocol.
//
//  These extensions are intentionally tiny:
//    - `buildSignedData` is the single source of truth for what gets signed
//      and verified — both sides MUST construct identical bytes or the
//      signature will not verify.
//    - `signChallenge` delegates to `KeyManagerProtocol` so tests inject
//      `TestKeyManager` instead of touching the Secure Enclave.
//    - `verifyChallenge` is a thin wrapper around `SecKeyVerifySignature` —
//      no SE access, runs anywhere a `SecKey` public-key reference exists.
//

import Foundation
import Security

// MARK: - Manager.Key (SE path)

extension Manager.Key {
    /// SE-backed ECDSA signature over `data` using the long-term identity key.
    ///
    /// Algorithm: `.ecdsaSignatureMessageX962SHA256` — hashes `data` internally
    /// with SHA-256 inside the SE. ⚠️ NEVER pre-hash. Double-hashing produces
    /// a signature that no verifier will accept, and the failure mode is
    /// silent (looks identical to "wrong key").
    ///
    /// SE access triggers biometric per the access-control flags on the
    /// identity key — this is hardware enforcement, not an app-level prompt.
    func signIdentityChallenge(_ data: Data) throws -> Data {
        guard let privateKey = try self.retrievePrivateKey() else {
            throw Errors.noIdentityAvailable
        }

        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw IdentityChallenge.SigningError.algorithmUnsupported
        }

        var error: Unmanaged<CFError>?

        // ⚠️ DO NOT PRE-HASH — API hashes internally. Double-hashing = silent failure.
        guard
            let signature = SecKeyCreateSignature(
                privateKey,
                algorithm,
                data as CFData,
                &error
            ) as Data?
        else {
            throw error!.takeRetainedValue() as Error
        }

        return signature
    }
}

// MARK: - SigningError

extension IdentityChallenge {
    enum SigningError: Error {
        /// The retrieved key reference does not support ECDSA signing.
        /// Should never occur with a valid SE-resident P-256 key.
        case algorithmUnsupported
    }
}

// MARK: - Manager.Crypto helpers

extension Manager.Crypto {

    /// Construct the exact byte sequence that is signed by the responder and
    /// verified by the challenger.
    ///
    /// Layout (concatenation, no length prefixes — every field is fixed size):
    /// ```
    /// domainPrefix (UTF-8, 29 bytes) ∥ nonce (32) ∥ timestamp (8 BE) ∥ challengerFingerprint (32)
    /// ```
    ///
    /// **Why a function and not a property:** sender and verifier MUST construct
    /// identical bytes. Sharing one function eliminates the entire class of
    /// "almost-identical-but-not-quite" bugs (off-by-one prefix length,
    /// endian flips, field reordering).
    ///
    /// **Why the domain prefix is non-negotiable:** without it, an ECDSA
    /// signature produced for an identity challenge could be accepted by a
    /// future Document Signing feature (or vice versa). That is the textbook
    /// cross-protocol signature-reuse vulnerability.
    static func buildSignedData(nonce: Data, timestamp: Data, challengerFingerprint: Data) -> Data {
        var data = Data(IdentityChallenge.domainPrefix.utf8)
        data.append(nonce)
        data.append(timestamp)
        data.append(challengerFingerprint)
        return data
    }

    /// Sign an identity-challenge `signedData` blob with our long-term identity key.
    ///
    /// Delegates to `keyManager.signIdentityChallenge(_:)` so the SE path
    /// (`Manager.Key`) and the in-memory test path (`TestKeyManager`) share the
    /// exact same wire format.
    ///
    /// - Parameter signedData: Output of `buildSignedData(nonce:timestamp:challengerFingerprint:)`.
    /// - Returns: DER-encoded ECDSA signature.
    func signChallenge(_ signedData: Data) throws -> Data {
        try self.keyManager.signIdentityChallenge(signedData)
    }

    /// Verify an identity-challenge signature against `signedData` using `publicKey`.
    ///
    /// - Parameters:
    ///   - signedData: Output of `buildSignedData(nonce:timestamp:challengerFingerprint:)`,
    ///                 reconstructed locally from the challenger's stored entry.
    ///   - signature:  DER-encoded ECDSA signature from the responder.
    ///   - publicKey:  The contact's stored long-term P-256 public key, as a SecKey.
    /// - Returns: `true` only if the signature is well-formed and verifies against
    ///            `publicKey` over `signedData` under
    ///            `.ecdsaSignatureMessageX962SHA256`. `false` on any failure mode.
    ///            Never throws — verify is a yes/no answer.
    ///
    /// ⚠️ Same algorithm as `signChallenge` — DO NOT pre-hash. Verifier hashes internally.
    func verifyChallenge(_ signedData: Data, signature: Data, publicKey: SecKey) -> Bool {
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            return false
        }

        var error: Unmanaged<CFError>?
        let ok = SecKeyVerifySignature(
            publicKey,
            algorithm,
            signedData as CFData,
            signature as CFData,
            &error
        )
        // Discard the CFError — verification is yes/no, no caller-visible diagnostics.
        // Per spec rule 4: error messages must not leak which key signed, what
        // failed, or any cryptographic detail.
        if !ok { _ = error?.takeRetainedValue() }
        return ok
    }
}
