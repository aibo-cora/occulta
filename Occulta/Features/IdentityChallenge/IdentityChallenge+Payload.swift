//
//  IdentityChallenge+Payload.swift
//  Occulta
//
//  Binary wire formats for the identity challenge protocol.
//  Fixed layout, no optional fields, manual Data serialisation.
//  JSON is explicitly NOT used — encoding ambiguity is unacceptable in a
//  structure that gets signed.
//

import Foundation

// MARK: - Errors

extension IdentityChallenge {
    enum PayloadError: Error {
        /// The supplied Data is not exactly the required byte count.
        case invalidLength(expected: Int, actual: Int)
        /// The supplied Data is too short to contain required fields.
        case dataTooShort
    }
}

// MARK: - ChallengePayload

extension IdentityChallenge {
    /// Fixed 72-byte structure sent from challenger to responder.
    ///
    /// Wire layout:
    /// ```
    /// Offset  Length  Field
    ///      0      32  nonce                 — SecRandomCopyBytes(32)
    ///     32       8  timestamp             — UInt64 big-endian, Unix epoch seconds
    ///     40      32  challengerFingerprint — SHA-256(challengerPublicKey ∥ nonce)
    /// ```
    ///
    /// Total: 72 bytes. No padding, no optional fields.
    struct ChallengePayload {
        static let encodedLength = 72

        private static let nonceRange:       Range<Int> = 0..<32
        private static let timestampRange:   Range<Int> = 32..<40
        private static let fingerprintRange: Range<Int> = 40..<72

        /// 32 cryptographically random bytes.
        let nonce: Data
        /// Unix epoch seconds, stored as big-endian UInt64 bytes (8 bytes).
        let timestamp: Data
        /// SHA-256(challengerPublicKey ∥ nonce) — 32 bytes.
        let challengerFingerprint: Data

        /// Designated initialiser.
        ///
        /// - Parameters:
        ///   - nonce:                  32 bytes of random entropy.
        ///   - timestamp:              8-byte big-endian UInt64 (use `encodeTimestamp(_:)`).
        ///   - challengerFingerprint:  SHA-256(challengerPublicKey ∥ nonce), 32 bytes.
        init(nonce: Data, timestamp: Data, challengerFingerprint: Data) {
            self.nonce                = nonce
            self.timestamp            = timestamp
            self.challengerFingerprint = challengerFingerprint
        }

        // MARK: Serialisation

        /// Pack into exactly 72 bytes: nonce ∥ timestamp ∥ challengerFingerprint.
        func encoded() -> Data {
            var data = Data(capacity: Self.encodedLength)
            data.append(nonce)
            data.append(timestamp)
            data.append(challengerFingerprint)
            return data
        }

        /// Unpack from exactly 72 bytes.
        ///
        /// - Throws: `PayloadError.invalidLength` if `data.count ≠ 72`.
        init(from data: Data) throws {
            guard data.count == Self.encodedLength else {
                throw IdentityChallenge.PayloadError.invalidLength(
                    expected: Self.encodedLength,
                    actual: data.count
                )
            }
            self.nonce                 = data[Self.nonceRange]
            self.timestamp             = data[Self.timestampRange]
            self.challengerFingerprint = data[Self.fingerprintRange]
        }
    }
}

// MARK: - ResponsePayload

extension IdentityChallenge {
    /// Variable-length structure sent from responder back to challenger.
    ///
    /// Wire layout:
    /// ```
    /// Offset  Length  Field
    ///      0      32  challengeNonce  — echoed from ChallengePayload.nonce
    ///     32     var  signature       — DER-encoded ECDSA, raw bytes from SecKeyCreateSignature
    /// ```
    ///
    /// The signature is variable-length DER. It is the final field, so no length
    /// prefix is needed — all bytes after offset 32 are the signature.
    /// Minimum total size: 33 bytes (nonce + at least 1 signature byte).
    struct ResponsePayload {
        private static let noncePrefixLength = 32

        /// Echoed challenge nonce, 32 bytes.
        let challengeNonce: Data
        /// DER-encoded ECDSA signature from `SecKeyCreateSignature`.
        let signature: Data

        init(challengeNonce: Data, signature: Data) {
            self.challengeNonce = challengeNonce
            self.signature      = signature
        }

        // MARK: Serialisation

        /// Pack into challengeNonce ∥ signature.
        func encoded() -> Data {
            var data = Data(capacity: Self.noncePrefixLength + signature.count)
            data.append(challengeNonce)
            data.append(signature)
            return data
        }

        /// Unpack: first 32 bytes = nonce, remainder = signature.
        ///
        /// - Throws: `PayloadError.dataTooShort` if `data.count < 33`.
        init(from data: Data) throws {
            guard data.count >= Self.noncePrefixLength + 1 else {
                throw IdentityChallenge.PayloadError.dataTooShort
            }
            self.challengeNonce = data[..<Self.noncePrefixLength]
            self.signature      = data[Self.noncePrefixLength...]
        }
    }
}

// MARK: - Timestamp helpers

extension IdentityChallenge {
    /// Encode a Unix timestamp as 8 big-endian bytes.
    static func encodeTimestamp(_ timestamp: UInt64) -> Data {
        var bigEndian = timestamp.bigEndian
        return Data(bytes: &bigEndian, count: MemoryLayout<UInt64>.size)
    }

    /// Decode 8 big-endian bytes back to UInt64.
    ///
    /// - Throws: `PayloadError.invalidLength` if `data.count ≠ 8`.
    static func decodeTimestamp(_ data: Data) throws -> UInt64 {
        guard data.count == MemoryLayout<UInt64>.size else {
            throw PayloadError.invalidLength(
                expected: MemoryLayout<UInt64>.size,
                actual: data.count
            )
        }
        return data.withUnsafeBytes { $0.load(as: UInt64.self) }.bigEndian
    }
}
