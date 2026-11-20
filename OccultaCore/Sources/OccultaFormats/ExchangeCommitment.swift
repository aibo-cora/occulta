//
//  ExchangeCommitment.swift
//  Occulta
//
//  Commit, then reveal, for the in-person key exchange (Bug 198). Each phone's discovery message carries a hash of its
//  nonce and not the nonce; the nonce goes out last, after every other message of the exchange, and is checked against
//  the hash. The verification words and the routing key are derived over both nonces and a hash of every message of the
//  exchange, so whatever a man in the middle sends is fixed before either nonce is known to him, and no search over what
//  he sends can steer the words. Also covers Bug 199: an ML-KEM key removed from an identity message changes that
//  message's bytes, so the two phones' transcripts, and their words, differ.
//
//  Pure functions, pinned by the interop vectors (`exchange.commitment`, `exchange.transcript*`, `exchange.words.*`,
//  `exchange.routingKey.*`).
//

import Foundation
import CryptoKit

public enum ExchangeCommitment {

    public static let nonceSize = 16
    public static let commitmentSize = 32
    public static let transcriptSize = 32

    static let commitmentDomain = Data("occulta-exchange-commit-v1".utf8)
    static let transcriptDomain = Data("occulta-exchange-transcript-v1".utf8)

    // MARK: - Commitment

    /// SHA-256("occulta-exchange-commit-v1" ‖ nonce). `nil` for a nonce that isn't 16 bytes.
    public static func commitment(to nonce: Data) -> Data? {
        guard nonce.count == Self.nonceSize else { return nil }
        return Data(SHA256.hash(data: Self.commitmentDomain + nonce))
    }

    /// Whether `nonce` is the one `commitment` was made to. Neither is secret by the time they are compared.
    public static func opens(_ commitment: Data, with nonce: Data) -> Bool {
        guard commitment.count == Self.commitmentSize, let expected = Self.commitment(to: nonce) else { return false }
        return expected == commitment
    }

    // MARK: - Transcript

    /// Which phone sent a message: the one whose Multipeer display name sorts lower is the initiator.
    public enum Role: UInt8, Sendable { case initiator = 0, responder = 1 }

    /// The messages that come before the reveal. The reveal itself, the card proof and anything after are not in it.
    public enum Step: UInt8, Sendable { case discovery = 1, identity = 2, ciphertext = 3 }

    /// One message of the exchange, exactly as it was sent and as it was received: the bytes that crossed the channel.
    public struct Message: Sendable {
        public let role: Role
        public let step: Step
        public let bytes: Data

        public init(role: Role, step: Step, bytes: Data) {
            self.role = role
            self.step = step
            self.bytes = bytes
        }
    }

    /// SHA-256("occulta-exchange-transcript-v1" ‖ each message as `step ‖ role ‖ UInt32 big-endian length ‖ bytes`), in
    /// the order discovery, identity, ciphertext, the initiator's before the responder's, whatever order the caller lists
    /// them in. Both phones hold the same messages if the channel is honest, so they get the same hash; a message that
    /// was added, removed, replaced or changed in any byte makes them differ.
    ///
    /// A message that is absent is simply not in it, which is how a classical exchange (no ciphertexts) differs from a
    /// hybrid one.
    ///
    /// - Returns: `nil` unless both phones' discovery and identity messages are present, there is at most one message for
    ///   a step and role, and the ciphertexts are both present or both absent.
    public static func transcript(_ messages: [Message]) -> Data? {
        var seen = Set<UInt8>()
        for message in messages {
            guard seen.insert(message.step.rawValue << 1 | message.role.rawValue).inserted else { return nil }
            guard UInt32(exactly: message.bytes.count) != nil else { return nil }
        }
        func has(_ step: Step, _ role: Role) -> Bool { seen.contains(step.rawValue << 1 | role.rawValue) }
        guard has(.discovery, .initiator), has(.discovery, .responder), has(.identity, .initiator), has(.identity, .responder),
              has(.ciphertext, .initiator) == has(.ciphertext, .responder)
        else { return nil }

        var input = Self.transcriptDomain
        for message in messages.sorted(by: { ($0.step.rawValue, $0.role.rawValue) < ($1.step.rawValue, $1.role.rawValue) }) {
            input.append(message.step.rawValue)
            input.append(message.role.rawValue)
            let length = UInt32(message.bytes.count)
            input.append(contentsOf: [UInt8(length >> 24), UInt8((length >> 16) & 0xFF), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
            input.append(message.bytes)
        }
        return Data(SHA256.hash(data: input))
    }
}
