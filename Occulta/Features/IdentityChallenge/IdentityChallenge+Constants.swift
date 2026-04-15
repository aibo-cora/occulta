//
//  IdentityChallenge+Constants.swift
//  Occulta
//

import Foundation

enum IdentityChallenge {
    /// Domain prefix for ECDSA signing — prevents cross-feature signature acceptance.
    /// Document Signing (future) MUST use a different prefix.
    /// Changing this string invalidates all previously issued challenges. Do it never.
    static let domainPrefix = "occulta-identity-challenge-v1"

    /// Challenge nonce length in bytes.
    static let nonceLength = 32

    /// Challenger-enforced verification window (seconds).
    static let timestampWindow: TimeInterval = 300

    /// Responder-side soft lower bound for stale rejection (seconds). Not security-critical.
    static let timestampStaleThreshold: TimeInterval = 3600

    /// Responder-side soft upper bound grace for clock skew (seconds). Not security-critical.
    static let clockSkewGrace: TimeInterval = 30

    /// Maximum outstanding challenges per contact.
    static let maxOutstandingPerContact = 1

    // MARK: - Fallback messages

    /// Fallback text shown by old Occulta builds that predate identity challenges.
    /// Such builds decode `SealedPayload` without `contentType` / `contentData` and
    /// render `message` as a regular text message. The strings are intentionally
    /// short, non-alarming, and actionable. The `[Occulta]` prefix helps the reader
    /// distinguish it from text their contact typed.
    static let challengeFallbackMessage = "[Occulta] This is an identity verification request. Update Occulta to respond."
    static let responseFallbackMessage  = "[Occulta] This is an identity verification response. Update Occulta to verify."
}
