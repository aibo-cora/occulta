//
//  IdentityChallenge+Envelope.swift
//  Occulta
//
//  Groups the three identity-challenge wire fields — phase discriminator,
//  binary payload, and optional context note — into a single Codable struct
//  nested inside `SealedPayload.identityChallenge`.
//
//  ## Why a struct, not three siblings
//
//  Previously `SealedPayload` carried `contentType: ContentType?`,
//  `contentData: Data?`, and `contextNote: String?` as three parallel
//  optionals. That shape let a malformed decoder produce nonsense states
//  ("response with a contextNote", "contentData without a contentType") and
//  every routing call site had to re-check the invariant. Bundling them
//  makes "kind and payload travel together" a type-level guarantee: the
//  routing check is one optional unwrap, and the factories below keep the
//  `Kind == .response => contextNote == nil` rule in a single place.
//
//  Future per-feature envelopes (Document Signing, etc.) should follow the
//  same pattern — a separate `documentSigning: DocumentSigningEnvelope?`
//  field rather than piling on more siblings inside the shared SealedPayload.
//

import Foundation

// MARK: - IdentityChallengeEnvelope

/// The identity-challenge block inside `OccultaBundle.SealedPayload`.
///
/// `nil` on the SealedPayload means "this is a regular message" — routing
/// to the identity manager happens iff this envelope is present.
struct IdentityChallengeEnvelope: Codable, Equatable {

    /// Phase discriminator. Raw values are stable wire strings — never
    /// rename or reorder without a wire-format migration.
    enum Kind: String, Codable {
        case challenge
        case response
    }

    /// Which of the two identity-challenge phases this envelope carries.
    let kind: Kind

    /// Binary payload for this phase. Challenge → 72-byte `ChallengePayload`
    /// encoding; response → 32-byte nonce + DER signature.
    let payload: Data

    /// Optional freetext question from the challenger. Always `nil` on a
    /// response — enforced by the `.response(payload:)` factory.
    ///
    /// Encrypted inside the SealedPayload (invisible to observers) and
    /// authenticated by GCM, but NOT included in the ECDSA-signed data:
    /// keeping user-typed freetext out of the signature eliminates a
    /// signing-oracle class of attack. Capped at
    /// `IdentityChallenge.maxContextNoteBytes` UTF-8 bytes.
    let contextNote: String?

    // MARK: - Factories
    //
    // Prefer these over the memberwise init so the kind/contextNote
    // invariant can't be bypassed at a call site.

    /// Build a phase-1 challenge envelope.
    static func challenge(payload: Data, contextNote: String?) -> Self {
        Self(kind: .challenge, payload: payload, contextNote: contextNote)
    }

    /// Build a phase-2 response envelope. A response never carries a
    /// contextNote — forced nil here so the rule lives in one place.
    static func response(payload: Data) -> Self {
        Self(kind: .response, payload: payload, contextNote: nil)
    }
}
