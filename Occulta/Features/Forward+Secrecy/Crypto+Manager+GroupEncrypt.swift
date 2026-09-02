//
//  Crypto+Manager+GroupEncrypt.swift
//  Occulta
//

import Foundation
import CryptoKit

// MARK: - GroupRecipient

/// Value type carrying per-recipient key material for `seal(message:groupID:recipients:)`.
///
/// Built by `ContactManager` from `Contact.Profile` before crossing into the crypto
/// layer — SwiftData is never touched inside the crypto functions.
struct GroupRecipient {
    /// Long-term P-256 identity public key (65-byte x963).
    /// Used for fingerprinting and ECDH on the longTermFallback path.
    let publicKey: Data
    let quantumMaterial: QuantumKeyMaterial?
    /// Contact's oldest stored inbound prekey, popped by the caller before this call.
    /// Non-nil → forward-secret path; nil → longTermFallback.
    let contactPrekey: Prekey?
    /// Outbound prekey batch to include in this recipient's `RecipientPayload`, or nil.
    let pendingBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?

    /// Already tier-padded by the caller (`ContactManager.encryptGroupBundle`) — this
    /// type performs no eligibility or padding logic itself, it just carries whatever
    /// it's given straight into `RecipientPayload`. Defaulted to empty/0 so existing
    /// callers that never mention shard content keep compiling unchanged.
    let shardOperations: [OccultaBundle.ShardOperation]
    let custodyManifest: [UUID]
    let custodyManifestCount: Int
    let expectedShards: [UUID]
    let expectedShardsCount: Int
    /// Whether the caller actually attempted to build `custodyManifest`/
    /// `expectedShards` for this recipient (always both together — see
    /// `RecipientPayload.shardMetadataAttempted` for why this can't be inferred
    /// from the two count fields alone). Defaults to `false` so existing callers
    /// that never mention shard content keep compiling unchanged and correctly
    /// report "not attempted".
    let shardMetadataAttempted: Bool

    /// Whether this recipient's build verifies `senderEphemeralSignature` over the
    /// domain-separated payload rather than the bare ephemeral public key — i.e. whether
    /// their tier is at least `.prefixedSenderSignatureCapable`.
    ///
    /// Resolved by the caller, like every other field here; this type carries decisions, it
    /// does not make them. Defaults to `false`, which is both the backward-compatible answer
    /// and the safe one for a caller that forgets: signing bare is understood by every build
    /// that understands the signature at all, whereas prefixing for a recipient who cannot
    /// verify it renders the message unopenable.
    let prefixesEphemeralSignature: Bool

    init(
        publicKey: Data,
        quantumMaterial: QuantumKeyMaterial?,
        contactPrekey: Prekey?,
        pendingBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?,
        shardOperations: [OccultaBundle.ShardOperation] = [],
        custodyManifest: [UUID] = [],
        custodyManifestCount: Int = 0,
        expectedShards: [UUID] = [],
        expectedShardsCount: Int = 0,
        shardMetadataAttempted: Bool = false,
        prefixesEphemeralSignature: Bool = false
    ) {
        self.publicKey              = publicKey
        self.quantumMaterial         = quantumMaterial
        self.contactPrekey           = contactPrekey
        self.pendingBatch            = pendingBatch
        self.shardOperations         = shardOperations
        self.custodyManifest         = custodyManifest
        self.custodyManifestCount    = custodyManifestCount
        self.expectedShards          = expectedShards
        self.expectedShardsCount     = expectedShardsCount
        self.shardMetadataAttempted  = shardMetadataAttempted
        self.prefixesEphemeralSignature = prefixesEphemeralSignature
    }
}

// MARK: - Group seal

extension Manager.Crypto {

    /// Convenience overload — builds a minimal `SealedPayload` (message + appVersion only).
    ///
    /// Use `seal(sealedPayload:groupID:recipients:)` directly when the payload also needs
    /// shard operations, a custody manifest, or expected-shard fields.
    func seal(
        message: Data,
        groupID: UUID,
        recipients: [GroupRecipient]
    ) throws -> OccultaBundle {
        let payload = OccultaBundle.SealedPayload(message: message, appVersion: Bundle.main.appVersion)
        return try self.seal(sealedPayload: payload, groupID: groupID, recipients: recipients)
    }

    /// Seal a pre-built `SealedPayload` for one or more recipients using the group bundle format.
    ///
    /// This is the canonical seal path for all 1.9.0+ sends, including 1:1 messages
    /// (where `recipients` has a single entry and `groupID` is an ephemeral UUID
    /// discarded after the call). Named-group sends pass a stable stored UUID and
    /// the active layer's full member list.
    ///
    /// ## Why one shared ciphertext
    /// The payload is sealed once under a random 256-bit session key. The session key is
    /// then wrapped individually for each recipient, so each recipient pays one ECDH
    /// round-trip while the bulk ciphertext is never duplicated.
    ///
    /// ## Outer AAD
    /// `computeAdditionalAuthentication(version: .v4, secrecy: outerSecrecy)` ‖ `blind`
    ///
    /// `blind` is derived from the group UUID, so cross-group replay is prevented without
    /// exposing the stable group identity in any cleartext field.
    ///
    /// ## Per-recipient AAD
    /// `blind`
    ///
    /// Binds the wrapped session key to this specific bundle. No cleartext recipient
    /// identity is included — receivers find their slot by trial-decryption, preventing
    /// passive observers from confirming membership without the wrapping key.
    ///
    /// ## Per-recipient key path
    /// `contactPrekey != nil` → FS: ECDH(senderEphemeral, contactPrekey.publicKey) [+ ML-KEM]
    /// `contactPrekey == nil` → fallback: ECDH(senderLongTerm, r.publicKey) [+ ML-KEM]
    ///
    /// The caller is responsible for enforcing FS when required (e.g. shard ops).
    func seal(
        sealedPayload: OccultaBundle.SealedPayload,
        groupID: UUID,
        recipients: [GroupRecipient]
    ) throws -> OccultaBundle {
        guard !recipients.isEmpty else { throw EncryptionError.noRecipients }

        let sessionKey     = SymmetricKey(size: .bits256)
        let sessionKeyData = sessionKey.withUnsafeBytes { Data($0) }

        let senderPub = try self.keyManager.retrieveIdentity()
        let senderProof = Data(HMAC<SHA256>.authenticationCode(for: senderPub, using: sessionKey))

        // Per-bundle group blind: HMAC(key: groupID.rawBytes, msg: blindNonce).
        // A fresh nonce per bundle produces a different blind each time, so a passive
        // observer cannot cluster bundles by group identity from the cleartext TLV.
        // The stable groupID is stored inside the encrypted SealedPayload only.
        let blindNonce   = try OccultaBundle.SecrecyContext.generateNonce()
        let groupIDBytes = withUnsafeBytes(of: groupID.uuid) { Data($0) }
        let blind        = Data(HMAC<SHA256>.authenticationCode(
            for: blindNonce, using: SymmetricKey(data: groupIDBytes)
        ))

        let authenticatedPayload = OccultaBundle.SealedPayload(
            message:           sealedPayload.message,
            prekeyBatch:       sealedPayload.prekeyBatch,
            identityChallenge: sealedPayload.identityChallenge,
            shardOperations:   sealedPayload.shardOperations,
            custodyManifest:   sealedPayload.custodyManifest,
            expectedShards:    sealedPayload.expectedShards,
            appVersion:        sealedPayload.appVersion,
            senderProof:       senderProof,
            groupID:           groupID
        )

        let outerSecrecy = OccultaBundle.SecrecyContext(
            mode: .group, ephemeralPublicKey: Data(), prekeyID: nil
        )

        var outerAAD = try OccultaBundle.computeAdditionalAuthentication(version: .v4, secrecy: outerSecrecy)
        outerAAD.append(blind)

        let payloadData = try WireHandle.encode(payload: authenticatedPayload)

        guard let ciphertext = try AES.GCM.seal(
            payloadData, using: sessionKey, nonce: AES.GCM.Nonce(), authenticating: outerAAD
        ).combined else { throw EncryptionError.sealFailed }

        let outerNonce = try OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(for: senderPub, nonce: outerNonce)

        let recipientEntries = try recipients.map { r in
            try self.wrapRecipient(r, sessionKeyData: sessionKeyData, blind: blind)
        }

        let envelope = OccultaBundle.GroupEnvelope(blind: blind, blindNonce: blindNonce, recipients: recipientEntries)
        return OccultaBundle(
            version: .v4,
            secrecy: outerSecrecy,
            ciphertext: ciphertext,
            fingerprintNonce: outerNonce,
            senderFingerprint: senderFingerprint,
            group: envelope
        )
    }

    private func wrapRecipient(
        _ r: GroupRecipient,
        sessionKeyData: Data,
        blind: Data
    ) throws -> OccultaBundle.Recipient {
        guard r.publicKey.count == 65 else { throw EncryptionError.invalidRecipientMaterial }

        let (wrappingKey, secrecyContext) = try self.deriveOutboundKey(
            contactPrekey: r.contactPrekey,
            recipientPublicKey: r.publicKey,
            quantumMaterial: r.quantumMaterial
        )

        // FS mode's session key is ECDH(senderEphemeral, recipientPrekey) — it never
        // involves our long-term identity, so senderProof alone doesn't prove we sent
        // this (see finding #8, SecurityReview2026-07-24). Sign the ephemeral key with
        // our real identity so the recipient can verify it. Fallback mode's wrapping
        // ECDH already requires our long-term private key, so it doesn't need a real
        // one — but it still gets random filler of the same size, matching this
        // codebase's forensic-neutrality pattern elsewhere (verifierFillerArray,
        // pinEnabledFillerArray, shard tier-padding): otherwise this field's mere
        // presence/size would let a mixed-mode group send distinguish FS from
        // fallback recipients by RecipientPayload size alone.
        let senderEphemeralSignature: Data
        switch secrecyContext.mode {
        case .forwardSecret, .forwardSecretNoPQ:
            // Domain-separated only for recipients who can verify it that way. Prefixing
            // unconditionally would make every message unopenable by 1.10.0/1.10.1, which
            // verify against the bare key — a break in the one direction we cannot patch,
            // since those installs are already deployed. See `.prefixedSenderSignatureCapable`.
            senderEphemeralSignature = try self.keyManager.signData(
                r.prefixesEphemeralSignature
                    ? Self.ephemeralSignaturePayload(secrecyContext.ephemeralPublicKey)
                    : secrecyContext.ephemeralPublicKey
            )
        case .longTermFallback, .longTermNoPQ, .group, .unsupported:
            senderEphemeralSignature = Self.randomEphemeralSignatureFiller()
        }

        let payload = OccultaBundle.RecipientPayload(
            sessionKey:               sessionKeyData,
            prekeyBatch:              r.pendingBatch,
            shardOperations:          r.shardOperations,
            custodyManifest:          r.custodyManifest,
            custodyManifestCount:     r.custodyManifestCount,
            expectedShards:           r.expectedShards,
            expectedShardsCount:      r.expectedShardsCount,
            shardMetadataAttempted:   r.shardMetadataAttempted,
            senderEphemeralSignature: senderEphemeralSignature
        )
        let encodedPayload = try JSONEncoder().encode(payload)

        guard let wrappedPayload = try AES.GCM.seal(
            encodedPayload, using: wrappingKey, nonce: AES.GCM.Nonce(), authenticating: blind
        ).combined else { throw EncryptionError.sealFailed }

        return OccultaBundle.Recipient(secrecyContext: secrecyContext, wrappedPayload: wrappedPayload)
    }

    /// Domain-separation prefix for `senderEphemeralSignature`.
    ///
    /// Every other use of the identity key carries one — `"occulta-identity-challenge-v1"` for
    /// challenges, `"occulta-signed-attribute-v2"` for vault attributes — and this one did not.
    /// A signature records nothing about the context that produced it; only the bytes decide,
    /// so two sites that can produce identical bytes produce interchangeable signatures. The
    /// bare form collided with nothing in practice, because an X9.63 point starts `0x04` while
    /// both prefixes start with ASCII `o`, but the collision space was exactly "65-byte P-256
    /// public key" — a shape this app handles constantly — and the safety was one call site
    /// deep. See §3.6 of `Docs/Audit/SECURITY_CHECKLIST.md`.
    static let ephemeralSignatureDomain = Data("occulta-sender-ephemeral-v1".utf8)

    /// The bytes signed for a domain-separated `senderEphemeralSignature`.
    /// Shared with `verifySenderEphemeralSignature` so the two cannot drift.
    static func ephemeralSignaturePayload(_ ephemeralPublicKey: Data) -> Data {
        var payload = Self.ephemeralSignatureDomain
        payload.append(ephemeralPublicKey)
        return payload
    }

    /// Random bytes matching the maximum size of a DER-encoded P-256 ECDSA signature
    /// (SEQUENCE of two up-to-33-byte INTEGERs + headers = 72 bytes). Real signatures
    /// can be a byte or two shorter when `r`/`s` don't need their padding byte — the
    /// same residual size variance already accepted elsewhere for DER signatures in
    /// this codebase (see `GroupShardGatingTests`).
    ///
    /// ⚠️ That variance is not actually residual here, and the reason is load-bearing:
    /// `RecipientPayload` is JSON-encoded, `JSONEncoder` emits `Data` as base64, and 70, 71
    /// and 72 bytes all base64 to exactly 96 characters — they share a 24-group boundary. So
    /// FS and fallback slots come out byte-identical in size, not merely close, and a
    /// mixed-mode group send leaks nothing through `wrappedPayload` length.
    ///
    /// The uniformity therefore comes from base64 grouping, not from this length. If
    /// `RecipientPayload` ever moves off `JSONEncoder` — this codebase already has a binary
    /// encoder in `WireHandle`, used for v4 baskets — the 70/71/72 spread becomes directly
    /// observable and this filler stops doing its job. Pad to the real signature's length at
    /// that point, or keep the encoding.
    private static func randomEphemeralSignatureFiller() -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<72).map { _ in UInt8.random(in: 0...255, using: &rng) })
    }
}
