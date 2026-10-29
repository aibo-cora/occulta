//
//  Crypto+Manager+GroupEncrypt.swift
//  Occulta
//

import Foundation
import CryptoKit
import OccultaFormats

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
    /// Contact's oldest stored inbound prekey, popped by the caller before this call, or their last-resort key.
    /// Non-nil → forward-secret path; nil → longTermFallback.
    let contactPrekey: Prekey?
    /// Whether `contactPrekey` is the contact's last-resort key (prekey continuity §3.1): its ID is then never
    /// written in the slot's `prekeyID`, a value derived from it and the ephemeral key is. Defaults to `false`,
    /// a one-time key.
    let contactPrekeyIsLastResort: Bool
    /// Outbound prekey batch to include in this recipient's `RecipientPayload`, or nil.
    let pendingBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?

    /// Already tier-padded by the caller (`ContactManager.encryptGroupBundle`) — this
    /// type performs no eligibility or padding logic itself, it just carries whatever
    /// it's given straight into `RecipientPayload`. Defaulted to empty/0 so existing
    /// callers that never mention shard content keep compiling unchanged.
    ///
    /// No custody manifest: group recipients are always sent
    /// `shardMetadataAttempted = false` (`RecipientPayload.shardMetadataAttempted`,
    /// `bugs.md` Bug 141), so there is nothing to carry.
    let shardOperations: [OccultaBundle.ShardOperation]

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

    /// Non-nil for a card conversation's recipient (`CardSlot`): `publicKey` is then the peer's card agreement key
    /// and the slot is built by `wrapCardRecipient`. Nil for every other recipient.
    let card: CardSlot?

    init(
        publicKey: Data,
        quantumMaterial: QuantumKeyMaterial?,
        contactPrekey: Prekey?,
        contactPrekeyIsLastResort: Bool = false,
        pendingBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?,
        shardOperations: [OccultaBundle.ShardOperation] = [],
        prefixesEphemeralSignature: Bool = false,
        card: CardSlot? = nil
    ) {
        self.publicKey              = publicKey
        self.quantumMaterial         = quantumMaterial
        self.contactPrekey           = contactPrekey
        self.contactPrekeyIsLastResort = contactPrekeyIsLastResort
        self.pendingBatch            = pendingBatch
        self.shardOperations         = shardOperations
        self.prefixesEphemeralSignature = prefixesEphemeralSignature
        self.card                    = card
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
    /// `blind` doesn't bind the slot to the body, which every recipient can re-encrypt: the
    /// slot's `RecipientPayload.bodyDigest` does (`bugs.md` Bug 165).
    ///
    /// ## Per-recipient key path
    /// `contactPrekey != nil` → FS: ECDH(senderEphemeral, contactPrekey.publicKey) [+ ML-KEM]
    /// `contactPrekey == nil` → fallback: ECDH(senderLongTerm, r.publicKey) [+ ML-KEM]
    ///
    /// The caller is responsible for enforcing FS when required (e.g. shard ops).
    ///
    /// `senderIdentity` replaces the long-term identity key in `senderFingerprint` and `senderProof`; a card
    /// conversation passes the sender's card agreement key (`SPEC.md` §3).
    func seal(
        sealedPayload: OccultaBundle.SealedPayload,
        groupID: UUID,
        recipients: [GroupRecipient],
        senderIdentity: Data? = nil
    ) throws -> OccultaBundle {
        let context = try self.groupSealContext(
            sealedPayload: sealedPayload, groupID: groupID, recipients: recipients, senderIdentity: senderIdentity
        )

        var outerAAD = try OccultaBundle.computeAdditionalAuthentication(version: .v4, secrecy: context.outerSecrecy)
        outerAAD.append(context.blind)

        let payloadData = try WireHandle.encode(payload: context.payload)

        guard let ciphertext = try AES.GCM.seal(
            payloadData, using: context.sessionKey, nonce: AES.GCM.Nonce(), authenticating: outerAAD
        ).combined else { throw EncryptionError.sealFailed }

        // Every recipient holds the session key, so each slot commits to the body it unlocks; without this a
        // recipient could put a body of their own behind the others' slots (bugs.md Bug 165).
        let bodyDigest = Data(SHA256.hash(data: ciphertext))

        return OccultaBundle(
            version: .v4,
            secrecy: context.outerSecrecy,
            ciphertext: ciphertext,
            fingerprintNonce: context.outerNonce,
            senderFingerprint: context.senderFingerprint,
            group: try self.groupEnvelope(for: recipients, context: context, bodyDigest: bodyDigest)
        )
    }

    /// The streamed layout's seal (`STREAMING_SPEC.md` §8.3): the same steps as `seal(sealedPayload:...)`, but the
    /// body is a chunk stream written to `files.destination` as it is sealed, so it is never in memory whole.
    ///
    /// `sealedPayload.message` is the basket with each streamed file's `streamedLength` and no content (or the
    /// message of a bundle that carries no basket); `files.sources` are the streamed files' bytes, in the order
    /// the basket lists them. The file is written in full or not at all: a failure removes it.
    func sealStreamed(
        sealedPayload: OccultaBundle.SealedPayload,
        groupID: UUID,
        recipients: [GroupRecipient],
        senderIdentity: Data? = nil,
        files: StreamedFiles
    ) throws {
        let context = try self.groupSealContext(
            sealedPayload: sealedPayload, groupID: groupID, recipients: recipients, senderIdentity: senderIdentity
        )

        // The manifest, framed, and the length of everything the stream will hold.
        let manifest = try BodyStream.Manifest.frame(payload: context.payload)
        var plaintextLength = UInt64(manifest.count)
        for source in files.sources { plaintextLength += source.length }
        let layout = try BodyStream.Layout(plaintextLength: plaintextLength)

        // The header first: it names the stream's length. The slots need the digest, so they and the sections
        // come last, after the stream.
        let envelope = OccultaBundle(
            version: .streamedBodyCapable, secrecy: context.outerSecrecy, ciphertext: Data(),
            fingerprintNonce: context.outerNonce, senderFingerprint: context.senderFingerprint
        )
        let writer = try NoCacheFile.writer(files.destination)
        do {
            try writer.write(try WireHandle.encodeHeader(envelope, ciphertextLength: layout.streamLength))

            var sealer = BodyStream.Sealer(
                sessionKey: context.sessionKey,
                header: try BodyStream.headerAAD(secrecy: context.outerSecrecy, blind: context.blind),
                layout: layout
            )
            try sealer.append(manifest) { try writer.write($0) }
            for source in files.sources {
                var delivered: UInt64 = 0
                try source.feed { piece in
                    delivered += UInt64(piece.count)
                    guard delivered <= source.length else { throw BodyStream.StreamError.lengthMismatch }
                    try sealer.append(piece) { try writer.write($0) }
                }
                // A file that changed under us, or one whose header lied, must not become a bundle that fails to open.
                guard delivered == source.length else { throw BodyStream.StreamError.lengthMismatch }
            }
            let digest = try sealer.finish { try writer.write($0) }

            let bundle = OccultaBundle(
                version: .streamedBodyCapable, secrecy: context.outerSecrecy, ciphertext: Data(),
                fingerprintNonce: context.outerNonce, senderFingerprint: context.senderFingerprint,
                group: try self.groupEnvelope(for: recipients, context: context, bodyDigest: digest)
            )
            try writer.write(try WireHandle.encodeSections(bundle))
            try writer.finish()
        } catch {
            writer.abandon()
            throw error
        }
    }

    /// What both layouts' seals start from: a fresh session key, the sender proof and the per-bundle blind.
    private struct GroupSealContext {
        let sessionKey: SymmetricKey
        let senderPublicKey: Data
        let blindNonce: Data
        let blind: Data
        let payload: OccultaBundle.SealedPayload
        let outerSecrecy: OccultaBundle.SecrecyContext
        let outerNonce: Data
        let senderFingerprint: Data
    }

    private func groupSealContext(
        sealedPayload: OccultaBundle.SealedPayload,
        groupID: UUID,
        recipients: [GroupRecipient],
        senderIdentity: Data?
    ) throws -> GroupSealContext {
        guard !recipients.isEmpty else { throw EncryptionError.noRecipients }

        let sessionKey = SymmetricKey(size: .bits256)

        let senderPub = try senderIdentity ?? self.keyManager.retrieveIdentity()
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
            appVersion:        sealedPayload.appVersion,
            senderProof:       senderProof,
            groupID:           groupID
        )

        let outerSecrecy = OccultaBundle.SecrecyContext(
            mode: .group, ephemeralPublicKey: Data(), prekeyID: nil
        )
        let outerNonce = try OccultaBundle.SecrecyContext.generateNonce()

        return GroupSealContext(
            sessionKey: sessionKey, senderPublicKey: senderPub, blindNonce: blindNonce, blind: blind,
            payload: authenticatedPayload, outerSecrecy: outerSecrecy, outerNonce: outerNonce,
            senderFingerprint: OccultaBundle.SecrecyContext.fingerprint(for: senderPub, nonce: outerNonce)
        )
    }

    private func groupEnvelope(
        for recipients: [GroupRecipient], context: GroupSealContext, bodyDigest: Data
    ) throws -> OccultaBundle.GroupEnvelope {
        let sessionKeyData = context.sessionKey.withUnsafeBytes { Data($0) }
        let entries = try recipients.map { r in
            try self.wrapRecipient(r, sessionKeyData: sessionKeyData, blind: context.blind, bodyDigest: bodyDigest)
        }
        return OccultaBundle.GroupEnvelope(blind: context.blind, blindNonce: context.blindNonce, recipients: entries)
    }

    func wrapRecipient(
        _ r: GroupRecipient,
        sessionKeyData: Data,
        blind: Data,
        bodyDigest: Data
    ) throws -> OccultaBundle.Recipient {
        guard r.publicKey.count == 65 else { throw EncryptionError.invalidRecipientMaterial }
        if let card = r.card {
            return try self.wrapCardRecipient(r, card: card, sessionKeyData: sessionKeyData, blind: blind, bodyDigest: bodyDigest)
        }

        let (wrappingKey, secrecyContext) = try self.deriveOutboundKey(
            contactPrekey: r.contactPrekey,
            isLastResort: r.contactPrekeyIsLastResort,
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
            // Always false: a v1.10.3 receiver reads true with no expected-shards list
            // as "delete every piece you hold from me" (bugs.md Bug 141).
            shardMetadataAttempted:   false,
            senderEphemeralSignature: senderEphemeralSignature,
            bodyDigest:               bodyDigest
        )
        // Sorted keys, so the same payload always encodes to the same bytes. It is sealed, so
        // the order was never observable, but a default JSONEncoder's order changes with every
        // app launch and can't be pinned by the interop vectors.
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let encodedPayload = try encoder.encode(payload)

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
    static func randomEphemeralSignatureFiller() -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<72).map { _ in UInt8.random(in: 0...255, using: &rng) })
    }
}

// MARK: - Streamed files

/// A streamed bundle's destination, and the files whose bytes follow its manifest.
struct StreamedFiles {
    let destination: URL
    /// In the order the basket lists the streamed files.
    let sources: [StreamedFileSource]
}

/// One streamed file: how long it is, and a way to read it a piece at a time.
struct StreamedFileSource {
    /// Plaintext bytes `feed` delivers. A source that delivers any other count fails the send.
    let length: UInt64
    let feed: (_ emit: (Data) throws -> Void) throws -> Void
}
