//
//  IdentityChallenge+Manager.swift
//  Occulta
//
//  The three-phase lifecycle of an identity challenge:
//    1. Challenger → createChallenge(for:)               → outbound OccultaBundle
//    2. Responder  → decryptChallenge(bundle:contacts:)  → PendingApproval
//                  → respond(to:)                        → outbound OccultaBundle
//    3. Challenger → verifyResponse(bundle:contacts:)    → Bool (pass/fail)
//
//  Only the long-term key derivation path is used — identity verification must
//  never fail because of prekey exhaustion.
//
//  ⚠️ Wire compatibility: challenge bundles ride on `Version.v3fs` +
//  `Mode.longTermFallback` — values every shipped Occulta build already decodes.
//  Routing to this manager happens via `SealedPayload.identityChallenge`
//  *after* decryption, so old builds that don't know about identity challenges
//  simply render the human-readable fallback string in `SealedPayload.message`.
//

import Foundation
import CryptoKit
import Security

extension IdentityChallenge {

    // MARK: - ContactView

    /// The subset of a contact's state this feature needs.
    ///
    /// A plain struct — not `Contact.Profile` — so protocol tests can construct
    /// fixtures without SwiftData, and so this feature has no dependency on the
    /// contact persistence layer.
    struct ContactView: Equatable {
        /// Stable per-contact identifier. Used as the contactKeyID in the
        /// outstanding-challenge store.
        let identifier: String
        /// x963-uncompressed P-256 long-term public key (65 bytes).
        let publicKey: Data
        /// Display name for the UI only. Never fed into crypto.
        let displayName: String
        /// ML-KEM quantum material from the proximity exchange, if present.
        /// Used to derive hybrid session keys consistent with regular messages.
        let quantumKeyMaterial: QuantumKeyMaterial?
    }

    // MARK: - PendingApproval

    /// Decrypted + well-formed challenge awaiting responder's explicit approval.
    ///
    /// Carries everything `respond(to:)` needs so it can complete without
    /// re-decrypting the bundle or re-searching the contact list.
    struct PendingApproval {
        /// The challenger — matched from the outer `senderFingerprint`.
        let challenger: ContactView
        /// Decoded inner payload.
        let payload: ChallengePayload
        /// Optional freetext from the challenger, shown alongside the approval
        /// prompt so the responder knows what they're being asked about. Plain
        /// text only — never rendered as markdown/HTML/attributed string.
        let contextNote: String?
    }

    // MARK: - Errors

    /// Deliberately coarse-grained — per spec rule 4, failure messages must not
    /// leak which verification step failed (signature, fingerprint, staleness,
    /// nonce lookup). The UI surfaces a single "verification failed" state.
    enum ManagerError: Error {
        /// No identity key is available to sign or derive a session key.
        case noIdentity
        /// Session key derivation returned nil.
        case keyDerivationFailed
        /// The bundle's `senderFingerprint` did not match any known contact.
        case unknownSender
        /// The bundle could not be decrypted or the inner payload did not parse.
        case malformedBundle
        /// Any verification-time rejection: bad signature, stale timestamp,
        /// unknown nonce, wrong responder, tampered inner fingerprint.
        /// Collapsed into one case on purpose — see rule 4.
        case verificationFailed
        /// Per-contact rate limit would be exceeded.
        case rateLimited
    }

    // MARK: - Manager

    /// Three-phase identity-challenge lifecycle.
    ///
    /// Stateless except for the in-memory `OutstandingChallengeStore`.
    /// `@MainActor` because the store is main-actor-isolated.
    @MainActor
    final class Manager {

        private let crypto: Occulta.Manager.Crypto
        private let store:  OutstandingChallengeStore
        private let now:    () -> Date

        /// - Parameters:
        ///   - crypto: The crypto facade. Same instance used elsewhere; no SE
        ///     state is held here.
        ///   - store:  The outstanding-challenge store. Shared across the app
        ///     so phase 3 can find the phase 1 entry.
        ///   - now:    Injectable clock. Tests pass a fixed clock to exercise
        ///     the 5-minute window boundary; production passes `Date.init`.
        init(
            crypto: Occulta.Manager.Crypto,
            store:  OutstandingChallengeStore,
            now:    @escaping () -> Date = Date.init
        ) {
            self.crypto = crypto
            self.store  = store
            self.now    = now
        }

        // MARK: Phase 1 — challenger creates the challenge

        /// Generate a fresh challenge bundle to send to `contact`.
        ///
        /// Side effects:
        ///   - Registers an entry in `store` keyed by `contact.identifier`.
        ///     Throws `.rateLimited` if one is already outstanding for this
        ///     contact.
        ///
        /// The bundle rides on `Version.v3fs` + `Mode.longTermFallback` — values
        /// every shipped Occulta build decodes. Routing discrimination lives in
        /// `SealedPayload.identityChallenge` inside the encrypted envelope.
        func createChallenge(
            for contact: ContactView,
            contextNote: String? = nil
        ) throws -> OccultaBundle {
            // 0. Rate limit first — avoid wasting SE work on a request we'll reject.
            guard !self.store.hasOutstanding(for: contact.identifier) else {
                throw ManagerError.rateLimited
            }

            // Sender-side cap: truncate (do not throw) so the user's question
            // still gets through in a slightly shortened form.
            let sanitizedNote = Self.truncate(
                note: contextNote,
                maxBytes: IdentityChallenge.maxContextNoteBytes
            )

            // 1. Gather our own public key (needed for the inner fingerprint
            //    AND for the outer routing fingerprint).
            let ourPublicKey: Data
            do {
                ourPublicKey = try self.crypto.keyManager.retrieveIdentity()
            } catch {
                throw ManagerError.noIdentity
            }

            // 2. Build the inner ChallengePayload.
            let nonce     = try Self.randomBytes(count: IdentityChallenge.nonceLength)
            let timestamp = UInt64(self.now().timeIntervalSince1970)
            let tsBytes   = IdentityChallenge.encodeTimestamp(timestamp)

            // Inner fingerprint binds the nonce to the challenger's identity.
            // Using the challenge nonce (not the outer fingerprintNonce) so the
            // responder's inner check is independent of the routing fingerprint.
            let challengerFingerprint = OccultaBundle.SecrecyContext.fingerprint(
                for: ourPublicKey,
                nonce: nonce
            )

            let payload = ChallengePayload(
                nonce: nonce,
                timestamp: tsBytes,
                challengerFingerprint: challengerFingerprint
            )

            // 3. Seal the payload for the responder.
            let envelope = IdentityChallengeEnvelope.challenge(
                payload:     payload.encoded(),
                contextNote: sanitizedNote
            )
            let bundle = try self.sealIdentityBundle(
                envelope:        envelope,
                fallbackMessage: IdentityChallenge.challengeFallbackMessage,
                ourPublicKey:    ourPublicKey,
                recipientKey:    contact.publicKey,
                quantumMaterial: contact.quantumKeyMaterial
            )

            // 4. Remember this challenge until the response arrives or expires.
            //    Done LAST so a seal failure doesn't leave a ghost entry.
            try self.store.store(
                .init(
                    nonce:        nonce,
                    timestamp:    timestamp,
                    contactKeyID: contact.identifier,
                    contextNote:  sanitizedNote
                )
            )

            return bundle
        }

        // MARK: Phase 2 — responder decrypts and (later) signs

        /// Decrypt an inbound challenge bundle and verify its framing.
        ///
        /// Performs NO signing — signing requires explicit user approval and
        /// happens in `respond(to:)`. This phase is a pure parse + validate.
        func decryptChallenge(
            bundle:   OccultaBundle,
            contacts: [ContactView]
        ) throws -> PendingApproval {
            // 1. Route by outer senderFingerprint.
            guard let sender = Self.matchSender(bundle: bundle, contacts: contacts) else {
                throw ManagerError.unknownSender
            }

            // 2. Open the bundle and extract the challenge envelope.
            //    A bundle whose envelope is missing or has the wrong kind
            //    has no business in this path.
            let envelope = try self.openIdentityBundle(
                bundle:        bundle,
                peerPublicKey: sender.publicKey,
                peerQuantum:   sender.quantumKeyMaterial,
                expecting:     .challenge
            )
            let payloadBytes = envelope.payload
            let note         = envelope.contextNote

            // Responder-side length enforcement. A compliant sender truncates
            // to `maxContextNoteBytes`; anything larger is treated as malformed.
            if let note, note.utf8.count > IdentityChallenge.maxContextNoteBytes {
                throw ManagerError.malformedBundle
            }

            // 3. Decode the inner ChallengePayload.
            let payload: ChallengePayload
            do {
                payload = try ChallengePayload(from: payloadBytes)
            } catch {
                throw ManagerError.malformedBundle
            }

            // 4. Inner fingerprint must bind to the sender's long-term key.
            //    Prevents a stored-but-misrouted bundle from being accepted.
            let expected = OccultaBundle.SecrecyContext.fingerprint(for: sender.publicKey, nonce: payload.nonce)
            guard expected == payload.challengerFingerprint else {
                throw ManagerError.verificationFailed
            }

            // 5. Soft staleness check — reject obviously old challenges so a
            //    replayed message can't coerce a biometric prompt hours later.
            //    Tolerates moderate clock skew in both directions.
            let nowSec = UInt64(self.now().timeIntervalSince1970)
            guard let ts = try? IdentityChallenge.decodeTimestamp(payload.timestamp) else {
                throw ManagerError.malformedBundle
            }
            if ts > nowSec {
                // Challenge timestamped in the future.
                let skew = TimeInterval(ts - nowSec)
                guard skew <= IdentityChallenge.clockSkewGrace else {
                    throw ManagerError.verificationFailed
                }
            } else {
                let age = TimeInterval(nowSec - ts)
                guard age < IdentityChallenge.timestampStaleThreshold else {
                    throw ManagerError.verificationFailed
                }
            }

            return PendingApproval(challenger: sender, payload: payload, contextNote: note)
        }

        /// Sign the approved challenge and build the response bundle.
        ///
        /// Biometric prompt (in production) fires inside `signChallenge` via
        /// Secure Enclave access control. The caller is responsible for having
        /// surfaced the user-approval UI before invoking this.
        func respond(to pending: PendingApproval) throws -> OccultaBundle {
            let ourPublicKey: Data
            do {
                ourPublicKey = try self.crypto.keyManager.retrieveIdentity()
            } catch {
                throw ManagerError.noIdentity
            }

            let signedData = Occulta.Manager.Crypto.buildSignedData(
                nonce:                 pending.payload.nonce,
                timestamp:             pending.payload.timestamp,
                challengerFingerprint: pending.payload.challengerFingerprint
            )

            let signature = try self.crypto.signChallenge(signedData)

            let response  = ResponsePayload(challengeNonce: pending.payload.nonce, signature: signature)

            // `.response(payload:)` forces contextNote == nil — the rule that
            // responses never carry a note lives inside the factory, not here.
            let envelope = IdentityChallengeEnvelope.response(payload: response.encoded())
            return try self.sealIdentityBundle(
                envelope:        envelope,
                fallbackMessage: IdentityChallenge.responseFallbackMessage,
                ourPublicKey:    ourPublicKey,
                recipientKey:    pending.challenger.publicKey,
                quantumMaterial: pending.challenger.quantumKeyMaterial
            )
        }

        // MARK: Phase 3 — challenger verifies the response

        /// Verify an inbound response bundle. Returns `true` only on a complete,
        /// in-window signature verification against the stored outstanding
        /// challenge. Returns `false` on every other failure mode.
        ///
        /// Removes the outstanding entry on both pass AND fail — a failed
        /// response consumes the one-shot rate-limit slot. This is intentional:
        /// retry must start with a fresh nonce.
        func verifyResponse(
            bundle:   OccultaBundle,
            contacts: [ContactView]
        ) throws -> (ok: Bool, contextNote: String?) {
            guard let sender = Self.matchSender(bundle: bundle, contacts: contacts) else {
                throw ManagerError.unknownSender
            }

            let envelope = try self.openIdentityBundle(
                bundle:        bundle,
                peerPublicKey: sender.publicKey,
                peerQuantum:   sender.quantumKeyMaterial,
                expecting:     .response
            )

            let response: ResponsePayload
            do {
                response = try ResponsePayload(from: envelope.payload)
            } catch {
                throw ManagerError.malformedBundle
            }

            // Look up the outstanding challenge by nonce.
            guard let entry = self.store.lookup(nonce: response.challengeNonce) else {
                // No such challenge — replay, forgery, or expired & removed.
                return (false, nil)
            }

            // Must come from the contact we issued the challenge to.
            // Otherwise a different contact could respond to someone else's
            // challenge and claim their identity.
            guard entry.contactKeyID == sender.identifier else {
                self.store.remove(nonce: response.challengeNonce)
                return (false, entry.contextNote)
            }

            // Hard 5-minute window — stricter than the staleness soft check.
            let nowSec = UInt64(self.now().timeIntervalSince1970)
            // Handle both directions: responder's clock ahead of us is fine
            // up to the same window.
            let delta: TimeInterval = {
                if nowSec >= entry.timestamp {
                    return TimeInterval(nowSec - entry.timestamp)
                } else {
                    return TimeInterval(entry.timestamp - nowSec)
                }
            }()
            guard delta < IdentityChallenge.timestampWindow else {
                self.store.remove(nonce: response.challengeNonce)
                return (false, entry.contextNote)
            }

            // Reconstruct the exact bytes that were signed. Inner fingerprint
            // comes from the challenger's own public key + original nonce —
            // NOT from any responder-supplied field.
            let ourPublicKey: Data
            do {
                ourPublicKey = try self.crypto.keyManager.retrieveIdentity()
            } catch {
                throw ManagerError.noIdentity
            }
            let challengerFingerprint = OccultaBundle.SecrecyContext.fingerprint(
                for: ourPublicKey,
                nonce: entry.nonce
            )
            let tsBytes = IdentityChallenge.encodeTimestamp(entry.timestamp)
            let signedData = Occulta.Manager.Crypto.buildSignedData(
                nonce:                 entry.nonce,
                timestamp:             tsBytes,
                challengerFingerprint: challengerFingerprint
            )

            // Construct a SecKey view over the responder's stored public key.
            guard let publicKey = Self.makePublicKey(x963: sender.publicKey) else {
                self.store.remove(nonce: response.challengeNonce)
                return (false, entry.contextNote)
            }

            let ok = self.crypto.verifyChallenge(signedData, signature: response.signature, publicKey: publicKey)

            // Snapshot the note BEFORE consuming the slot so the caller can
            // render "you asked X — verified" even after removal.
            let note = entry.contextNote

            // One-shot: consume the slot regardless of outcome.
            self.store.remove(nonce: response.challengeNonce)
            return (ok, note)
        }

        // MARK: - Private helpers

        /// Build an OccultaBundle for the identity-challenge protocol.
        ///
        /// Wire envelope is deliberately indistinguishable from a regular
        /// long-term-fallback message: `version = .v3fs`, `mode = .longTermFallback`.
        /// The identity-challenge envelope lives inside the encrypted payload,
        /// so old decoders render `fallbackMessage` as a normal text message
        /// and new decoders route on `SealedPayload.identityChallenge`.
        private func sealIdentityBundle(
            envelope:        IdentityChallengeEnvelope,
            fallbackMessage: String,
            ourPublicKey:    Data,
            recipientKey:    Data,
            quantumMaterial: QuantumKeyMaterial? = nil
        ) throws -> OccultaBundle {
            let sealed = OccultaBundle.SealedPayload(
                message:           Data(fallbackMessage.utf8),
                prekeyBatch:       nil,
                identityChallenge: envelope
            )
            let encodedSealed: Data
            do {
                encodedSealed = try JSONEncoder().encode(sealed)
            } catch {
                throw ManagerError.malformedBundle
            }

            guard let sessionKey = self.crypto.deriveSessionKey(using: recipientKey, quantumMaterial: quantumMaterial) else {
                throw ManagerError.keyDerivationFailed
            }

            let secrecy = OccultaBundle.SecrecyContext(
                mode:               .longTermFallback,
                ephemeralPublicKey: Data(),
                prekeyID:           nil
            )

            let version = OccultaBundle.Version.v3fs
            let aad = try OccultaBundle.computeAdditionalAuthentication(version: version, secrecy: secrecy)

            let ciphertext: Data
            do {
                let box = try AES.GCM.seal(encodedSealed, using: sessionKey, nonce: AES.GCM.Nonce(), authenticating: aad)
                guard let combined = box.combined else { throw ManagerError.malformedBundle }
                ciphertext = combined
            } catch {
                throw ManagerError.malformedBundle
            }

            let fingerprintNonce  = try OccultaBundle.SecrecyContext.generateNonce()
            let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(
                for: ourPublicKey,
                nonce: fingerprintNonce
            )

            return OccultaBundle(
                version:           version,
                secrecy:           secrecy,
                ciphertext:        ciphertext,
                fingerprintNonce:  fingerprintNonce,
                senderFingerprint: senderFingerprint
            )
        }

        /// Open an identity-challenge bundle and return its
        /// `IdentityChallengeEnvelope`.
        ///
        /// Rejects bundles whose envelope is missing or whose `kind` does not
        /// match `expecting` — e.g. a challenge bundle offered to the response
        /// verifier.
        private func openIdentityBundle(
            bundle:          OccultaBundle,
            peerPublicKey:   Data,
            peerQuantum:     QuantumKeyMaterial? = nil,
            expecting:       IdentityChallengeEnvelope.Kind
        ) throws -> IdentityChallengeEnvelope {
            // Reject unsupported versions/modes up-front — never derive a key or
            // compute AAD for a bundle we fundamentally can't process.
            guard bundle.version      != .unsupported else { throw ManagerError.malformedBundle }
            guard bundle.secrecy.mode != .unsupported else { throw ManagerError.malformedBundle }

            guard let sessionKey = self.crypto.deriveSessionKey(using: peerPublicKey, quantumMaterial: peerQuantum) else {
                throw ManagerError.keyDerivationFailed
            }
            let plaintext: Data
            do {
                plaintext = try self.crypto.open(bundle, using: sessionKey)
            } catch {
                throw ManagerError.malformedBundle
            }
            let sealed: OccultaBundle.SealedPayload
            do {
                sealed = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: plaintext)
            } catch {
                throw ManagerError.malformedBundle
            }
            guard let envelope = sealed.identityChallenge, envelope.kind == expecting else {
                throw ManagerError.malformedBundle
            }
            return envelope
        }

        /// Truncate `note` so its UTF-8 encoding is at most `maxBytes` bytes.
        /// Drops trailing bytes at a scalar boundary — never produces invalid
        /// UTF-8. An empty string round-trips to `nil` so absent and empty
        /// are treated the same on the wire.
        static func truncate(note: String?, maxBytes: Int) -> String? {
            guard let note, !note.isEmpty else { return nil }
            if note.utf8.count <= maxBytes { return note }

            // Walk unicode scalars, appending while we stay under the cap.
            var out = ""
            var used = 0
            for scalar in note.unicodeScalars {
                let add = String(scalar).utf8.count
                if used + add > maxBytes { break }
                out.unicodeScalars.append(scalar)
                used += add
            }
            return out.isEmpty ? nil : out
        }

        /// Routing — find the contact whose `senderFingerprint` matches the bundle.
        private static func matchSender(bundle: OccultaBundle, contacts: [ContactView]) -> ContactView? {
            for c in contacts {
                let fp = OccultaBundle.SecrecyContext.fingerprint(for: c.publicKey, nonce: bundle.fingerprintNonce)
                if fp == bundle.senderFingerprint { return c }
            }
            return nil
        }

        private static func makePublicKey(x963: Data) -> SecKey? {
            let attrs: [String: Any] = [
                kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 256
            ]
            var err: Unmanaged<CFError>?
            return SecKeyCreateWithData(x963 as CFData, attrs as CFDictionary, &err)
        }

        private static func randomBytes(count: Int) throws -> Data {
            var bytes = [UInt8](repeating: 0, count: count)
            guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
                throw OccultaBundle.BundleError.entropyUnavailable
            }
            return Data(bytes)
        }
    }
}
