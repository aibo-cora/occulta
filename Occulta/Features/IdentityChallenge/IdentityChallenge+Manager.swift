//
//  IdentityChallenge+Manager.swift
//  Occulta
//
//  The three-phase lifecycle of an identity challenge:
//    1. Challenger → createChallenge(recipientKey:recipientQuantum:contactID:)          → outbound OccultaBundle
//    2. Responder  → decryptChallenge(bundle:senderKey:senderQuantum:senderID:senderName:) → PendingApproval
//                  → respond(to:)                                                        → outbound OccultaBundle
//    3. Challenger → verifyResponse(bundle:senderKey:senderQuantum:senderID:)           → VerificationResult
//
//  Two formats (prekey continuity §3.4). To a contact at `.bodyDigestCapable`, a
//  challenge or response goes as a group bundle through `ContactManager.encryptBundle`,
//  like a message: a one-time key, else the contact's last-resort key, else the
//  long-term key, so verification never fails because of prekey exhaustion. The
//  caller picks that path with the `seal:` variants of `createChallenge` and
//  `respond`; it arrives through `ContactManager.openGroup` as
//  `IdentityChallenge.Authenticated`, and the `envelope:` variants check it.
//
//  ⚠️ To an older contact, the long-term format: challenge bundles ride on
//  `Version.v3fs` + `Mode.longTermFallback` — values every shipped Occulta build
//  already decodes. Routing to this manager happens via `SealedPayload.identityChallenge`
//  *after* decryption, so old builds that don't know about identity challenges
//  simply render the human-readable fallback string in `SealedPayload.message`.
//

import Foundation
import CryptoKit
import Security
import OccultaFormats

extension IdentityChallenge {

    // MARK: - PendingApproval

    /// Decrypted + well-formed challenge awaiting responder's explicit approval.
    ///
    /// Carries everything `respond(to:)` needs so it can complete without
    /// re-decrypting the bundle.
    struct PendingApproval {
        let challengerID:        String
        let challengerName:      String
        let challengerPublicKey: Data
        let challengerQuantum:   QuantumKeyMaterial?
        /// Decoded inner payload.
        let payload:             ChallengePayload
        /// Optional freetext from the challenger. Plain text only — never
        /// rendered as markdown/HTML/attributed string.
        let contextNote:         String?
    }

    // MARK: - VerificationResult

    /// What a response says about the challenge it names.
    enum VerificationResult: Equatable {
        /// It answers our challenge to this contact, signed by their identity key in time.
        case passed(contextNote: String?)
        /// It names our challenge to this contact, and the signature or the time window fails.
        case failed(contextNote: String?)
        /// It names no challenge waiting for this contact: an old response reopened, or one to a challenge we never
        /// sent them. Says nothing about the contact, so it must show nothing (`bugs.md` Bug 166).
        case notOurs
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
    /// Stateless except for the context notes, which stay in memory, and the `ChallengeLedger`, which says
    /// which challenges are outstanding for the session that is open now.
    /// `@MainActor` because the ledger is main-actor-isolated.
    @MainActor
    final class Manager {

        private let crypto: Occulta.Manager.Crypto
        private let ledger: any ChallengeLedger
        private let now:    () -> Date

        /// The question the owner asked with each outstanding challenge, until it settles or expires. In memory
        /// only, and apart from the ledger so that the ledger holds nothing worth keeping: a note is reachable only
        /// by holding the challenge itself, and the ledger hands out only the current depth's.
        private var notes: [OutstandingChallenge: String] = [:]

        /// - Parameters:
        ///   - crypto: The crypto facade. Same instance used elsewhere; no SE
        ///     state is held here.
        ///   - ledger: The outstanding-challenge ledger. Shared across the app
        ///     so phase 3 can find the phase 1 entry.
        ///   - now:    Injectable clock. Tests pass a fixed clock to exercise
        ///     the `IdentityChallenge.timestampWindow` boundary; production passes `Date.init`.
        init(
            crypto: Occulta.Manager.Crypto,
            ledger: any ChallengeLedger,
            now:    @escaping () -> Date = Date.init
        ) {
            self.crypto = crypto
            self.ledger = ledger
            self.now    = now
        }

        /// Forget the notes of challenges that can no longer be answered. Beside `ChallengeLedger.sweepExpired`.
        func forgetExpiredNotes(now: Date) {
            self.notes = self.notes.filter { !$0.key.isExpired(at: now) }
        }

        // MARK: Phase 1 — challenger creates the challenge

        /// Generate a fresh challenge bundle to send to a recipient.
        ///
        /// Side effects:
        ///   - Registers an entry in `ledger` for `contactID`.
        ///     Throws `.rateLimited` if one is already outstanding for this
        ///     contact.
        ///
        /// The bundle rides on `Version.v3fs` + `Mode.longTermFallback` — values
        /// every shipped Occulta build decodes. Routing discrimination lives in
        /// `SealedPayload.identityChallenge` inside the encrypted envelope. For a
        /// contact at `.bodyDigestCapable`, use `createChallenge(contactID:contextNote:seal:)`
        /// with `ContactManager.encryptBundle` instead (prekey continuity §3.4).
        func createChallenge(
            recipientKey:    Data,
            recipientQuantum: QuantumKeyMaterial?,
            contactID:       String,
            contextNote:     String? = nil
        ) throws -> OccultaBundle {
            try self.createChallenge(contactID: contactID, contextNote: contextNote) { envelope in
                try self.sealIdentityBundle(
                    envelope:        envelope,
                    fallbackMessage: IdentityChallenge.challengeFallbackMessage,
                    recipientKey:    recipientKey,
                    quantumMaterial: recipientQuantum
                )
            }
        }

        /// Build a challenge and hand its envelope to `seal`, which picks the format. Same side effects as above:
        /// the challenge is registered only once `seal` returns.
        func createChallenge<Sealed>(
            contactID:   String,
            contextNote: String? = nil,
            seal:        (IdentityChallengeEnvelope) throws -> Sealed
        ) throws -> Sealed {
            // 0. Rate limit first — avoid wasting SE work on a request we'll reject.
            guard !self.ledger.hasOutstanding(for: contactID, now: self.now()) else {
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
            let sealed = try seal(envelope)

            // 4. Remember this challenge until the response arrives or expires.
            //    Done LAST so a seal failure doesn't leave a ghost entry.
            let stale = self.ledger.challenge(for: contactID)
            let issued = OutstandingChallenge(nonce: nonce, issuedAt: timestamp)
            do {
                try self.ledger.record(issued, for: contactID, now: self.now())
            } catch {
                throw ManagerError.rateLimited
            }
            if let stale { self.notes.removeValue(forKey: stale) }
            self.notes[issued] = sanitizedNote

            return sealed
        }

        // MARK: Phase 2 — responder decrypts and (later) signs

        /// Decrypt an inbound challenge bundle and verify its framing.
        ///
        /// The caller is responsible for sender identification — the sender's
        /// resolved key material is passed directly so this method can
        /// independently re-derive the session key as defense-in-depth.
        ///
        /// Performs NO signing — signing requires explicit user approval and
        /// happens in `respond(to:)`. This phase is a pure parse + validate.
        func decryptChallenge(
            bundle:        OccultaBundle,
            senderKey:     Data,
            senderQuantum: QuantumKeyMaterial?,
            senderID:      String,
            senderName:    String
        ) throws -> PendingApproval {
            // Open the bundle independently — we do NOT trust the pre-decrypted
            // payload alone. Wrong key → AES-GCM auth failure → malformedBundle.
            let envelope = try self.openIdentityBundle(
                bundle:        bundle,
                peerPublicKey: senderKey,
                peerQuantum:   senderQuantum,
                expecting:     .challenge
            )
            return try self.decryptChallenge(
                envelope:      envelope,
                senderKey:     senderKey,
                senderQuantum: senderQuantum,
                senderID:      senderID,
                senderName:    senderName
            )
        }

        /// Validate a challenge whose bundle is already open and authenticated: one that arrived in a group body
        /// and passed `ContactManager.openGroup` (prekey continuity §3.4). Every check after opening is the same as
        /// for a bundle; only the long-term reopening is skipped. Take `IdentityChallenge.Authenticated` at the call
        /// site, never an envelope from anywhere else.
        func decryptChallenge(
            envelope:      IdentityChallengeEnvelope,
            senderKey:     Data,
            senderQuantum: QuantumKeyMaterial?,
            senderID:      String,
            senderName:    String
        ) throws -> PendingApproval {
            guard envelope.kind == .challenge else { throw ManagerError.malformedBundle }
            let payloadBytes = envelope.payload
            let note         = envelope.contextNote

            // Responder-side length enforcement. A compliant sender truncates
            // to `maxContextNoteBytes`; anything larger is treated as malformed.
            if let note, note.utf8.count > IdentityChallenge.maxContextNoteBytes {
                throw ManagerError.malformedBundle
            }

            // Decode the inner ChallengePayload.
            let payload: ChallengePayload
            do {
                payload = try ChallengePayload(from: payloadBytes)
            } catch {
                throw ManagerError.malformedBundle
            }

            // Inner fingerprint must bind to the sender's long-term key.
            // Prevents a stored-but-misrouted bundle from being accepted.
            let expected = OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: payload.nonce)
            guard expected == payload.challengerFingerprint else {
                throw ManagerError.verificationFailed
            }

            // Soft staleness check — reject obviously old challenges so a
            // replayed message can't coerce a biometric prompt hours later.
            // Tolerates moderate clock skew in both directions.
            let nowSec = UInt64(self.now().timeIntervalSince1970)
            guard let ts = try? IdentityChallenge.decodeTimestamp(payload.timestamp) else {
                throw ManagerError.malformedBundle
            }
            if ts > nowSec {
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

            return PendingApproval(
                challengerID:        senderID,
                challengerName:      senderName,
                challengerPublicKey: senderKey,
                challengerQuantum:   senderQuantum,
                payload:             payload,
                contextNote:         note
            )
        }

        /// Sign the approved challenge and build the response bundle.
        ///
        /// Biometric prompt (in production) fires inside `signChallenge` via
        /// Secure Enclave access control. The caller is responsible for having
        /// surfaced the user-approval UI before invoking this.
        func respond(to pending: PendingApproval) throws -> OccultaBundle {
            try self.respond(to: pending) { envelope in
                try self.sealIdentityBundle(
                    envelope:        envelope,
                    fallbackMessage: IdentityChallenge.responseFallbackMessage,
                    recipientKey:    pending.challengerPublicKey,
                    quantumMaterial: pending.challengerQuantum
                )
            }
        }

        /// Sign the approved challenge and hand the response envelope to `seal`, which picks the format: for a
        /// challenger at `.bodyDigestCapable`, `ContactManager.encryptBundle` (prekey continuity §3.4).
        func respond<Sealed>(to pending: PendingApproval, seal: (IdentityChallengeEnvelope) throws -> Sealed) throws -> Sealed {
            let signedData = Occulta.Manager.Crypto.buildSignedData(
                nonce:                 pending.payload.nonce,
                timestamp:             pending.payload.timestamp,
                challengerFingerprint: pending.payload.challengerFingerprint
            )

            let signature = try self.crypto.signChallenge(signedData)
            let response  = ResponsePayload(challengeNonce: pending.payload.nonce, signature: signature)

            // `.response(payload:)` forces contextNote == nil — the rule that
            // responses never carry a note lives inside the factory, not here.
            return try seal(IdentityChallengeEnvelope.response(payload: response.encoded()))
        }

        // MARK: Phase 3 — challenger verifies the response

        /// Verify an inbound response bundle. `.passed` only on a complete, in-window
        /// signature verification against the stored outstanding challenge; `.failed`
        /// when the response names that challenge and fails; `.notOurs` when it names
        /// none waiting for this contact (`bugs.md` Bug 166).
        ///
        /// Removes the outstanding entry on both pass AND fail — a failed
        /// response consumes the one-shot rate-limit slot. This is intentional:
        /// retry must start with a fresh nonce. `.notOurs` leaves it: the contact's
        /// own response may still come.
        func verifyResponse(
            bundle:        OccultaBundle,
            senderKey:     Data,
            senderQuantum: QuantumKeyMaterial?,
            senderID:      String
        ) throws -> VerificationResult {
            let envelope = try self.openIdentityBundle(
                bundle:        bundle,
                peerPublicKey: senderKey,
                peerQuantum:   senderQuantum,
                expecting:     .response
            )
            return try self.verifyResponse(envelope: envelope, senderKey: senderKey, senderID: senderID)
        }

        /// Verify a response whose bundle is already open and authenticated, as `decryptChallenge(envelope:…)`
        /// describes. The same checks as for a bundle, after the long-term reopening.
        func verifyResponse(
            envelope:  IdentityChallengeEnvelope,
            senderKey: Data,
            senderID:  String
        ) throws -> VerificationResult {
            guard envelope.kind == .response else { throw ManagerError.malformedBundle }

            let response: ResponsePayload
            do {
                response = try ResponsePayload(from: envelope.payload)
            } catch {
                throw ManagerError.malformedBundle
            }

            // The challenge we issued to this contact, in the session that is open now, and it must be the one
            // this response names. The ledger holds one per contact, so another contact's response to someone
            // else's challenge can't claim their identity. Neither case is an answer from this contact — a replay,
            // a challenge already settled, one made at another depth — so it says nothing about them, and the
            // entry stays for the response that is.
            guard let entry = self.ledger.challenge(for: senderID),
                  entry.nonce == response.challengeNonce else {
                return .notOurs
            }
            let note = self.notes[entry]

            // Hard verification window — `IdentityChallenge.timestampWindow`.
            let now = self.now()
            let nowSec = UInt64(now.timeIntervalSince1970)
            // Handle both directions: responder's clock ahead of us is fine
            // up to the same window.
            let delta: TimeInterval = {
                if nowSec >= entry.issuedAt {
                    return TimeInterval(nowSec - entry.issuedAt)
                } else {
                    return TimeInterval(entry.issuedAt - nowSec)
                }
            }()
            guard delta < IdentityChallenge.timestampWindow else {
                self.settle(entry, for: senderID, passedAt: nil)
                return .failed(contextNote: note)
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
            let tsBytes = IdentityChallenge.encodeTimestamp(entry.issuedAt)
            let signedData = Occulta.Manager.Crypto.buildSignedData(
                nonce:                 entry.nonce,
                timestamp:             tsBytes,
                challengerFingerprint: challengerFingerprint
            )

            // Construct a SecKey view over the responder's stored public key.
            guard let publicKey = Self.makePublicKey(x963: senderKey) else {
                self.settle(entry, for: senderID, passedAt: nil)
                return .failed(contextNote: note)
            }

            let ok = self.crypto.verifyChallenge(signedData, signature: response.signature, publicKey: publicKey)

            // One-shot: consume the slot regardless of outcome. The note was read above, so the caller can
            // render "you asked X — verified" even after removal.
            self.settle(entry, for: senderID, passedAt: ok ? now : nil)
            return ok ? .passed(contextNote: note) : .failed(contextNote: note)
        }

        /// Consume `entry` and the note that went with it.
        private func settle(_ entry: OutstandingChallenge, for contactID: String, passedAt: Date?) {
            self.ledger.settle(nonce: entry.nonce, for: contactID, passedAt: passedAt)
            self.notes.removeValue(forKey: entry)
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
            recipientKey:    Data,
            quantumMaterial: QuantumKeyMaterial? = nil
        ) throws -> OccultaBundle {
            let ourPublicKey: Data
            do {
                ourPublicKey = try self.crypto.keyManager.retrieveIdentity()
            } catch {
                throw ManagerError.noIdentity
            }
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
