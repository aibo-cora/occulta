//
//  IdentityChallenge+Coordinator.swift
//  Occulta
//
//  UI-facing orchestrator that owns the `IdentityChallenge.Manager` +
//  `OutstandingChallengeStore` and exposes `@Observable` state for the sheets
//  in `IdentityChallenge+View.swift`.
//
//  Lives as `@State` on `OccultaApp` and is injected into the environment so
//  both `Contact.Details` (outbound creation) and the app-level inbound
//  router can drive the same state.
//
//  In-memory only. Verified-at timestamps and outstanding challenges vanish
//  on app termination — deliberate, see protocol spec.
//

import Foundation
import LocalAuthentication
import SwiftUI
import OccultaFormats

extension IdentityChallenge {

    @Observable
    @MainActor
    final class Coordinator {

        // MARK: - Sub-types

        /// Outbound-share state. Drives `ShareActivityView`.
        struct OutboundShare: Identifiable {
            let id = UUID()
            let url: URL
            /// For post-sharing UI: "waiting for response from [contactName]".
            let contactID: String
            let contactName: String
            /// Set only when we created a challenge. Nil for the response share.
            let contextNote: String?
            /// Distinguishes challenge-share from response-share in the UI copy.
            let kind: Kind
            enum Kind { case challenge, response }
        }

        /// Inbound challenge awaiting responder's explicit approval.
        struct IncomingChallenge: Identifiable {
            let id = UUID()
            let pending: PendingApproval
        }

        /// Verification outcome on the challenger side.
        struct VerificationOutcome: Identifiable {
            let id = UUID()
            let passed: Bool
            let contactID: String
            let contactName: String
            let contextNote: String?
        }

        // MARK: - State

        /// Exposed so `Contact.Details` can show "Waiting…" / disable the
        /// Verify-Identity button while a challenge is outstanding.
        let store: OutstandingChallengeStore

        /// Transient verified-at map — keyed by `Contact.Profile.identifier`.
        /// Cleared on app termination. Drives the "Verified N ago" badge.
        private(set) var verifiedAt: [String: Date] = [:]

        /// Drives the outbound share sheet (challenge OR response).
        var outboundShare: OutboundShare?

        /// Drives the incoming-challenge approval sheet.
        var incomingChallenge: IncomingChallenge?

        /// Drives the verification-result sheet on the challenger.
        var verificationOutcome: VerificationOutcome?

        /// One-shot error banner for flows that don't have their own sheet.
        var errorMessage: String?

        // MARK: - Private

        private let manager: Manager
        /// Sends to a contact at `.bodyDigestCapable` in group format, as a message (prekey continuity §3.4).
        private let contactManager: ContactManager

        init(contactManager: ContactManager) {
            let store   = OutstandingChallengeStore()
            let crypto  = Occulta.Manager.Crypto()
            self.store   = store
            self.manager = Manager(crypto: crypto, store: store)
            self.contactManager = contactManager
            // Sweep stale entries on init — matches app-launch cleanup in the spec.
            store.removeExpired()
        }

        // MARK: - Outbound: create challenge

        /// Build a challenge bundle for `contact`, write it to a temp `.occ`
        /// file, and stage it for sharing via `ShareActivityView`. In group format,
        /// as a message, to a contact at `.bodyDigestCapable`; in the long-term
        /// format to anyone older (prekey continuity §3.4).
        func createChallenge(
            for contact: Contact.Profile,
            contextNote: String?
        ) throws {
            let crypto = Occulta.Manager.Crypto()
            let url: URL
            if Self.takesGroupFormat(contact, using: crypto) {
                url = try self.manager.createChallenge(contactID: contact.identifier, contextNote: contextNote) { envelope in
                    try self.sealToFile(for: contact.identifier, envelope: envelope)
                }
            } else {
                guard
                    let keyRecord    = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
                    let recipientKey = try? crypto.decrypt(data: keyRecord.material)
                else {
                    throw IdentityChallenge.ManagerError.noIdentity
                }
                let quantum: QuantumKeyMaterial? = {
                    guard
                        let enc = keyRecord.quantumKeyMaterialEncrypted,
                        let dec = try? crypto.decrypt(data: enc)
                    else { return nil }
                    return try? JSONDecoder().decode(QuantumKeyMaterial.self, from: dec)
                }()
                let encoded = try self.manager.createChallenge(
                    recipientKey:     recipientKey,
                    recipientQuantum: quantum,
                    contactID:        contact.identifier,
                    contextNote:      contextNote
                ).encoded()
                url = try Self.writeOCC(encoded, kind: "challenge")
            }
            let displayName = contact.givenName.decrypt()
            self.outboundShare = OutboundShare(
                url:         url,
                contactID:   contact.identifier,
                contactName: displayName.isEmpty ? "Unknown" : displayName,
                contextNote: contextNote?.isEmpty == false ? contextNote : nil,
                kind:        .challenge
            )
        }

        // MARK: - Inbound: route a decrypted SealedPayload

        /// Called by the inbound `.occ` pipeline in `OccultaApp` for a one-to-one
        /// bundle whose decoded `SealedPayload.identityChallenge` is non-nil. The
        /// sender's `Contact.Profile` is resolved at the call site (by `ownerID` from
        /// `decryptSealed`) and passed in directly.
        ///
        /// Re-opens the bundle through its own ECDSA/AAD checks as
        /// defense-in-depth — we do NOT trust the pre-decrypted payload alone.
        /// `decryptSealed`'s forward-secret bundles carry no sender binding, so
        /// that reopening is what authenticates the sender here.
        ///
        /// - Returns: `true` if the bundle was consumed by identity-challenge
        ///   handling. `false` if the envelope was absent (caller falls through
        ///   to regular message handling).
        @discardableResult
        func handleInboundChallenge(
            bundle:   OccultaBundle,
            envelope: IdentityChallengeEnvelope,
            sender:   Contact.Profile
        ) -> Bool {
            self.route(
                envelope.kind, from: sender,
                challenge: { key, quantum, id, name in
                    try self.manager.decryptChallenge(
                        bundle: bundle, senderKey: key, senderQuantum: quantum, senderID: id, senderName: name
                    )
                },
                response: { key, quantum, id in
                    try self.manager.verifyResponse(bundle: bundle, senderKey: key, senderQuantum: quantum, senderID: id)
                }
            )
        }

        /// Called for a challenge or response that arrived in a group body. `ContactManager.openGroup` already
        /// opened and authenticated it (prekey continuity §3.4), and `IdentityChallenge.Authenticated` can only be
        /// built there, so it isn't reopened with the long-term key: a group bundle never opens that way.
        @discardableResult
        func handleAuthenticatedChallenge(
            _ challenge: IdentityChallenge.Authenticated,
            sender:      Contact.Profile
        ) -> Bool {
            self.route(
                challenge.envelope.kind, from: sender,
                challenge: { key, quantum, id, name in
                    try self.manager.decryptChallenge(
                        envelope: challenge.envelope, senderKey: key, senderQuantum: quantum, senderID: id, senderName: name
                    )
                },
                response: { key, _, id in
                    try self.manager.verifyResponse(envelope: challenge.envelope, senderKey: key, senderID: id)
                }
            )
        }

        private func route(
            _ kind:    IdentityChallengeEnvelope.Kind,
            from sender: Contact.Profile,
            challenge: (Data, QuantumKeyMaterial?, String, String) throws -> PendingApproval,
            response:  (Data, QuantumKeyMaterial?, String) throws -> VerificationResult
        ) -> Bool {
            let crypto = Occulta.Manager.Crypto()
            guard
                let keyRecord = sender.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
                let senderKey = try? crypto.decrypt(data: keyRecord.material)
            else {
                self.errorMessage = "Could not open identity verification request."
                return true
            }
            let senderQuantum: QuantumKeyMaterial? = {
                guard
                    let enc = keyRecord.quantumKeyMaterialEncrypted,
                    let dec = try? crypto.decrypt(data: enc)
                else { return nil }
                return try? JSONDecoder().decode(QuantumKeyMaterial.self, from: dec)
            }()
            let senderID   = sender.identifier
            let senderName = { let n = sender.givenName.decrypt(); return n.isEmpty ? "Unknown" : n }()

            switch kind {
            case .challenge:
                do {
                    let pending = try challenge(senderKey, senderQuantum, senderID, senderName)
                    self.incomingChallenge = IncomingChallenge(pending: pending)
                } catch {
                    self.errorMessage = "Could not open identity verification request."
                }
                return true

            case .response:
                // A result only for a response to our challenge to this contact. One that doesn't
                // open, or names no challenge waiting for them, says nothing about them: showing
                // "Verification failed" for it accused them over a reopened file (`bugs.md` Bug 166).
                // Only the contact can produce a response that opens and names our nonce.
                let passed: Bool
                let note: String?
                switch try? response(senderKey, senderQuantum, senderID) {
                case .passed(let contextNote)?:
                    (passed, note) = (true, contextNote)
                    self.verifiedAt[senderID] = Date()
                case .failed(let contextNote)?:
                    (passed, note) = (false, contextNote)
                case .notOurs?, nil:
                    return true
                }
                self.verificationOutcome = VerificationOutcome(
                    passed:      passed,
                    contactID:   senderID,
                    contactName: senderName,
                    contextNote: note
                )
                return true
            }
        }

        // MARK: - Inbound: approve / decline

        /// Sign the pending challenge and stage the response `.occ` for share.
        func approvePending() {
            guard let pending = self.incomingChallenge?.pending else { return }
            // Hold sheet open until biometry resolves — clear after.
            Task {
                let context = LAContext()
                let authenticated: Bool
                do {
                    // Prefer biometrics; fall back to device passcode so users
                    // without enrolled Face ID / Touch ID can still approve.
                    let policy: LAPolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
                        ? .deviceOwnerAuthenticationWithBiometrics
                        : .deviceOwnerAuthentication
                    try await context.evaluatePolicy(
                        policy,
                        localizedReason: "Confirm your identity to sign this verification"
                    )
                    authenticated = true
                } catch {
                    authenticated = false
                }

                await MainActor.run {
                    self.incomingChallenge = nil
                    guard authenticated else { return }
                    do {
                        let url: URL
                        if let challenger = try? self.contactManager.fetchContact(by: pending.challengerID),
                           Self.takesGroupFormat(challenger, using: Occulta.Manager.Crypto()) {
                            url = try self.manager.respond(to: pending) { envelope in
                                try self.sealToFile(for: pending.challengerID, envelope: envelope)
                            }
                        } else {
                            url = try Self.writeOCC(try self.manager.respond(to: pending).encoded(), kind: "response")
                        }
                        self.outboundShare = OutboundShare(
                            url:         url,
                            contactID:   pending.challengerID,
                            contactName: pending.challengerName,
                            contextNote: nil,
                            kind:        .response
                        )
                    } catch {
                        self.errorMessage = "Could not produce response. The verification request has been discarded."
                    }
                }
            }
        }

        func declinePending() {
            self.incomingChallenge = nil
        }

        // MARK: - Verified badge

        /// Human-readable "Verified N minutes ago" string, or nil if the
        /// badge should not be shown.
        /// Hidden after `timestampStaleThreshold` (1 hour) per spec.
        func verifiedBadge(for contactID: String, now: Date = Date()) -> String? {
            guard let at = self.verifiedAt[contactID] else { return nil }
            let elapsed = now.timeIntervalSince(at)
            guard elapsed >= 0 && elapsed < IdentityChallenge.timestampStaleThreshold else {
                return nil
            }
            let minutes = Int(elapsed / 60)
            if minutes <= 0 { return "Verified just now" }
            if minutes == 1 { return "Verified 1 minute ago" }
            return "Verified \(minutes) minutes ago"
        }

        // MARK: - Helpers

        /// Whether `contact`'s build accepts a challenge or response in group format: recorded at
        /// `.bodyDigestCapable`, which only rises. Below it, or with a stranded marker, the long-term format, which
        /// every build reads (prekey continuity §3.4).
        private static func takesGroupFormat(_ contact: Contact.Profile, using crypto: Occulta.Manager.Crypto) -> Bool {
            ContactManager.resolveTargetVersion(for: contact, using: crypto).isAtLeast(.bodyDigestCapable)
        }

        /// A challenge or response in group format, written to a temp `.occ` for the share sheet. It travels in the
        /// layout a message to the same contact would: streamed, with only a manifest, when the contact can read
        /// that. A layout of its own would tell it apart from a message (STREAMING_SPEC §3).
        private func sealToFile(for contactID: String, envelope: IdentityChallengeEnvelope) throws -> URL {
            let name = (UUID().uuidString.components(separatedBy: "-").last ?? "unknown") + ".occ"
            let url  = FileManager.default.temporaryDirectory.appendingPathComponent(name)
            try self.contactManager.encryptBundle(
                for: contactID, identityChallenge: envelope,
                output: .file(destination: url, attachments: nil, memoryGuard: .system)
            )
            return url
        }

        /// Write bundle bytes to a temp `.occ` file ready for share sheet.
        private static func writeOCC(_ data: Data, kind: String) throws -> URL {
            let name = (UUID().uuidString.components(separatedBy: "-").last ?? "unknown") + ".occ"
            let url  = FileManager.default.temporaryDirectory.appendingPathComponent(name)
            try data.writeProtected(to: url)
            return url
        }
    }
}
