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

        init() {
            let store   = OutstandingChallengeStore()
            let crypto  = Occulta.Manager.Crypto()
            self.store   = store
            self.manager = Manager(crypto: crypto, store: store)
            // Sweep stale entries on init — matches app-launch cleanup in the spec.
            store.removeExpired()
        }

        // MARK: - Outbound: create challenge

        /// Build a challenge bundle for `contact`, write it to a temp `.occ`
        /// file, and stage it for sharing via `ShareActivityView`.
        func createChallenge(
            for contact: Contact.Profile,
            contextNote: String?
        ) throws {
            let crypto = Occulta.Manager.Crypto()
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
            let displayName = contact.givenName.decrypt()
            let bundle = try self.manager.createChallenge(
                recipientKey:     recipientKey,
                recipientQuantum: quantum,
                contactID:        contact.identifier,
                contextNote:      contextNote
            )
            let url = try Self.writeOCC(bundle.encoded(), kind: "challenge")
            self.outboundShare = OutboundShare(
                url:         url,
                contactID:   contact.identifier,
                contactName: displayName.isEmpty ? "Unknown" : displayName,
                contextNote: contextNote?.isEmpty == false ? contextNote : nil,
                kind:        .challenge
            )
        }

        // MARK: - Inbound: route a decrypted SealedPayload

        /// Called by the inbound `.occ` pipeline in `OccultaApp` when the
        /// decoded `SealedPayload.identityChallenge` is non-nil. The sender's
        /// `Contact.Profile` is resolved at the call site (by `ownerID` from
        /// `decryptSealed`) and passed in directly.
        ///
        /// Re-opens the bundle through its own ECDSA/AAD checks as
        /// defense-in-depth — we do NOT trust the pre-decrypted payload alone.
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

            switch envelope.kind {
            case .challenge:
                do {
                    let pending = try self.manager.decryptChallenge(
                        bundle:        bundle,
                        senderKey:     senderKey,
                        senderQuantum: senderQuantum,
                        senderID:      senderID,
                        senderName:    senderName
                    )
                    self.incomingChallenge = IncomingChallenge(pending: pending)
                } catch {
                    self.errorMessage = "Could not open identity verification request."
                }
                return true

            case .response:
                do {
                    let (ok, note) = try self.manager.verifyResponse(
                        bundle:        bundle,
                        senderKey:     senderKey,
                        senderQuantum: senderQuantum,
                        senderID:      senderID
                    )
                    if ok {
                        self.verifiedAt[senderID] = Date()
                    }
                    self.verificationOutcome = VerificationOutcome(
                        passed:      ok,
                        contactID:   senderID,
                        contactName: senderName,
                        contextNote: note
                    )
                } catch {
                    self.verificationOutcome = VerificationOutcome(
                        passed:      false,
                        contactID:   senderID,
                        contactName: senderName,
                        contextNote: nil
                    )
                }
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
                        let bundle = try self.manager.respond(to: pending)
                        let url    = try Self.writeOCC(bundle.encoded(), kind: "response")
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

        /// Write bundle bytes to a temp `.occ` file ready for share sheet.
        private static func writeOCC(_ data: Data, kind: String) throws -> URL {
            let name = (UUID().uuidString.components(separatedBy: "-").last ?? "unknown") + ".occ"
            let url  = FileManager.default.temporaryDirectory.appendingPathComponent(name)
            try data.write(to: url)
            return url
        }
    }
}
