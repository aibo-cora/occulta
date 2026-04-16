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
            guard let view = Self.contactView(for: contact) else {
                throw IdentityChallenge.ManagerError.noIdentity
            }
            let bundle = try self.manager.createChallenge(for: view, contextNote: contextNote)
            let url    = try Self.writeOCC(bundle.encoded(), kind: "challenge")
            self.outboundShare = OutboundShare(
                url:          url,
                contactID:    contact.identifier,
                contactName:  view.displayName,
                contextNote:  contextNote?.isEmpty == false ? contextNote : nil,
                kind:         .challenge
            )
        }

        // MARK: - Inbound: route a decrypted SealedPayload

        /// Called by the inbound `.occ` pipeline in `OccultaApp` when the
        /// decoded `SealedPayload.contentType` is non-nil. Reconstitutes the
        /// `OccultaBundle` so the `Manager` can re-open it through its own
        /// ECDSA/AAD checks — we do NOT trust the pre-decrypted payload alone.
        ///
        /// - Returns: `true` if the bundle was routed to identity-challenge
        ///   handling (approval sheet or verification result was presented).
        ///   `false` means the caller should fall back to regular message
        ///   handling (e.g. an unknown content type from a future build).
        @discardableResult
        func handleInbound(
            bundle: OccultaBundle,
            sealed: OccultaBundle.SealedPayload,
            contactManager: ContactManager
        ) -> Bool {
            guard let contentType = sealed.contentType else { return false }

            let contactViews = Self.allContactViews(contactManager: contactManager)

            switch contentType {
            case .identityChallenge:
                do {
                    let pending = try self.manager.decryptChallenge(bundle: bundle, contacts: contactViews)
                    self.incomingChallenge = IncomingChallenge(pending: pending)
                } catch {
                    self.errorMessage = "Could not open identity verification request."
                }
                return true

            case .identityChallengeResponse:
                do {
                    let (ok, note) = try self.manager.verifyResponse(bundle: bundle, contacts: contactViews)
                    // Best-effort: match the responder back to a contact name.
                    let sender = Self.matchSender(bundle: bundle, contactViews: contactViews)
                    let name   = sender?.displayName ?? "This contact"
                    let id     = sender?.identifier ?? ""
                    if ok && !id.isEmpty {
                        self.verifiedAt[id] = Date()
                    }
                    self.verificationOutcome = VerificationOutcome(
                        passed:      ok,
                        contactID:   id,
                        contactName: name,
                        contextNote: note
                    )
                } catch {
                    self.verificationOutcome = VerificationOutcome(
                        passed:      false,
                        contactID:   "",
                        contactName: "This contact",
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
            defer { self.incomingChallenge = nil }

            do {
                let bundle = try self.manager.respond(to: pending)
                let url    = try Self.writeOCC(bundle.encoded(), kind: "response")
                self.outboundShare = OutboundShare(
                    url:         url,
                    contactID:   pending.challenger.identifier,
                    contactName: pending.challenger.displayName,
                    contextNote: nil,
                    kind:        .response
                )
            } catch {
                self.errorMessage = "Could not produce response. The verification request has been discarded."
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

        /// Build a `ContactView` from a SwiftData profile — decrypts the
        /// latest non-expired public key and the display name.
        static func contactView(for contact: Contact.Profile) -> IdentityChallenge.ContactView? {
            let crypto = Occulta.Manager.Crypto()
            guard
                let keyRecord = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
                let pubKey    = try? crypto.decrypt(data: keyRecord.material)
            else { return nil }
            let name = contact.givenName.decrypt()
            return IdentityChallenge.ContactView(
                identifier:  contact.identifier,
                publicKey:   pubKey,
                displayName: name.isEmpty ? "Unknown" : name
            )
        }

        private static func allContactViews(contactManager: ContactManager) -> [IdentityChallenge.ContactView] {
            guard let contacts = try? contactManager.fetchAllContacts() else { return [] }
            return contacts.compactMap { Self.contactView(for: $0) }
        }

        private static func matchSender(
            bundle: OccultaBundle,
            contactViews: [IdentityChallenge.ContactView]
        ) -> IdentityChallenge.ContactView? {
            for view in contactViews {
                let fp = OccultaBundle.SecrecyContext.fingerprint(
                    for: view.publicKey,
                    nonce: bundle.fingerprintNonce
                )
                if fp == bundle.senderFingerprint { return view }
            }
            return nil
        }

        /// Write bundle bytes to a temp `.occ` file ready for share sheet.
        private static func writeOCC(_ data: Data, kind: String) throws -> URL {
            let name = "\(kind)-\(UUID().uuidString.prefix(8)).occ"
            let url  = FileManager.default.temporaryDirectory.appendingPathComponent(name)
            try data.write(to: url)
            return url
        }
    }
}
