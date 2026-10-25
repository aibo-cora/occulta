//
//  IdentityChallenge+Ledger.swift
//  Occulta
//
//  The seam between the identity-challenge protocol and whatever remembers its state.
//
//  The state of a challenge (the one we issued to a contact, and when we last verified them) belongs to the
//  depth that created it, not to the process: `bugs.md` Bug 180. A session at another depth must find an empty
//  ledger, as if the owner had never challenged anyone, or a duress session can see the owner's real-depth
//  activity and the owner's own question. So the depth is never an argument. `ContactManager` implements
//  `ChallengeLedger` and reads `security.currentDepth` itself, where nothing can pass or forget it, and the
//  `Coordinator`, which is built once before any PIN is entered, holds only these protocols.
//

import Foundation
import OccultaFormats

extension IdentityChallenge {

    /// A challenge we issued and have not yet settled: all the challenger remembers about it.
    ///
    /// The context note is not part of it. It is the owner's own free text and stays with the `Manager`, keyed by
    /// `nonce`, where it is reachable only by someone who already holds the nonce of a challenge at their depth.
    struct OutstandingChallenge: Hashable {
        /// The 32-byte challenge nonce.
        let nonce: Data
        /// Unix epoch seconds when the challenge was created. A raw `UInt64` so the signed data is a pure function of it.
        let issuedAt: UInt64

        /// Whether `|now − issuedAt|` has reached `timestampStaleThreshold`. Either direction: a clock set backwards
        /// must not keep a record alive forever (it is the same rule the response window applies).
        func isExpired(at now: Date) -> Bool {
            let nowSeconds = UInt64(max(0, now.timeIntervalSince1970))
            let delta = nowSeconds >= self.issuedAt ? nowSeconds - self.issuedAt : self.issuedAt - nowSeconds
            return TimeInterval(delta) >= IdentityChallenge.timestampStaleThreshold
        }
    }

    enum LedgerError: Error {
        /// A challenge to this contact has been waiting, unexpired, since before this one.
        case alreadyOutstanding
    }

    /// Per-contact challenge state for the session that is open now. Every method acts on the current depth's
    /// entries only: no caller can name another depth's.
    @MainActor
    protocol ChallengeLedger: AnyObject {
        /// The challenge this session issued to `contactID` and has not settled, expired or not, or nil.
        func challenge(for contactID: String) -> OutstandingChallenge?

        /// Whether a new challenge to `contactID` must wait. An expired entry is free: it can no longer be answered.
        func hasOutstanding(for contactID: String, now: Date) -> Bool

        /// Remember `challenge` for `contactID`, replacing an expired one.
        /// - Throws: `LedgerError.alreadyOutstanding` if an unexpired one is waiting.
        func record(_ challenge: OutstandingChallenge, for contactID: String, now: Date) throws

        /// Consume the entry holding `nonce`, if it is still the one for `contactID`. `passedAt` is set only when
        /// the answer verified, and starts the "Verified N minutes ago" badge.
        func settle(nonce: Data, for contactID: String, passedAt: Date?)

        /// When this session last verified `contactID`, or nil.
        func verifiedAt(for contactID: String) -> Date?

        /// Drop what is expired, at every depth: an expired entry can't be acted on at any of them.
        func sweepExpired(now: Date)
    }

    /// What the `Coordinator` needs from `ContactManager` to send a challenge or a response as a message.
    @MainActor
    protocol ChallengeSealer: AnyObject {
        /// For a contact at `.bodyDigestCapable`, a function that seals an envelope to a temp `.occ` for the share
        /// sheet in group format, as a message. Nil means the long-term format, which every build reads
        /// (prekey continuity §3.4).
        func groupSealer(for contactID: String) -> ((IdentityChallengeEnvelope) throws -> URL)?
    }
}
