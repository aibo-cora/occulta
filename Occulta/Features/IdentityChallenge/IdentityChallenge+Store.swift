//
//  IdentityChallenge+Store.swift
//  Occulta
//
//  In-memory challenge state for one depth.
//
//  State is per depth, and in memory. `ContactManager` keeps one `OutstandingChallengeStore` for each depth
//  and picks the one for `security.currentDepth` on every call, so a session never reaches another depth's
//  entries (`bugs.md` Bug 180). Nothing here knows about depth, and this type must stay that way: the binding
//  lives in one place, `ContactManager+ChallengeLedger.swift`.
//
//  ⚠️ NEVER persist this to disk in this form. If the app is terminated, outstanding challenges are lost —
//  in this stage that is correct behaviour, and it is the property the persistence decision still has to
//  weigh: an at-rest record of "challenge outstanding on contact X at depth d" is a new forensic trace.
//  Open, needs a decision (`Docs/Features/Secure Mode/bugs.md`, Bug 180).
//

import Foundation

extension IdentityChallenge {

    /// Tracks open challenges — one per contact, in memory only. Also the ledger used by tests and by the
    /// responder, which never records one.
    ///
    /// Keyed by contact, not by nonce: the `maxOutstandingPerContact = 1` rate limit is checked on insertion,
    /// and a reply is matched against the one entry its sender can have, in O(1), so a reply can't be matched
    /// to another contact's challenge by construction.
    @MainActor
    final class OutstandingChallengeStore: ChallengeLedger {

        private struct Slot {
            var challenge: OutstandingChallenge?
            var verifiedAt: Date?
        }

        private var slots: [String: Slot] = [:]

        func challenge(for contactID: String) -> OutstandingChallenge? {
            self.slots[contactID]?.challenge
        }

        func hasOutstanding(for contactID: String, now: Date) -> Bool {
            guard let challenge = self.slots[contactID]?.challenge else { return false }
            return !challenge.isExpired(at: now)
        }

        func record(_ challenge: OutstandingChallenge, for contactID: String, now: Date) throws {
            guard !self.hasOutstanding(for: contactID, now: now) else {
                throw LedgerError.alreadyOutstanding
            }
            self.slots[contactID, default: Slot()].challenge = challenge
        }

        func settle(nonce: Data, for contactID: String, passedAt: Date?) {
            guard self.slots[contactID]?.challenge?.nonce == nonce else { return }
            self.slots[contactID]?.challenge = nil
            if let passedAt {
                self.slots[contactID]?.verifiedAt = passedAt
            }
            self.dropIfEmpty(contactID)
        }

        func verifiedAt(for contactID: String) -> Date? {
            self.slots[contactID]?.verifiedAt
        }

        func sweepExpired(now: Date) {
            for (contactID, slot) in self.slots {
                if let challenge = slot.challenge, challenge.isExpired(at: now) {
                    self.slots[contactID]?.challenge = nil
                }
                // The badge hides at the same threshold, on either side of now.
                if let at = slot.verifiedAt, abs(now.timeIntervalSince(at)) >= IdentityChallenge.timestampStaleThreshold {
                    self.slots[contactID]?.verifiedAt = nil
                }
                self.dropIfEmpty(contactID)
            }
        }

        private func dropIfEmpty(_ contactID: String) {
            if let slot = self.slots[contactID], slot.challenge == nil, slot.verifiedAt == nil {
                self.slots.removeValue(forKey: contactID)
            }
        }

        /// Test-only inspection — number of outstanding challenges, expired or not.
        /// Production code must not depend on this.
        var count: Int { self.slots.values.filter { $0.challenge != nil }.count }
    }
}
