//
//  IdentityChallenge+Store.swift
//  Occulta
//
//  In-memory challenge ledger.
//
//  This is no longer where the app keeps challenges. The app's state is the sealed, per-depth
//  `Contact.Profile.challengeStateEncrypted`, read and written by `ContactManager+ChallengeLedger.swift`, which
//  picks the slot from `security.currentDepth` (`bugs.md` Bug 180). This type is the same `ChallengeLedger` over a
//  dictionary: the stand-in the protocol tests give the `Manager`, and the one a responder holds, which never
//  records a challenge.
//
//  ⚠️ This reverses the old header, which said "NEVER persist this to disk: if the app is terminated, outstanding
//  challenges are lost — that is correct behaviour." The challenge now outlives the process, because a challenge
//  that dies with a suspended app made the common flow (challenge, share sheet, the app evicted, open the reply)
//  end in nothing. What that costs is recorded where the decision was made: a sealed record, readable with the
//  local DB key, that a challenge to contact X is outstanding at depth d, since when, for at most an hour (and
//  until the next sweep after that), and a live slot at depth ≥ 1 shows a duress layer was used. Open, needs a
//  decision; see `Docs/Features/Secure Mode/forensic-trace-avoidance.md`. The owner's own question is NOT
//  persisted: it stays in memory in the `Manager`, keyed by the challenge.
//

import Foundation

extension IdentityChallenge {

    /// Tracks open challenges — one per contact, in memory only. The ledger for tests and for the responder,
    /// which never records one; not the app's (see the header).
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
