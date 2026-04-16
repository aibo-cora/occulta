//
//  IdentityChallenge+Store.swift
//  Occulta
//
//  In-memory store for outstanding challenges.
//
//  ⚠️ NEVER persist this to disk. If the app is terminated, outstanding
//  challenges are lost — that is correct behaviour. Persistence would add
//  an encrypted-at-rest attack surface for a record whose maximum lifetime
//  is `IdentityChallenge.timestampWindow` (5 minutes).
//

import Foundation

extension IdentityChallenge {

    /// Tracks open challenges — one per contact, in memory only.
    ///
    /// Why keyed by `contactKeyID` (not by nonce):
    /// - The `maxOutstandingPerContact = 1` rate limit has to be checked on
    ///   insertion. With a dictionary keyed by the rate-limit dimension,
    ///   that check is O(1) and collision-free.
    /// - `lookup(nonce:)` is a linear scan, which is fine: the dictionary
    ///   holds at most one entry per contact, so the total entry count is
    ///   bounded by the contact count (tens or low hundreds in practice).
    ///   Do NOT add a secondary index — more state, more invariants.
    @MainActor
    final class OutstandingChallengeStore {

        /// One outstanding challenge — the challenger's side of the protocol.
        struct Entry: Equatable {
            /// The 32-byte challenge nonce.
            let nonce: Data
            /// Unix epoch seconds when the challenge was created.
            /// Kept as a raw `UInt64` so wire-format encoding is a pure function.
            let timestamp: UInt64
            /// Stable per-contact identifier — enforces the 1-per-contact limit.
            let contactKeyID: String
            /// Preserved across the round trip so the UI can show the original
            /// question alongside the verification result. Not part of the
            /// signed data, not part of the rate-limit key.
            let contextNote: String?
        }

        enum StoreError: Error {
            /// The rate limit is already at `maxOutstandingPerContact`.
            case alreadyOutstanding
        }

        private var entries: [String: Entry] = [:]

        /// Insert a new entry, rejecting if the per-contact limit is reached.
        func store(_ entry: Entry) throws {
            guard entries[entry.contactKeyID] == nil else {
                throw StoreError.alreadyOutstanding
            }
            entries[entry.contactKeyID] = entry
        }

        /// Linear-scan lookup by nonce. O(n) where n = outstanding challenge count,
        /// bounded by total contact count.
        func lookup(nonce: Data) -> Entry? {
            entries.values.first { $0.nonce == nonce }
        }

        /// Remove the entry with the given nonce, if any. No-op if not present.
        /// Called after verification (pass or fail) and after expiry.
        func remove(nonce: Data) {
            if let key = entries.first(where: { $0.value.nonce == nonce })?.key {
                entries.removeValue(forKey: key)
            }
        }

        /// Drop entries older than `timestampStaleThreshold`.
        /// Call on app launch to clean up leftover state from a prior run
        /// whose challenges can no longer pass the responder-side staleness
        /// check anyway.
        func removeExpired(now: Date = Date()) {
            let nowSeconds = UInt64(now.timeIntervalSince1970)
            entries = entries.filter { _, entry in
                // Keep entries from the future (clock skew) and recent past.
                guard nowSeconds >= entry.timestamp else { return true }
                return TimeInterval(nowSeconds - entry.timestamp) < IdentityChallenge.timestampStaleThreshold
            }
        }

        /// Rate-limit predicate used by the challenger before generating a new nonce.
        func hasOutstanding(for contactKeyID: String) -> Bool {
            entries[contactKeyID] != nil
        }

        /// Test-only inspection — total number of outstanding entries.
        /// Production code must not depend on this.
        var count: Int { entries.count }
    }
}
