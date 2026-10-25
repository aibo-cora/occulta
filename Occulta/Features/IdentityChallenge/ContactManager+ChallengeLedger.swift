//
//  ContactManager+ChallengeLedger.swift
//  Occulta
//
//  Identity-challenge state, bound to the depth that created it (`bugs.md` Bug 180).
//
//  `ContactManager` reads `security.currentDepth` on every call, here and only here, and uses the store for
//  that depth. A session at another depth finds an empty ledger: a reply to a challenge made at the real depth
//  matches nothing, shows nothing, and leaves the entry for the depth that made it. The depth is not a
//  parameter, so no caller can pass the wrong one or forget it, and secure mode off is the same code at depth 0.
//
//  In memory only, in this stage. See `IdentityChallenge+Store.swift`.
//

import Foundation
import OccultaFormats

extension ContactManager: IdentityChallenge.ChallengeLedger {

    /// The store for the current depth. Reads create nothing: the first write at a depth does.
    private var readableChallengeStore: IdentityChallenge.OutstandingChallengeStore? {
        self.challengeStores[self.security.currentDepth]
    }

    private var writableChallengeStore: IdentityChallenge.OutstandingChallengeStore {
        let depth = self.security.currentDepth
        if let store = self.challengeStores[depth] { return store }
        let store = IdentityChallenge.OutstandingChallengeStore()
        self.challengeStores[depth] = store
        return store
    }

    func challenge(for contactID: String) -> IdentityChallenge.OutstandingChallenge? {
        self.readableChallengeStore?.challenge(for: contactID)
    }

    func hasOutstanding(for contactID: String, now: Date) -> Bool {
        self.readableChallengeStore?.hasOutstanding(for: contactID, now: now) ?? false
    }

    func record(_ challenge: IdentityChallenge.OutstandingChallenge, for contactID: String, now: Date) throws {
        try self.writableChallengeStore.record(challenge, for: contactID, now: now)
    }

    func settle(nonce: Data, for contactID: String, passedAt: Date?) {
        self.readableChallengeStore?.settle(nonce: nonce, for: contactID, passedAt: passedAt)
    }

    func verifiedAt(for contactID: String) -> Date? {
        self.readableChallengeStore?.verifiedAt(for: contactID)
    }

    /// Every depth's store, not the current one's: an expired entry can't be acted on at any depth.
    func sweepExpired(now: Date) {
        for store in self.challengeStores.values {
            store.sweepExpired(now: now)
        }
    }
}

extension ContactManager: IdentityChallenge.ChallengeSealer {

    /// A contact is sent a challenge or response in group format when recorded at `.bodyDigestCapable`, which only
    /// rises. Below it, or with a stranded marker, the long-term format, which every build reads (prekey continuity §3.4).
    func groupSealer(for contactID: String) -> ((IdentityChallengeEnvelope) throws -> URL)? {
        guard
            let contact = try? self.fetchContact(by: contactID),
            Self.resolveTargetVersion(for: contact, using: Manager.Crypto()).isAtLeast(.bodyDigestCapable)
        else { return nil }

        // It travels in the layout a message to the same contact would: streamed, with only a manifest, when the
        // contact can read that. A layout of its own would tell it apart from a message (STREAMING_SPEC §3).
        return { envelope in
            let name = (UUID().uuidString.components(separatedBy: "-").last ?? "unknown") + ".occ"
            let url  = FileManager.default.temporaryDirectory.appendingPathComponent(name)
            try self.encryptBundle(
                for: contactID, identityChallenge: envelope,
                output: .file(destination: url, attachments: nil, memoryGuard: .system)
            )
            return url
        }
    }
}
