//
//  ContactManager+ChallengeLedger.swift
//  Occulta
//
//  Identity-challenge state, a sealed per-depth property of the contact (`bugs.md` Bug 180).
//
//  The state is `Contact.Profile.challengeStateEncrypted`: one slot per depth (`ChallengeStateCodec`). Every method
//  here reads `security.currentDepth` itself, here and only here, and touches that depth's slot. A session at another
//  depth finds an empty slot: a reply to a challenge made at the real depth matches nothing, shows nothing, and leaves
//  the entry for the depth that made it. The depth is not a parameter, so no caller can pass the wrong one or forget
//  it, and secure mode off is the same code at depth 0 over the same column.
//
//  Only the sweep looks at every depth, and it only clears what has expired.
//
//  A column that is nil, won't open or won't decode reads as empty, and never throws: the state lives for at most an
//  hour and the owner can challenge again, so there is nothing worth refusing a write for (unlike the card field).
//

import Foundation
import SwiftData
import CryptoKit
import OccultaFormats

extension Contact.Profile {

    /// The contact's challenge state, opened with the local DB key. A field that is nil, won't decrypt or won't
    /// decode reads as `.empty`, and never throws.
    var challengeState: ChallengeState {
        self.challengeState(opening: { $0.decrypt() })
    }

    /// Same as `challengeState`, under a local DB key the caller already derived, for passes over many contacts.
    func challengeState(using key: SymmetricKey) -> ChallengeState {
        self.challengeState(opening: { $0.decrypt(using: key) })
    }

    private func challengeState(opening open: (Data) -> Data?) -> ChallengeState {
        guard
            let sealed = self.challengeStateEncrypted,
            let plaintext = open(sealed),
            let state = try? ChallengeStateCodec().decode(plaintext)
        else { return .empty }
        return state
    }
}

extension ContactManager {

    /// Seals `state` into `contact`, at the fixed `ChallengeStateCodec.capacity` whatever the state. Doesn't save;
    /// the caller does.
    func store(_ state: ChallengeState, for contact: Contact.Profile) throws {
        guard let sealed = try ChallengeStateCodec().encode(state).encrypt() else {
            throw IdentityChallenge.LedgerError.cannotStore
        }
        contact.challengeStateEncrypted = sealed
    }
}

extension ContactManager: IdentityChallenge.ChallengeLedger {

    /// The contact's row. Not filtered by depth: the presence oracle `fetchContact(by:)` already is.
    private func challengeContact(_ contactID: String) -> Contact.Profile? {
        try? self.fetchContact(by: contactID)
    }

    /// The slot of the depth that is open now.
    private func currentSlot(of contactID: String) -> ChallengeState.Slot? {
        self.challengeContact(contactID)?.challengeState[depth: self.security.currentDepth]
    }

    func challenge(for contactID: String) -> IdentityChallenge.OutstandingChallenge? {
        self.currentSlot(of: contactID)?.challenge
    }

    func hasOutstanding(for contactID: String, now: Date) -> Bool {
        guard let challenge = self.challenge(for: contactID) else { return false }
        return !challenge.isExpired(at: now)
    }

    func record(_ challenge: IdentityChallenge.OutstandingChallenge, for contactID: String, now: Date) throws {
        guard let contact = self.challengeContact(contactID) else { throw IdentityChallenge.LedgerError.contactUnknown }
        let depth = self.security.currentDepth
        var state = contact.challengeState
        if let existing = state[depth: depth].challenge, !existing.isExpired(at: now) {
            throw IdentityChallenge.LedgerError.alreadyOutstanding
        }
        state[depth: depth].challenge = challenge
        try self.write(state, to: contact, flush: false)
    }

    func settle(nonce: Data, for contactID: String, passedAt: Date?) {
        guard let contact = self.challengeContact(contactID) else { return }
        let depth = self.security.currentDepth
        var state = contact.challengeState
        // No write for a nonce this depth doesn't hold: a stray reply must leave no trace on disk.
        guard state[depth: depth].challenge?.nonce == nonce else { return }
        state[depth: depth].challenge = nil
        if let passedAt {
            state[depth: depth].verifiedAt = UInt64(max(0, passedAt.timeIntervalSince1970))
        }
        // Best effort. If the write fails the entry stays and expires with the hour.
        try? self.write(state, to: contact, flush: true)
    }

    func verifiedAt(for contactID: String) -> Date? {
        self.currentSlot(of: contactID)?.verifiedAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// Every contact and every depth, not the current depth's: an expired slot can't be acted on at any depth, and
    /// clearing only this one would leave the others on disk. Writes only if something expired. A column that won't
    /// open is left alone: it holds nothing readable, and a write replaces it.
    func sweepExpired(now: Date) {
        guard let key = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey() else { return }
        var changed = false

        for contact in (try? self.fetchAllContacts()) ?? [] {
            guard
                let sealed = contact.challengeStateEncrypted,
                let plaintext = sealed.decrypt(using: key),
                var state = try? ChallengeStateCodec().decode(plaintext),
                state.removeExpired(now: now),
                let resealed = try? ChallengeStateCodec().encode(state).encrypt(using: key)
            else { continue }
            contact.challengeStateEncrypted = resealed
            changed = true
        }

        if changed { try? self.saveAndFlush() }
    }

    /// Seals `state` into `contact` and saves. A failure puts the previous column back: nothing half-written.
    /// `flush` also checkpoints the write-ahead log, so the cleared slot's predecessor leaves it
    /// (`saveAndFlush`); a create just saves.
    private func write(_ state: ChallengeState, to contact: Contact.Profile, flush: Bool) throws {
        let previous = contact.challengeStateEncrypted
        do {
            try self.store(state, for: contact)
            if flush { try self.saveAndFlush() } else { try self.modelContext.save() }
        } catch {
            contact.challengeStateEncrypted = previous
            throw IdentityChallenge.LedgerError.cannotStore
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
