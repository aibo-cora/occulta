//
//  PairingSecretState+Swap.swift
//  Occulta
//
//  How a pairing from before this fix gets its secret (`bugs.md` Bug 196): each side sends a random half in its
//  one-time-prekey slots, the secret is made from both, and the sides confirm to each other. Pure functions over the
//  state: `ContactManager+PairingSecret` applies them to the contact's key row.
//
//  The steps, for two phones A and B, each in `.none`:
//  1. A sends its half `hA` in a one-time-prekey slot (`.swapping(hA)`).
//  2. B receives it, makes `hB` and the secret S = combine(hA, hB): `.held(S, unconfirmed, ourHalf: hB)`. B's next one-time
//     slot carries `hB` and a confirmation over it, which only a holder of S can make.
//  3. A receives that, makes S from `hA` and `hB`, and the confirmation verifies: `.held(S, confirmed, ourHalf: hA)`. A now
//     sends the new form, and its next one-time slot carries `hA` and its confirmation.
//  4. B's confirmation check on A's slot passes: B is confirmed, and sends the new form too. Each side drops its half
//     when a file of the new form arrives from the other, which proves that they hold S and have seen our confirmation.
//  Crossing sends, where both are `.swapping`, agree because the halves are sorted. A lost message leaves the old form
//  working: nothing is sent in the new form until a side holds the other's confirmation.
//
//  A classical pairing's half travels only in a one-time-prekey slot, never a long-term or last-resort one: such a slot
//  opens again, so a half in it could be read from a saved copy.
//

import Foundation
import OccultaFormats

extension PairingSecretState {

    /// What the next one-time-prekey slot to this peer carries, and the state after it. `nil` swap is filler.
    ///
    /// - Parameters:
    ///   - peerCanHold: whether the peer is recorded at the pairing-secret tier. Nothing starts before that.
    ///   - newHalf: a fresh random half, asked for only when a swap begins.
    func outgoingSwap(
        peerCanHold: Bool, newHalf: () throws -> Data
    ) throws -> (swap: PairingSecretSwap?, state: PairingSecretState?) {
        switch self.phase {
        case .none:
            guard peerCanHold else { return (nil, nil) }
            let half = try newHalf()
            var next = self
            next.phase = .swapping(ourHalf: half)
            return (try Self.halfSwap(half), next)

        case .swapping(let half):
            return (try Self.halfSwap(half), nil)

        case .held(let secret, _, let half?):
            return (try Self.halfSwap(half, confirmation: PairingSecret.confirmation(secret: secret, ownHalf: half)), nil)

        case .held(_, _, nil):
            return (nil, nil)
        }
    }

    /// The state after the peer's half arrives in one of their one-time-prekey slots that we opened, or `nil` when it
    /// changes nothing.
    ///
    /// The caller has already established that the slot is a one-time-prekey one and that the sender is authenticated.
    func receiving(_ swap: PairingSecretSwap, newHalf: () throws -> Data) throws -> PairingSecretState? {
        guard swap.kind == .half, swap.key.count == PairingSecret.size else { return nil }

        switch self.phase {
        case .none:
            let half = try newHalf()
            guard let secret = try? PairingSecret.combine(half, swap.key) else { return nil }
            var next = self
            // A confirmation can't verify yet: it would need the secret this half is only now making.
            next.phase = .held(secret: secret, peerConfirmed: false, ourHalf: half)
            return next

        case .swapping(let half):
            guard let secret = try? PairingSecret.combine(half, swap.key) else { return nil }
            var next = self
            let confirmed = PairingSecret.isValidConfirmation(swap.confirmation, secret: secret, peerHalf: swap.key)
            next.phase = .held(secret: secret, peerConfirmed: confirmed, ourHalf: half)
            return next

        case .held(let secret, false, let half):
            // A confirmation over the half they sent, made with a secret only a holder has: they hold it.
            guard PairingSecret.isValidConfirmation(swap.confirmation, secret: secret, peerHalf: swap.key) else { return nil }
            var next = self
            next.phase = .held(secret: secret, peerConfirmed: true, ourHalf: half)
            return next

        case .held(_, true, _):
            return nil
        }
    }

    /// The state after a file of the new form from the peer opened and its slot proof verified. That proves they hold the
    /// secret, and that they have seen our confirmation, since they send the new form only once they hold ours: our half
    /// has done its work, and the peer has switched, so from here an old-form file naming them by identity is one sent
    /// before the switch and arriving late, or another pairing's, and the record refuses it like one that began with a
    /// secret (decided 2026-11-04). `nil` when nothing changes.
    func afterTaggedFile() -> PairingSecretState? {
        guard case .held(let secret, let confirmed, let half) = self.phase else { return nil }
        guard !confirmed || half != nil || !self.refusesOldForm else { return nil }
        var next = self
        next.phase = .held(secret: secret, peerConfirmed: true, ourHalf: nil)
        next.refusesOldForm = true
        return next
    }

    /// A swap carrying `half`. Without a confirmation, random bytes of the same size stand in for one.
    private static func halfSwap(_ half: Data, confirmation: Data? = nil) throws -> PairingSecretSwap {
        PairingSecretSwap(kind: .half, key: half, confirmation: try confirmation ?? PairingSecret.newHalf())
    }
}
