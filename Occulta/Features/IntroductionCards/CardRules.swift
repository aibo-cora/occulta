//
//  CardRules.swift
//  Occulta
//

import Foundation
import OccultaFormats

/// What a contact's card says about the contact, from the field and the in-person keys.
nonisolated
enum CardTier: Equatable {
    case pending
    case notVerified
    case verified
}

/// What importing a card into a contact does (`Docs/Features/Introduction Cards/SPEC.md` §6.3).
nonisolated
enum CardImportDecision: Equatable {
    /// The field is empty.
    case importNew
    /// The field is `imported`: waiting on an earlier card. The new state overwrites the old one.
    case replace
    /// The field is `issued` (the cards crossed) and the incoming card's agreement key sorts lower:
    /// cancel our card, then import.
    case cancelOwnAndImport
    case refuse(Refusal)

    enum Refusal: Equatable {
        /// A conversation is live. A card claiming to be from the peer must not replace it.
        case alreadyTalking
        /// The cards crossed and ours sorts lower, so ours survives.
        case ownCardWins
        case expired
        /// The card is one of ours. Importing it would start a conversation with ourselves.
        case ownCard
    }
}

nonisolated
enum CardSweepAction: Equatable {
    case keep
    case clear
}

/// The rules for a contact's card field. Pure: it reads the values it's given and touches nothing else.
/// Keys, storage and the clock belong to the callers.
nonisolated
enum CardRules {

    /// Computed from the field and never stored. In-person keys win: a contact met in person is verified
    /// whatever the field says.
    static func tier(_ state: CardState, hasInPersonKeys: Bool) -> CardTier {
        if hasInPersonKeys { return .verified }
        switch state {
        case .imported, .conversation: return .notVerified
        case .empty, .issued:          return .pending
        }
    }

    /// Decides what importing `incoming` into a contact whose field is `current` does, at `now`.
    ///
    /// An expired card is refused whatever the field holds, and so is one of our own: `ownIssuedAgreementKeys`
    /// holds the agreement public key of every card we have issued, on any contact at any depth, which the
    /// caller gathers. When the cards crossed (`current` is `issued`), the card with the lower agreement public
    /// key survives on both phones, compared bytewise, so exactly one does. A tie can only be a copy of our
    /// own card, which the own-card refusal already caught; if it got here it keeps ours. An own card that
    /// no longer parses can't win and is cancelled.
    static func importDecision(current: CardState, incoming: IntroductionCard, now: Date, ownIssuedAgreementKeys: Set<Data>) -> CardImportDecision {
        guard incoming.expiresAt > now else { return .refuse(.expired) }
        guard !ownIssuedAgreementKeys.contains(incoming.agreementKey) else { return .refuse(.ownCard) }

        switch current {
        case .empty:
            return .importNew
        case .imported:
            return .replace
        case .conversation:
            return .refuse(.alreadyTalking)
        case .issued(let card, _, _, _, _):
            guard let own = IntroductionCard.recognize(card) else { return .cancelOwnAndImport }
            return incoming.agreementKey.lexicographicallyPrecedes(own.agreementKey) ? .cancelOwnAndImport : .refuse(.ownCardWins)
        }
    }

    /// The unlock sweep (§6.4): an expired `issued` card is cancelled, and an expired `imported` one is
    /// cleared unless a first message may have left.
    static func sweep(_ state: CardState, now: Date) -> CardSweepAction {
        switch state {
        case .issued(_, _, _, _, let expiresAt):
            return expiresAt <= now ? .clear : .keep
        case .imported(_, _, _, _, _, _, let expiresAt, let sentFirstMessage):
            return expiresAt <= now && !sentFirstMessage ? .clear : .keep
        case .empty, .conversation:
            return .keep
        }
    }

    /// Whether Carol's phone may send. Past `expiresAt` she may not send a first message, so it doesn't
    /// send one that can't open; once she has sent one, she may keep sending.
    static func canSend(_ state: CardState, now: Date) -> Bool {
        switch state {
        case .imported(_, _, _, _, _, _, let expiresAt, let sentFirstMessage):
            return sentFirstMessage || now < expiresAt
        case .conversation:
            return true
        case .empty, .issued:
            return false
        }
    }

    /// The §8 hard blocks: vault trustee, shard content, payment cards, identity challenge, Presence
    /// Verification and groups refuse a contact for whom this is true.
    static func isHardBlocked(_ state: CardState) -> Bool {
        switch state {
        case .imported, .conversation: return true
        case .empty, .issued:          return false
        }
    }
}
