//
//  CardRulesTests.swift
//  OccultaTests
//
//  The rules for a contact's card field (`Docs/Features/Introduction Cards/SPEC.md` §5, §6.3, §6.4, §8).
//  Pure: the rules read what they're given. Cards that must parse use software keys.
//

import Testing
import Foundation

@testable import Occulta
@testable import OccultaFormats

@Suite("Card rules — tier, import, sweep, send, blocks")
struct CardRulesTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private var later: Date { self.now.addingTimeInterval(3_600) }
    private var earlier: Date { self.now.addingTimeInterval(-3_600) }

    // MARK: - States

    private func issued(card: Data = randomBytes(1_770), expiresAt: Date) -> CardState {
        .issued(card: card, agreementKey: randomBytes(143), signingKey: randomBytes(143), mlkemKey: randomBytes(4_788), expiresAt: expiresAt)
    }

    private func imported(expiresAt: Date, sent: Bool) -> CardState {
        .imported(
            peerCard: randomBytes(1_770), agreementKey: randomBytes(143), signingKey: randomBytes(143), mlkemKey: randomBytes(4_788),
            ss1: randomBytes(32), ct1: randomBytes(1_568), expiresAt: expiresAt, sentFirstMessage: sent
        )
    }

    private func conversation(bootstrapOpen: Bool = true) -> CardState {
        .conversation(
            agreementKey: randomBytes(143), signingKey: randomBytes(143),
            peerAgreementKey: randomBytes(65), peerSigningKey: randomBytes(65),
            quantum: QuantumKeyMaterial(
                encapsulatedSecret: randomBytes(32), decapsulatedSecret: randomBytes(32),
                ourCiphertext: randomBytes(1_568), peerCiphertext: randomBytes(1_568)
            ),
            bootstrapOpen: bootstrapOpen, isIssuer: false
        )
    }

    // MARK: - Tier

    @Test("Tier: in-person keys win; otherwise empty and issued are pending, imported and conversation not verified")
    func tierForEveryState() {
        let states: [(String, CardState, CardTier)] = [
            ("empty", .empty, .pending),
            ("issued", self.issued(expiresAt: self.later), .pending),
            ("issued, expired", self.issued(expiresAt: self.earlier), .pending),
            ("imported", self.imported(expiresAt: self.later, sent: false), .notVerified),
            ("imported, sent", self.imported(expiresAt: self.earlier, sent: true), .notVerified),
            ("conversation, bootstrap open", self.conversation(bootstrapOpen: true), .notVerified),
            ("conversation, settled", self.conversation(bootstrapOpen: false), .notVerified),
        ]
        for (name, state, expected) in states {
            #expect(CardRules.tier(state, hasInPersonKeys: false) == expected, "\(name) without in-person keys")
            #expect(CardRules.tier(state, hasInPersonKeys: true) == .verified, "\(name) with in-person keys")
        }
    }

    // MARK: - Import: the plain cases

    @Test("A card that expires at or before now is refused as expired, whatever the field holds")
    func expiredIsRefusedFirst() {
        let states: [(String, CardState)] = [
            ("empty", .empty),
            ("issued", self.issued(expiresAt: self.later)),
            ("imported", self.imported(expiresAt: self.later, sent: false)),
            ("conversation", self.conversation()),
        ]
        for expiry in [self.now, self.earlier, Date(timeIntervalSince1970: 0)] {
            let incoming = makeShapedCard(expiresAt: expiry)
            for (name, state) in states {
                #expect(CardRules.importDecision(current: state, incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .refuse(.expired), "\(name), expiry \(expiry.timeIntervalSince1970)")
            }
        }
    }

    @Test("An unexpired card: empty imports, imported is replaced, a conversation refuses")
    func importDecisionForEachState() {
        let incoming = makeShapedCard(expiresAt: self.now.addingTimeInterval(1))

        #expect(CardRules.importDecision(current: .empty, incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .importNew)
        #expect(CardRules.importDecision(current: self.imported(expiresAt: self.later, sent: false), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .replace)
        #expect(CardRules.importDecision(current: self.imported(expiresAt: self.later, sent: true), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .replace)
        #expect(CardRules.importDecision(current: self.imported(expiresAt: self.earlier, sent: true), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .replace, "an expired imported field is still replaced")
        #expect(CardRules.importDecision(current: self.conversation(bootstrapOpen: true), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .refuse(.alreadyTalking))
        #expect(CardRules.importDecision(current: self.conversation(bootstrapOpen: false), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .refuse(.alreadyTalking))
    }

    // MARK: - Import: crossing cards (SPEC §6.3)

    @available(iOS 26, *)
    @Test("Crossing cards: the lower agreement key survives, decided identically on both phones")
    func crossingCardsHaveExactlyOneSurvivor() throws {
        // Two issuers, ordered by agreement key, so both assignments of "who is Alice" are covered deterministically.
        var pair = [try CardTestIssuer(), try CardTestIssuer()]
        pair.sort { bytewiseLess($0.card.agreementKey, $1.card.agreementKey) }
        let (lower, higher) = (pair[0], pair[1])
        #expect(bytewiseLess(lower.card.agreementKey, higher.card.agreementKey), "control: the keys differ")

        let unrelated: Set<Data> = [randomBytes(65), randomBytes(65)]
        for (alice, bob, unrelatedKeys) in [(lower, higher, Set<Data>()), (higher, lower, Set<Data>()), (lower, higher, unrelated), (higher, lower, unrelated)] {
            // Each phone has issued a card and now imports the other's. A phone's own-card set holds the
            // agreement key of every card it issued: its own card, here, plus any unrelated ones.
            let aliceField = self.issued(card: alice.card.encoded, expiresAt: self.later)
            let bobField   = self.issued(card: bob.card.encoded, expiresAt: self.later)
            let aliceOwn = unrelatedKeys.isEmpty ? Set<Data>() : unrelatedKeys.union([alice.card.agreementKey])
            let bobOwn   = unrelatedKeys.isEmpty ? Set<Data>() : unrelatedKeys.union([bob.card.agreementKey])
            let onAlice = CardRules.importDecision(current: aliceField, incoming: bob.card, now: self.now, ownIssuedAgreementKeys: aliceOwn)
            let onBob   = CardRules.importDecision(current: bobField, incoming: alice.card, now: self.now, ownIssuedAgreementKeys: bobOwn)

            let aliceHasLower = bytewiseLess(alice.card.agreementKey, bob.card.agreementKey)
            // The phone whose own card is lower keeps it and refuses; the other cancels its own and imports.
            #expect(onAlice == (aliceHasLower ? .refuse(.ownCardWins) : .cancelOwnAndImport))
            #expect(onBob   == (aliceHasLower ? .cancelOwnAndImport : .refuse(.ownCardWins)))

            // Exactly one of them cancels, and the card that survives on both phones is the same one.
            let cancels = [onAlice, onBob].filter { $0 == .cancelOwnAndImport }
            let refuses = [onAlice, onBob].filter { $0 == .refuse(.ownCardWins) }
            #expect(cancels.count == 1 && refuses.count == 1)
            let survivorOnAlice = onAlice == .cancelOwnAndImport ? bob.card : alice.card
            let survivorOnBob   = onBob == .cancelOwnAndImport ? alice.card : bob.card
            #expect(survivorOnAlice == survivorOnBob)
            #expect(survivorOnAlice == lower.card, "the lower agreement key wins")
        }
    }

    @available(iOS 26, *)
    @Test("Crossing cards with many random pairs: always exactly one survivor, the lower key")
    func crossingCardsManyPairs() throws {
        for _ in 0 ..< 25 {
            let alice = try CardTestIssuer(), bob = try CardTestIssuer()
            let onAlice = CardRules.importDecision(current: self.issued(card: alice.card.encoded, expiresAt: self.later), incoming: bob.card, now: self.now, ownIssuedAgreementKeys: [])
            let onBob   = CardRules.importDecision(current: self.issued(card: bob.card.encoded, expiresAt: self.later), incoming: alice.card, now: self.now, ownIssuedAgreementKeys: [])

            #expect((onAlice == .cancelOwnAndImport) != (onBob == .cancelOwnAndImport), "exactly one cancels")
            #expect((onAlice == .refuse(.ownCardWins)) != (onBob == .refuse(.ownCardWins)), "exactly one refuses")
            let lowerIsBobs = bytewiseLess(bob.card.agreementKey, alice.card.agreementKey)
            #expect((onAlice == .cancelOwnAndImport) == lowerIsBobs)
        }
    }

    @available(iOS 26, *)
    @Test("A tie, which only a copy of the user's own card could cause, keeps the user's card")
    func tieKeepsOwnCard() throws {
        let own = try CardTestIssuer()
        let decision = CardRules.importDecision(current: self.issued(card: own.card.encoded, expiresAt: self.later), incoming: own.card, now: self.now, ownIssuedAgreementKeys: [])
        #expect(decision == .refuse(.ownCardWins))
    }

    @Test("An own card that no longer parses can't win: it is cancelled")
    func unparseableOwnCardIsCancelled() {
        let incoming = makeShapedCard(expiresAt: self.later)
        #expect(CardRules.importDecision(current: self.issued(card: randomBytes(1_770), expiresAt: self.later), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .cancelOwnAndImport)
        #expect(CardRules.importDecision(current: self.issued(card: Data(), expiresAt: self.later), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .cancelOwnAndImport)
    }

    @Test("An expired incoming card is refused as expired even when the cards crossed and its key sorts lower")
    func expiredBeatsKeyOrder() {
        let incoming = makeShapedCard(agreementKey: Data(count: 65), expiresAt: self.earlier)
        #expect(CardRules.importDecision(current: self.issued(expiresAt: self.later), incoming: incoming, now: self.now, ownIssuedAgreementKeys: []) == .refuse(.expired))
    }

    // MARK: - Import: the user's own card

    private func everyState() -> [(String, CardState)] {
        [
            ("empty", .empty),
            ("issued", self.issued(expiresAt: self.later)),
            ("imported", self.imported(expiresAt: self.later, sent: false)),
            ("conversation", self.conversation()),
        ]
    }

    @Test("A card whose agreement key is one the user issued is refused as their own, for every current state")
    func ownCardIsRefusedForEveryState() {
        let incoming = makeShapedCard(expiresAt: self.later)
        let others: Set<Data> = [randomBytes(65), randomBytes(65)]
        for keys in [Set([incoming.agreementKey]), others.union([incoming.agreementKey])] {
            for (name, state) in self.everyState() {
                #expect(CardRules.importDecision(current: state, incoming: incoming, now: self.now, ownIssuedAgreementKeys: keys) == .refuse(.ownCard), "\(name), \(keys.count) own keys")
            }
        }
    }

    @Test("An own card that is expired is refused as expired: expiry comes first")
    func expiredOwnCardIsExpired() {
        for expiry in [self.now, self.earlier] {
            let incoming = makeShapedCard(expiresAt: expiry)
            for (name, state) in self.everyState() {
                #expect(CardRules.importDecision(current: state, incoming: incoming, now: self.now, ownIssuedAgreementKeys: [incoming.agreementKey]) == .refuse(.expired), "\(name)")
            }
        }
    }

    @Test("A card not in the own set behaves as before, whatever the set holds")
    func foreignCardIgnoresTheOwnSet() {
        let incoming = makeShapedCard(expiresAt: self.later)
        let unrelated: Set<Data> = [randomBytes(65), randomBytes(65), Data(), Data(incoming.agreementKey.dropLast())]
        let expected: [String: CardImportDecision] = ["empty": .importNew, "imported": .replace, "conversation": .refuse(.alreadyTalking)]
        for keys in [Set<Data>(), unrelated] {
            for (name, state) in self.everyState() where name != "issued" {
                #expect(CardRules.importDecision(current: state, incoming: incoming, now: self.now, ownIssuedAgreementKeys: keys) == expected[name], "\(name)")
            }
        }
    }

    @Test("The own-card check compares whole keys: a key that differs in one byte is not the user's own")
    func ownCardNeedsAnExactMatch() {
        let incoming = makeShapedCard(expiresAt: self.later)
        var nearly = [UInt8](incoming.agreementKey); nearly[64] ^= 0x01
        #expect(CardRules.importDecision(current: .empty, incoming: incoming, now: self.now, ownIssuedAgreementKeys: [Data(nearly)]) == .importNew)
    }

    @available(iOS 26, *)
    @Test("A copy of the user's own issued card is refused as their own, not as a tie")
    func copyOfOwnCardIsOwnCard() throws {
        let own = try CardTestIssuer()
        let field = self.issued(card: own.card.encoded, expiresAt: self.later)
        #expect(CardRules.importDecision(current: field, incoming: own.card, now: self.now, ownIssuedAgreementKeys: [own.card.agreementKey]) == .refuse(.ownCard))
        #expect(CardRules.importDecision(current: .empty, incoming: own.card, now: self.now, ownIssuedAgreementKeys: [own.card.agreementKey]) == .refuse(.ownCard), "on another contact, at another depth")
    }

    // MARK: - Sweep

    @Test("Sweep: an expired issued card is cleared; an unexpired one is kept")
    func sweepIssued() {
        #expect(CardRules.sweepClears(self.issued(expiresAt: self.earlier), now: self.now))
        #expect(CardRules.sweepClears(self.issued(expiresAt: self.now), now: self.now), "at the deadline")
        #expect(!CardRules.sweepClears(self.issued(expiresAt: self.later), now: self.now))
    }

    @Test("Sweep: an expired imported card is cleared only if no first message may have left")
    func sweepImported() {
        #expect(CardRules.sweepClears(self.imported(expiresAt: self.earlier, sent: false), now: self.now))
        #expect(CardRules.sweepClears(self.imported(expiresAt: self.now, sent: false), now: self.now), "at the deadline")
        #expect(!CardRules.sweepClears(self.imported(expiresAt: self.earlier, sent: true), now: self.now), "a message may have left")
        #expect(!CardRules.sweepClears(self.imported(expiresAt: self.later, sent: false), now: self.now))
        #expect(!CardRules.sweepClears(self.imported(expiresAt: self.later, sent: true), now: self.now))
    }

    @Test("Sweep keeps empty and conversation fields")
    func sweepKeepsTheRest() {
        #expect(!CardRules.sweepClears(.empty, now: self.now))
        #expect(!CardRules.sweepClears(self.conversation(bootstrapOpen: true), now: self.now))
        #expect(!CardRules.sweepClears(self.conversation(bootstrapOpen: false), now: self.now))
    }

    // MARK: - Send

    @Test("canSend: imported until the deadline or once a message has left; a conversation always; empty and issued never")
    func canSendForEveryState() {
        #expect(!CardRules.canSend(.empty, now: self.now))
        #expect(!CardRules.canSend(self.issued(expiresAt: self.later), now: self.now))
        #expect(!CardRules.canSend(self.issued(expiresAt: self.earlier), now: self.now))

        #expect(CardRules.canSend(self.imported(expiresAt: self.later, sent: false), now: self.now))
        #expect(CardRules.canSend(self.imported(expiresAt: self.later, sent: true), now: self.now))
        #expect(!CardRules.canSend(self.imported(expiresAt: self.earlier, sent: false), now: self.now), "no first message after the deadline")
        #expect(!CardRules.canSend(self.imported(expiresAt: self.now, sent: false), now: self.now), "not at the deadline either")
        #expect(CardRules.canSend(self.imported(expiresAt: self.earlier, sent: true), now: self.now), "no timer once one has left")
        #expect(CardRules.canSend(self.imported(expiresAt: self.now, sent: true), now: self.now))

        #expect(CardRules.canSend(self.conversation(bootstrapOpen: true), now: self.now))
        #expect(CardRules.canSend(self.conversation(bootstrapOpen: false), now: self.now))
    }

    // MARK: - Hard blocks (SPEC §8)

    @Test("Hard blocks: imported and conversation, nothing else")
    func hardBlocks() {
        #expect(!(CardState.empty).isCardContact)
        #expect(!(self.issued(expiresAt: self.later)).isCardContact)
        #expect(!(self.issued(expiresAt: self.earlier)).isCardContact)
        #expect((self.imported(expiresAt: self.later, sent: false)).isCardContact)
        #expect((self.imported(expiresAt: self.earlier, sent: true)).isCardContact)
        #expect((self.conversation(bootstrapOpen: true)).isCardContact)
        #expect((self.conversation(bootstrapOpen: false)).isCardContact)
    }

    @Test("A hard-blocked state is never pending: the block and the tier agree")
    func blockAndTierAgree() {
        let states: [CardState] = [
            .empty, self.issued(expiresAt: self.later), self.imported(expiresAt: self.later, sent: false),
            self.imported(expiresAt: self.earlier, sent: true), self.conversation(),
        ]
        for state in states {
            #expect((state).isCardContact == (CardRules.tier(state, hasInPersonKeys: false) == .notVerified))
        }
    }
}
