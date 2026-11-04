//
//  PairingSwapTests.swift
//  OccultaTests
//
//  Bug 196, stage 6: how a pairing from before this fix gets its secret. The transitions are pure functions over the
//  state, so two phones are two states passing swaps to each other; what the real send and open do with them is
//  tested through `ContactManager` below.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Two phones

/// Two phones' states for one pairing, and what each sends in its next one-time-prekey slot.
private struct Pairing {
    var a: PairingSecretState = .empty
    var b: PairingSecretState = .empty

    /// `a`'s next one-time slot, delivered to `b`. Returns whether it changed `b`.
    @discardableResult mutating func aSends(peerCanHold: Bool = true) throws -> Bool {
        let (swap, next) = try self.a.outgoingSwap(peerCanHold: peerCanHold) { try PairingSecret.newHalf() }
        if let next { self.a = next }
        guard let swap else { return false }
        guard let received = try self.b.receiving(swap, newHalf: { try PairingSecret.newHalf() }) else { return false }
        self.b = received
        return true
    }

    @discardableResult mutating func bSends(peerCanHold: Bool = true) throws -> Bool {
        let (swap, next) = try self.b.outgoingSwap(peerCanHold: peerCanHold) { try PairingSecret.newHalf() }
        if let next { self.b = next }
        guard let swap else { return false }
        guard let received = try self.a.receiving(swap, newHalf: { try PairingSecret.newHalf() }) else { return false }
        self.a = received
        return true
    }

    /// Either side's new-form file reaching the other.
    mutating func aSendsNewForm() { if let next = self.b.afterTaggedFile() { self.b = next } }
    mutating func bSendsNewForm() { if let next = self.a.afterTaggedFile() { self.a = next } }
}

@Suite("Bug 196 — the swap's transitions")
struct PairingSwapTransitionTests {

    @Test("A starts, B answers, A confirms: both hold the same secret and both are confirmed")
    func oneSideStarts() throws {
        var p = Pairing()
        try p.aSends()                       // hA in a slot
        #expect(p.a.phase != .none)
        #expect(p.b.secret != nil && !p.b.sendsNewForm, "B holds the secret but hasn't seen A's confirmation")

        try p.bSends()                       // hB and B's confirmation
        #expect(p.a.secret == p.b.secret)
        #expect(p.a.sendsNewForm, "A saw B's confirmation")
        #expect(!p.b.sendsNewForm)

        try p.aSends()                       // A's confirmation
        #expect(p.b.sendsNewForm)
        #expect(p.a.secret == p.b.secret && p.a.secret?.count == 32)
    }

    @Test("Crossing first sends agree")
    func crossing() throws {
        var p = Pairing()
        // Both begin before either arrives: each is `.swapping` with its own half.
        let (swapA, nextA) = try p.a.outgoingSwap(peerCanHold: true) { try PairingSecret.newHalf() }
        let (swapB, nextB) = try p.b.outgoingSwap(peerCanHold: true) { try PairingSecret.newHalf() }
        p.a = try #require(nextA); p.b = try #require(nextB)
        let fromA = try #require(swapA), fromB = try #require(swapB)

        let afterA = try p.a.receiving(fromB, newHalf: { try PairingSecret.newHalf() })
        let afterB = try p.b.receiving(fromA, newHalf: { try PairingSecret.newHalf() })
        p.a = try #require(afterA)
        p.b = try #require(afterB)

        #expect(p.a.secret == p.b.secret && p.a.secret != nil)
        #expect(!p.a.sendsNewForm && !p.b.sendsNewForm, "neither has seen a confirmation yet")

        try p.aSends(); try p.bSends()
        #expect(p.a.sendsNewForm && p.b.sendsNewForm)
    }

    @Test("A half is dropped once the other side's new-form file arrives")
    func halfDropped() throws {
        var p = Pairing()
        try p.aSends(); try p.bSends(); try p.aSends()
        guard case .held(_, _, let halfA) = p.a.phase, case .held(_, _, let halfB) = p.b.phase else { Issue.record("not held"); return }
        #expect(halfA != nil && halfB != nil, "both still hold their halves, sending their confirmations")

        p.bSendsNewForm()
        p.aSendsNewForm()

        guard case .held(_, let confirmedA, let afterA) = p.a.phase, case .held(_, let confirmedB, let afterB) = p.b.phase else {
            Issue.record("not held"); return
        }
        #expect(afterA == nil && afterB == nil)
        #expect(confirmedA && confirmedB)
        #expect(p.a.secret == p.b.secret)
    }

    @Test("A lost message leaves the old form working: nothing is sent in the new form without the other's confirmation")
    func lostMessage() throws {
        var p = Pairing()
        try p.aSends()
        // B's answer is lost: B holds the secret, A holds only its half.
        #expect(p.b.secret != nil)
        #expect(p.a.secret == nil && !p.a.sendsNewForm)
        #expect(!p.b.sendsNewForm)

        // A keeps sending the same half; B, already holding, ignores the repeat.
        guard case .swapping(let half) = p.a.phase else { Issue.record("A should still be swapping"); return }
        try p.aSends()
        guard case .swapping(let again) = p.a.phase else { Issue.record("A should still be swapping"); return }
        #expect(half == again, "a retry sends the same half")

        // The next answer from B arrives and the swap completes.
        try p.bSends()
        #expect(p.a.secret == p.b.secret && p.a.sendsNewForm)
    }

    @Test("Nothing starts before the peer is recorded at the tier")
    func tierGate() throws {
        var p = Pairing()
        #expect(try p.aSends(peerCanHold: false) == false)
        #expect(p.a == .empty && p.b == .empty)
    }

    @Test("A peer's own half echoed back, or a half of the wrong size, makes nothing")
    func badHalves() throws {
        let half = try PairingSecret.newHalf()
        let swapping = PairingSecretState(phase: .swapping(ourHalf: half), refusesOldForm: false)
        #expect(try swapping.receiving(PairingSecretSwap(kind: .half, key: half, confirmation: half), newHalf: { half }) == nil)
        #expect(try PairingSecretState.empty.receiving(
            PairingSecretSwap(kind: .half, key: Data(count: 31), confirmation: half), newHalf: { half }) == nil)
        #expect(try PairingSecretState.empty.receiving(
            PairingSecretSwap(kind: .none, key: half, confirmation: half), newHalf: { try PairingSecret.newHalf() }) == nil)
        #expect(try PairingSecretState.empty.receiving(
            PairingSecretSwap(kind: .unsupported, key: half, confirmation: half), newHalf: { try PairingSecret.newHalf() }) == nil)
    }

    @Test("A forged confirmation does not confirm")
    func forgedConfirmation() throws {
        var p = Pairing()
        try p.aSends()                                       // B holds S
        guard case .swapping(let hA) = p.a.phase else { Issue.record("A should be swapping"); return }
        _ = hA
        let (swap, _) = try p.b.outgoingSwap(peerCanHold: true) { try PairingSecret.newHalf() }
        let honest = try #require(swap)
        let forged = PairingSecretSwap(kind: .half, key: honest.key, confirmation: try PairingSecret.newHalf())

        let afterForged = try #require(try p.a.receiving(forged, newHalf: { try PairingSecret.newHalf() }))
        #expect(afterForged.secret != nil)
        #expect(!afterForged.sendsNewForm, "a confirmation nobody made with the secret confirms nothing")
    }

    @Test("A pairing that derived its secret ignores a swap")
    func derivedIgnoresSwaps() throws {
        let derived = PairingSecretState.derived(secret: try PairingSecret.newHalf())
        #expect(try derived.receiving(PairingSecretSwap(kind: .half, key: try PairingSecret.newHalf(),
                                                       confirmation: try PairingSecret.newHalf()), newHalf: { try PairingSecret.newHalf() }) == nil)
        let (swap, next) = try derived.outgoingSwap(peerCanHold: true) { try PairingSecret.newHalf() }
        #expect(swap == nil && next == nil)
        #expect(derived.afterTaggedFile() == nil)
    }

    @Test("The swap changes nothing about whether old form is refused")
    func refusalIsSticky() throws {
        var p = Pairing()
        p.a = PairingSecretState(phase: .none, refusesOldForm: true)
        try p.aSends(); try p.bSends()
        #expect(p.a.refusesOldForm)
        #expect(!p.b.refusesOldForm)
    }

    @Test("The codec keeps a held state's half, and refuses the flag on any other state")
    func codecKeepsHalf() throws {
        let half = try PairingSecret.newHalf(), secret = try PairingSecret.newHalf()
        let state = PairingSecretState(phase: .held(secret: secret, peerConfirmed: true, ourHalf: half), refusesOldForm: false)
        let plaintext = try PairingSecretCodec().encode(state)
        #expect(plaintext.count == PairingSecretCodec.capacity)
        #expect(try PairingSecretCodec().decode(plaintext) == state)

        var bad = try PairingSecretCodec().encode(.empty)
        bad[2] |= 0x04
        #expect(throws: PairingSecretCodec.CodecError.malformed) { try PairingSecretCodec().decode(bad) }
    }
}
