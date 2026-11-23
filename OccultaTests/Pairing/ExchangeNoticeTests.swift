//
//  ExchangeNoticeTests.swift
//  OccultaTests
//
//  What the key-exchange screen says when an exchange ends without a result (2.0.5 review). A reveal that does not open its
//  commitment, or a message that was changed in transit, ends in `.failed`; it used to show the same "didn't connect, move
//  closer" notice as a timeout, so an active attack read as poor ranging and the person simply retried.
//

import Testing
@testable import Occulta

@MainActor
@Suite("Key exchange — the notice each way an exchange can end")
struct ExchangeNoticeTests {

    @Test("A timeout, a failed exchange and a peer that needs to update each have a notice of their own")
    func distinct() {
        let notices = [ExchangeManager.ExchangePhase.timedOut, .failed, .peerNeedsUpdate].map { KeyExchange.notice(for: $0) }
        #expect(notices == [.timedOut, .failed, .peerNeedsUpdate])
        #expect(Set(notices.compactMap { $0 }).count == 3, "no two share one")
    }

    @Test("A failed exchange is not shown as a timeout")
    func failedIsNotATimeout() {
        #expect(KeyExchange.notice(for: .failed) != KeyExchange.notice(for: .timedOut))
    }

    @Test("A phase with no result to report has no notice")
    func others() {
        for phase in [ExchangeManager.ExchangePhase.resting, .searching, .found, .connected, .complete] {
            #expect(KeyExchange.notice(for: phase) == nil, "\(phase)")
        }
    }
}
