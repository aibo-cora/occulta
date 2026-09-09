//
//  BEKSlotAADTests.swift
//  OccultaTests
//
//  VAULT_KEY_LAYERING.md §5 — AAD must bind a slot's own index, so a slot swap
//  fails at AES-GCM's tag-verification step rather than needing to be caught by
//  application logic after the wrong slot's ciphertext has already been accepted.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

@Suite("BEKSlotAAD — per-slot AAD for the BEK array")
struct BEKSlotAADTests {

    private typealias SlotAAD = VaultManager.Backup.SlotAAD

    @Test("Deterministic — the same slot index always produces the same AAD")
    func deterministicForSameIndex() {
        #expect(SlotAAD.aad(slotIndex: 5) == SlotAAD.aad(slotIndex: 5))
    }

    @Test("Different slot indices produce different AAD, across the whole valid range")
    func distinctAcrossValidRange() {
        let all = SlotAAD.validRange.map { SlotAAD.aad(slotIndex: $0) }
        #expect(Set(all).count == all.count)
    }

    @Test("Valid range is exactly 0..<32 — its own constant, not borrowed from AppLayerConfig")
    func validRangeIsItsOwnConstant() {
        #expect(SlotAAD.slotCount == 32)
        #expect(SlotAAD.validRange == 0..<32)
    }

    // MARK: The actual security property

    @Test("Sealing under one slot's AAD and opening under another's fails authentication — the whole point")
    func crossSlotOpenFailsAuthentication() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("this is slot 2's real content".utf8)

        let sealedAtSlot2 = try AES.GCM.seal(
            plaintext, using: key, authenticating: SlotAAD.aad(slotIndex: 2)
        )

        // Attacker copies slot 2's ciphertext into slot 0's position and the app
        // tries to open it as if it were slot 0's content.
        #expect(throws: (any Error).self) {
            try AES.GCM.open(
                sealedAtSlot2, using: key, authenticating: SlotAAD.aad(slotIndex: 0)
            )
        }
    }

    @Test("Sealing and opening under the matching slot index succeeds")
    func sameSlotOpenSucceeds() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("this is slot 7's real content".utf8)

        let sealed = try AES.GCM.seal(
            plaintext, using: key, authenticating: SlotAAD.aad(slotIndex: 7)
        )
        let opened = try AES.GCM.open(
            sealed, using: key, authenticating: SlotAAD.aad(slotIndex: 7)
        )

        #expect(opened == plaintext)
    }

    @Test("A swap between the two boundary slots (0 and 31) also fails authentication")
    func boundarySlotSwapFailsAuthentication() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data.randomBytes(32)

        let sealedAtSlot31 = try AES.GCM.seal(
            plaintext, using: key, authenticating: SlotAAD.aad(slotIndex: 31)
        )

        #expect(throws: (any Error).self) {
            try AES.GCM.open(
                sealedAtSlot31, using: key, authenticating: SlotAAD.aad(slotIndex: 0)
            )
        }
    }
}
