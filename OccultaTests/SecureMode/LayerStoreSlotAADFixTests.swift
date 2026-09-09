//
//  LayerStoreSlotAADFixTests.swift
//  OccultaTests
//
//  Bug 106 — Manager.LayerStore sealed every slot with no AAD at all, so nothing bound a
//  slot's ciphertext to its own position in the file. Fixed by adding LayerStoreSlotAAD
//  (SecureMode+LayerStore.swift), mirroring VaultManager.Backup.SlotAAD's shape, with a
//  fallback to the pre-fix (no-AAD) scheme on open so existing files keep reading and get
//  upgraded on the very next push()/pop() — both already reseal every slot unconditionally.
//
//  These tests go through the public API only (push/pop/readPayload) plus raw CryptoKit
//  calls a test file can make itself — LayerStoreSlotAAD is private to its own file, by
//  design, so there's nothing to unit-test about the AAD value directly, only its effect.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

@Suite("LayerStore — Bug 106 AAD fix and migration")
struct LayerStoreSlotAADFixTests {

    private func makePayload(sequenceNumber: Int, slotIndex: Int) -> LayerPayload {
        LayerPayload(sequenceNumber: sequenceNumber, slotIndex: slotIndex, contacts: [])
    }

    /// Hand-builds a file in the pre-fix format: every slot sealed with no AAD at all,
    /// matching exactly what push()/pop() produced before this fix shipped.
    private func makeLegacyFile(realPayload: LayerPayload, atSlot target: Int, key: SymmetricKey) throws -> Data {
        var file = Data(capacity: Manager.LayerStore.slotCount * Manager.LayerStore.slotCiphertextSize)
        for i in 0..<Manager.LayerStore.slotCount {
            if i == target {
                var plaintext = try JSONEncoder().encode(realPayload)
                plaintext.append(contentsOf: repeatElement(0, count: Manager.LayerStore.slotPlaintextSize - plaintext.count))
                file.append(try AES.GCM.seal(plaintext, using: key).combined!)
            } else {
                var random = Data(count: Manager.LayerStore.slotPlaintextSize)
                _ = random.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
                file.append(try AES.GCM.seal(random, using: key).combined!)
            }
        }
        return file
    }

    @Test("A legacy, pre-fix slot (sealed with no AAD) still opens via readPayload's fallback")
    func legacySlotStillOpensViaFallback() throws {
        let backend = InMemoryLayerStoreBackend()
        let key     = SymmetricKey(size: .bits256)
        let payload = self.makePayload(sequenceNumber: 11, slotIndex: 4)

        try backend.write(try self.makeLegacyFile(realPayload: payload, atSlot: 4, key: key))

        let store = Manager.LayerStore(backend: backend)
        let read  = try store.readPayload(key: key, slotIndex: 4, expectedSequenceNumber: 11)

        #expect(read.sequenceNumber == 11)
        #expect(read.slotIndex == 4)
    }

    @Test("Popping a legacy file re-seals every slot under the new AAD scheme, not just the target")
    func popUpgradesLegacyFileToNewScheme() throws {
        let backend = InMemoryLayerStoreBackend()
        let key     = SymmetricKey(size: .bits256)
        let payload = self.makePayload(sequenceNumber: 5, slotIndex: 2)

        try backend.write(try self.makeLegacyFile(realPayload: payload, atSlot: 2, key: key))

        let store = Manager.LayerStore(backend: backend)
        _ = try store.pop(key: key, slotIndex: 2, expectedSequenceNumber: 5)

        // Slot 2 is now erased filler. Check a slot that was pure filler both before and
        // after (slot 3) to see whether the *preserve* path — not just the popped slot —
        // adopted the new scheme.
        let fileData = try backend.read()
        let offset   = 3 * Manager.LayerStore.slotCiphertextSize
        let cipher   = fileData[offset..<(offset + Manager.LayerStore.slotCiphertextSize)]
        let box      = try AES.GCM.SealedBox(combined: cipher)

        // Opening under the OLD (no-AAD) scheme must now fail — proves this slot was
        // re-sealed under the new AAD-bound scheme during the pop(), not left untouched.
        #expect(throws: (any Swift.Error).self) {
            try AES.GCM.open(box, using: key)
        }
    }

    @Test("A slot's ciphertext relocated to another position is discarded, not silently preserved there")
    func relocatedCiphertextIsDiscardedNotPreserved() throws {
        let backend = InMemoryLayerStoreBackend()
        let key     = SymmetricKey(size: .bits256)
        let store   = Manager.LayerStore(backend: backend)

        try store.push(self.makePayload(sequenceNumber: 55, slotIndex: 5), key: key, slotIndex: 5)

        // Simulate a slot-swap: copy slot 5's ciphertext into slot 6's position, leaving
        // slot 5 itself untouched. A pure file-level move — no key needed to do this.
        var fileData  = try backend.read()
        let slotSize  = Manager.LayerStore.slotCiphertextSize
        let slot5Range = (5 * slotSize)..<(6 * slotSize)
        let slot6Range = (6 * slotSize)..<(7 * slotSize)
        fileData.replaceSubrange(slot6Range, with: fileData[slot5Range])
        try backend.write(fileData)

        // Any push touches every slot's preserve logic, including the tampered slot 6.
        try store.push(self.makePayload(sequenceNumber: 1, slotIndex: 20), key: key, slotIndex: 20)

        // Before this fix: slot 6 decrypted fine (no AAD check at all in the preserve
        // path), decoded as slot 5's real, valid payload, and was silently re-sealed at
        // position 6 — corrupting it permanently. A targeted read afterward would throw
        // .slotIndexMismatch specifically, because the content is real and decodable,
        // just carrying the wrong field. After this fix: slot 6's relocated ciphertext
        // fails to open under its own AAD, so the preserve path replaces it with fresh
        // random filler instead of carrying the theft forward. That filler decrypts fine
        // under its own new AAD (it's genuinely, correctly sealed) but is random bytes —
        // so the failure now surfaces as a JSON decoding error, not .slotIndexMismatch,
        // because there is no longer any decodable payload at slot 6 to mismatch against.
        do {
            _ = try store.readPayload(key: key, slotIndex: 6, expectedSequenceNumber: 55)
            Issue.record("Expected slot 6 to no longer hold the relocated payload at all")
        } catch Manager.LayerStore.Error.slotIndexMismatch {
            Issue.record("Slot 6 still decoded as slot 5's real payload — the relocation was preserved, not discarded")
        } catch is DecodingError {
            // Expected: slot 6 is fresh, correctly-sealed random filler now, not slot 5's
            // preserved content — there's nothing decodable left to mismatch against.
        } catch {
            Issue.record("Expected a JSON decoding error (fresh filler), got \(error)")
        }
    }
}
