//
//  BEKArrayTests.swift
//  OccultaTests
//
//  VAULT_KEY_LAYERING.md §8 item 8 — the write algorithm must throw on a
//  corrupt/unreadable slot rather than silently replacing it with fresh filler
//  (the bug found and fixed here before it shipped, then found live in
//  Manager.LayerStore as Bug 107). Pure crypto/logic, no Secure Enclave, no
//  gating needed.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

@Suite("BEKArray — 32-slot BEK array crypto and slot logic")
struct BEKArrayTests {

    private typealias Array_ = VaultManager.BEKArray

    private func makePayload(bekBytes: Data = Data.randomBytes(32)) -> BackupEncryptionKey.Payload {
        BackupEncryptionKey.Payload(
            bekBytes: bekBytes, distributionID: UUID(), shardMetadata: nil
        )
    }

    // MARK: Round trip

    @Test("Write then read the same slot returns the same payload")
    func roundTripSingleSlot() throws {
        let array = Array_(backend: InMemoryBEKArrayBackend())
        let key = SymmetricKey(size: .bits256)
        let payload = makePayload()

        try array.write(payload, slotIndex: 5, vaultKey: key)
        let read = try array.read(slotIndex: 5, vaultKey: key)

        #expect(read?.bekBytes == payload.bekBytes)
        #expect(read?.distributionID == payload.distributionID)
    }

    @Test("Reading a slot when the array has never been written at all returns nil, not a throw")
    func readOnCompletelyEmptyBackendReturnsNil() throws {
        let array = Array_(backend: InMemoryBEKArrayBackend())
        let key = SymmetricKey(size: .bits256)

        let read = try array.read(slotIndex: 0, vaultKey: key)

        #expect(read == nil)
    }

    @Test("An untouched slot reads as nil — genuinely empty, not an error")
    func untouchedSlotReadsAsNil() throws {
        let array = Array_(backend: InMemoryBEKArrayBackend())
        let key = SymmetricKey(size: .bits256)

        try array.write(makePayload(), slotIndex: 0, vaultKey: key)
        let read = try array.read(slotIndex: 1, vaultKey: key)

        #expect(read == nil)
    }

    // MARK: Full-array reseal (item 7) preserves other slots

    @Test("Writing to one slot preserves a previously-written different slot's content")
    func writingOneSlotPreservesAnother() throws {
        let array = Array_(backend: InMemoryBEKArrayBackend())
        let key = SymmetricKey(size: .bits256)
        let first = makePayload()
        let second = makePayload()

        try array.write(first, slotIndex: 3, vaultKey: key)
        try array.write(second, slotIndex: 20, vaultKey: key)

        let readFirst = try array.read(slotIndex: 3, vaultKey: key)
        let readSecond = try array.read(slotIndex: 20, vaultKey: key)

        #expect(readFirst?.bekBytes == first.bekBytes)
        #expect(readSecond?.bekBytes == second.bekBytes)
    }

    @Test("A third write still preserves both earlier slots")
    func thirdWritePreservesEarlierTwo() throws {
        let array = Array_(backend: InMemoryBEKArrayBackend())
        let key = SymmetricKey(size: .bits256)
        let a = makePayload()
        let b = makePayload()
        let c = makePayload()

        try array.write(a, slotIndex: 0, vaultKey: key)
        try array.write(b, slotIndex: 1, vaultKey: key)
        try array.write(c, slotIndex: 31, vaultKey: key)

        #expect(try array.read(slotIndex: 0, vaultKey: key)?.bekBytes == a.bekBytes)
        #expect(try array.read(slotIndex: 1, vaultKey: key)?.bekBytes == b.bekBytes)
        #expect(try array.read(slotIndex: 31, vaultKey: key)?.bekBytes == c.bekBytes)
    }

    // MARK: File size

    @Test("A file present but the wrong total size throws fileSizeMismatch, not treated as first creation")
    func wrongFileSizeThrows() throws {
        let backend = InMemoryBEKArrayBackend()
        try backend.write(Data.randomBytes(100))   // present, but not Array_.fileSize
        let array = Array_(backend: backend)
        let key = SymmetricKey(size: .bits256)

        #expect(throws: Array_.Error.fileSizeMismatch) {
            try array.read(slotIndex: 0, vaultKey: key)
        }
        #expect(throws: Array_.Error.fileSizeMismatch) {
            try array.write(makePayload(), slotIndex: 0, vaultKey: key)
        }
    }

    // MARK: The actual point — corruption is never silently treated as empty

    @Test("A corrupted slot throws corruptSlot on read, not nil")
    func corruptedSlotThrowsOnRead() throws {
        let backend = InMemoryBEKArrayBackend()
        let array = Array_(backend: backend)
        let key = SymmetricKey(size: .bits256)

        try array.write(makePayload(), slotIndex: 4, vaultKey: key)

        var file = try backend.read()
        // Flip a byte inside slot 4's ciphertext region.
        let slotOffset = 4 * Array_.slotCiphertextSize
        file[file.startIndex + slotOffset] ^= 0xFF
        try backend.write(file)

        #expect(throws: Array_.Error.corruptSlot(index: 4)) {
            try array.read(slotIndex: 4, vaultKey: key)
        }
    }

    @Test("A corrupted slot halts a write to a different slot — never silently replaced with filler")
    func corruptedSlotHaltsWriteToAnotherSlot() throws {
        let backend = InMemoryBEKArrayBackend()
        let array = Array_(backend: backend)
        let key = SymmetricKey(size: .bits256)
        let real = makePayload()

        try array.write(real, slotIndex: 4, vaultKey: key)

        var file = try backend.read()
        let slotOffset = 4 * Array_.slotCiphertextSize
        file[file.startIndex + slotOffset] ^= 0xFF
        try backend.write(file)

        // Writing to an unrelated slot (10) must still notice slot 4 is corrupt
        // and halt, rather than silently sealing fresh filler over it.
        #expect(throws: Array_.Error.corruptSlot(index: 4)) {
            try array.write(makePayload(), slotIndex: 10, vaultKey: key)
        }

        // Confirming the halt actually prevented the write: the file on disk is
        // unchanged from before the attempted write (still readable for slot 4
        // as corrupt, not silently replaced).
        #expect(throws: Array_.Error.corruptSlot(index: 4)) {
            try array.read(slotIndex: 4, vaultKey: key)
        }
    }

    @Test("Wrong key on read throws corruptSlot, not nil — a wrong key must never look like 'empty'")
    func wrongKeyThrowsNotNil() throws {
        let array = Array_(backend: InMemoryBEKArrayBackend())
        let key = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)

        try array.write(makePayload(), slotIndex: 7, vaultKey: key)

        #expect(throws: Array_.Error.corruptSlot(index: 7)) {
            try array.read(slotIndex: 7, vaultKey: wrongKey)
        }
    }
}
