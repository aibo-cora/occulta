//
//  CustodyManifestPaddingTests.swift
//  OccultaTests
//
//  Bug 162: the custody manifest a trustee sends the owner is padded with random IDs, so its
//  size doesn't tell how many of the owner's depths have a backup. Simulator-safe — uses
//  TestKeyManager throughout.
//

import Testing
import SwiftData
import Foundation
@testable import Occulta
@testable import OccultaFormats

@Suite("Custody manifest padding (Bug 162)")
@MainActor struct CustodyManifestPaddingTests {

    @Test("Up to the floor, every manifest pads to the floor", arguments: [0, 1, 3, 32])
    func padsToFloor(count: Int) {
        let real   = (0..<count).map { _ in UUID() }
        let padded = ContactManager.paddedCustodyManifest(real)
        #expect(padded.count == ContactManager.custodyManifestFloor)
        #expect(Array(padded.prefix(count)) == real)
    }

    @Test("The floor is one ID per possible depth")
    func floorMatchesDepthCount() {
        #expect(ContactManager.custodyManifestFloor == AppLayerConfig.maxDepthCount)
    }

    @Test("Above the floor, a manifest pads to the next doubling tier")
    func padsAboveFloorToTier() {
        let real   = (0..<33).map { _ in UUID() }
        let padded = ContactManager.paddedCustodyManifest(real)
        #expect(padded.count == 64)
        #expect(Array(padded.prefix(33)) == real)
    }

    @Test("Filler IDs are distinct from each other and from the real ones")
    func fillerIsDistinct() {
        let real   = [UUID()]
        let padded = ContactManager.paddedCustodyManifest(real)
        #expect(Set(padded).count == padded.count)
    }

    @Test("An owner given a padded manifest confirms only the piece it really holds, and adds no other watch rows")
    func ownerIgnoresFiller() throws {
        let schema = Schema([CustodyShard.self, PendingShardDistribute.self, PotentiallyLostShard.self])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let custody   = ShardCustodyManager(modelContainer: container, keyManager: TestKeyManager())

        let held     = try self.piece()
        let notHeld  = try self.piece()
        try custody.queueDistribute(attribute: held, for: "bob")
        try custody.queueDistribute(attribute: notHeld, for: "bob")

        try custody.processInboundManifest(ContactManager.paddedCustodyManifest([held.id]), from: "bob")

        let context = ModelContext(container)
        #expect(try context.fetch(FetchDescriptor<PotentiallyLostShard>()).count == 1,
                "one watch row, for the confirmed piece; none for filler")
        #expect(try context.fetch(FetchDescriptor<PendingShardDistribute>()).count == 1,
                "the piece Bob doesn't hold stays queued")
    }

    private func piece() throws -> SignedAttribute {
        let signer    = TestKeyManager()
        let id        = UUID()
        let value     = Data([UInt8(1)]) + Data.randomBytes(32)
        let createdAt = Date()
        let entryID   = UUID()
        let payload   = SignedAttribute.signingPayload(
            id: id, category: .shard, value: value, entryID: entryID, createdAt: createdAt, expiresAt: nil
        )
        return SignedAttribute(
            id: id, label: SignedAttribute.backupKeyPieceLabel, value: value, category: .shard,
            signature: try signer.signData(payload), createdAt: createdAt, expiresAt: nil, entryID: entryID
        )
    }
}
