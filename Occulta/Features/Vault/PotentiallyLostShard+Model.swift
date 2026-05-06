//
//  PotentiallyLostShard+Model.swift
//  Occulta
//
//  Tracks shards that were confirmed delivered but have since disappeared from
//  a trustee's custodyManifest. Populated while the vault is locked (when the
//  vault key is unavailable); processed and cleared the next time the vault
//  unlocks via VaultManager.drainPotentiallyLostShards().
//
//  Lifecycle:
//  - Inserted by ShardCustodyManager.processInboundManifest when a PendingShardDistribute
//    row is confirmed (ID appears in trustee's custodyManifest) and the distribute row
//    is deleted.
//  - isAbsent is set to true when a subsequent manifest does not include the ID,
//    and reset to false when a manifest includes it again.
//  - All rows for a contact are deleted at vault unlock. Absent rows (isAbsent == true)
//    with status .confirmed trigger an updateShardStatus(.lost) before deletion.
//
//  Privacy model:
//  - attributeID and contactIdentifier are stored in plaintext. Neither field reveals
//    vault entry content — attributeID is an opaque UUID and contactIdentifier is
//    already present in other non-encrypted indexes. Cold-disk forensics learns
//    "N shards are being watched for a given contact" — no vault content is exposed.
//

import Foundation
import SwiftData

@Model
final class PotentiallyLostShard {

    var id: UUID = UUID()

    /// Shard attributeID that was confirmed delivered (distribute row deleted).
    var attributeID: UUID

    /// Contact whose custodyManifest confirmed delivery.
    var contactIdentifier: String

    /// Set to true when a subsequent manifest for this contact does not include
    /// attributeID. Reset to false when a manifest includes it again.
    /// Rows where isAbsent == true are checked against vault status at unlock.
    var isAbsent: Bool = false

    init(attributeID: UUID, contactIdentifier: String) {
        self.attributeID       = attributeID
        self.contactIdentifier = contactIdentifier
    }
}
