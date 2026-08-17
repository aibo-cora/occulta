//
//  RotationRegistry.swift
//  Occulta
//
//  Created by Yura on 8/16/26.
//

import Foundation

/// Which persisted models hold ciphertext under the **local DB key** — the key a Secure Mode
/// activation or deactivation rotates — and which are sealed under a key that never rotates.
///
/// **Why this exists.** The rotation stages a new local DB key, re-encrypts, commits, then
/// deletes the superseded key. A model left out of that middle step is sealed under a key that
/// no longer exists, permanently: the hybrid key needs a Secure Enclave half that is
/// non-exportable, so there is no repair pass on this device or any other. `Group` and
/// `AppLayerConfig` were missed exactly this way (Bugs 75 and 76), and every failure of this
/// class is silent by design — unreadable fields are nil-ed, read accessors have safe
/// fallbacks, and the system degrades quietly for forensic reasons.
///
/// **Putting a model in the wrong list is a bug in both directions.** Omitting one that holds
/// local-DB ciphertext strands it when the old key is deleted. Adding one that is sealed under
/// the shard-custody or vault key re-seals it under the DB key and strands it the other way
/// round.
///
/// **What checks it.** `RotationRegistryTests` asserts these two lists partition
/// `OccultaApp.schema` exactly — every persisted model classified once, and no entry naming a
/// model that is no longer persisted. That anchor matters: the schema is load-bearing, so a new
/// model cannot reach the store without passing through this check.
///
/// The check is deliberately *type-level*. It cannot tell whether a **field** on an already
/// classified model is covered — that is `EncryptedFieldCoverageTests`' job — nor whether a
/// model listed as rotated is actually re-keyed in both paths. See
/// `Docs/Features/Secure Mode/ROTATION_COVERAGE.md`.
///
/// The prose equivalent of these tables lives in `SecureMode+RotationContract.md`, and is
/// the reason this file exists: that table was written on 2026-06-01 and already omitted
/// `PotentiallyLostShard`, which had been in the schema since 2026-05-06. A careful manual
/// enumeration missed one of eighteen on the day it was made.
enum RotationRegistry {

    /// Holds ciphertext under the local DB key — **must** be re-keyed in *both*
    /// `activateSecureMode` and `deactivateSecureMode`. They are separate code paths and
    /// nothing links them; `Message.Draft` was correct in activation from the start and absent
    /// from deactivation until 2026-08-14.
    ///
    /// Keyed by the model's SwiftData entity name; the value records what is sealed.
    static let rotated: [String: String] = [
        "Profile":         "every text field, images, visibleThroughDepth, globalTrusteeDepth, originDepth, signedAttributes, forwardSecrecyEncrypted, maxBundleVersion, deletionToken — Contact.Profile, via reencryptAllFields",
        "PhoneNumber":     "value and label — Contact.Profile.PhoneNumber, swept by reencryptAllFields",
        "EmailAddress":    "value and label — Contact.Profile.EmailAddress, swept by reencryptAllFields",
        "PostalAddress":   "all address components — Contact.Profile.PostalAddress, swept by reencryptAllFields",
        "URLAddress":      "value and label — Contact.Profile.URLAddress, swept by reencryptAllFields",
        "Key":             "material, acquiredAt, owner, expiredOn, quantumKeyMaterialEncrypted — Contact.Profile.Key, via reencryptKeyRecords",
        "Draft":           "encryptedRecipientID, encryptedContent — Message.Draft, via reKeyOrPurgeAll",
        "Group":           "encryptedID, encryptedName, encryptedCreatedAt, all 32 membership depths — via Group.reencrypt(from:to:)",
        "AppLayerConfig":  "persistedDepth, pinEnabled, coercerBaseDepth, lockoutCountEncrypted, lockoutAnchorUptimeEncrypted, pinEnabledPerDepth — via AppLayerConfig.reencrypt(from:to:). Verifiers and blob metadata are NOT here: they are under the SE Secure Mode key and must stay out",
        "VaultEntry":      "visibleThroughDepth ONLY — label and value are under the vault key and must not be rotated. Re-keyed by an inline loop in both paths, not a model-level helper",
    ]

    /// Sealed under a key that never rotates, or holding no ciphertext at all. Adding one of
    /// these to the rotation would re-seal it under the wrong key and strand it.
    static let notRotated: [String: String] = [
        "Message":                  "declared but never used — the only reference outside its own file is the schema registration itself, so no code path creates a row and no ciphertext exists to strand. RE-CLASSIFY if that changes: `origin` and `content` are documented as encrypted and would be local-DB ciphertext.",
        "CustodyShard":             "shard custody key (SE, .privateKeyUsage) — automatic shard operations run without user approval, so the key must be derivable while the vault is locked",
        "ReconstructShard":         "return-buffer key — scoped to a single reconstruction session",
        "PendingShardDistribute":   "shard custody key (SE, .privateKeyUsage)",
        "PendingShardStatusUpdate": "shard custody key (SE, .privateKeyUsage)",
        "PotentiallyLostShard":     "shard custody key (SE, .privateKeyUsage) — sealed and updated while the vault is locked, during inbound bundle processing. Absent from the rotation contract's table since it was written; the omission was benign, this list is where it is now recorded",
        "GlobalShardConfig":        "shard custody key (SE, .privateKeyUsage) — orphaned by the per-contact globalTrusteeDepth migration and scheduled for removal, blocked on the absence of a VersionedSchema/SchemaMigrationPlan",
        "BackupEncryptionKey":      "vault key (SE, biometry or passcode) — deliberately gated on user presence",
    ]
}
