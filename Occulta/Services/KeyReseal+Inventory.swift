//
//  KeyReseal+Inventory.swift
//  Occulta
//
//  The reseal inventory for Bug 171 (`Docs/Features/Secure Mode/bugs.md`): every attribute in
//  `OccultaApp.schema` that holds a sealed value, and every file sealed outside SwiftData, with what seals it.
//
//  Stage 2 moves what is sealed under the legacy keys onto the Enclave-bound ones (`enclaveBoundKey(_:)`), and
//  the passphrase migration after it reuses this table. A field missing from it is a field the reseal skips, and
//  a skipped field stays readable by anyone holding Q. So `ResealInventoryTests` fails if an attribute of type
//  `Data`, `[Data]` or `String` is in the schema and in neither `fields` nor `exempt`, and if an entry names an
//  attribute the schema no longer has.
//
//  Each entry says:
//    - key:       what seals it (`Key`);
//    - aad:       the authenticated data it was sealed with, which the reseal must pass again unchanged;
//    - filler:    whether a container of these also holds placeholders (`Filler`), which the reseal must treat
//                 as the uniform-change rule says: in a container that mixes real and filler members, either
//                 every member changes or none does;
//    - treatment: what the reseal does with it (`Treatment`).
//
//  Places checked that hold nothing sealed under these keys: `UserDefaults` and `@AppStorage` (plain settings;
//  the one flag the vault kept there is deleted at unlock), the keychain (the tier secrets, the tier PQ records and
//  Enclave keys are inputs to the keys, not data sealed under them), `InteropVectors.json` (wire bundles only), and the
//  Enclave-key blobs kept inside `Profile.prekeyRecordEncrypted` and `Profile.introductionCardEncrypted`, which
//  those two fields cover.
//

import Foundation

/// The reseal of data sealed under the keys Bug 171 changes. Stage 1 holds only its inventory.
nonisolated enum KeyReseal { }

extension KeyReseal {

    /// What seals a value.
    nonisolated enum Key {
        /// The local DB key: `createHybridLocalEncryptionKey()`, derived through `Manager.Ambient`.
        case local
        /// The shard custody key: `deriveShardCustodyKey()`.
        case custody
        /// The restore buffer key: `deriveRestoreVaultKey()`.
        case restore
        /// The vault key: `deriveVaultKey(context:)`. Needs the vault unlocked.
        case vault
        /// A PIN verifier: a key derived from `deriveSecureModeKey()` and the PIN, not the secure mode key itself.
        /// Stage 3 wraps it.
        case pin
        /// The compose staging key: `deriveComposeStagingKey()`, tier U's, which seals the draft attachments of a group or of a
        /// contact we hold no key for. A file, not a field; it has no legacy form (Stage 8), so the Stage 2 reseal has nothing
        /// of it to move, and the Stage 6 upgrade moves it from the classical form to the hybrid one.
        case compose
        /// A key this fix doesn't reseal: the per-entry key of a vault entry, a per-contact file key, the share
        /// staging key (Stage 5 moved what it seals under; a session is never resealed, it is swept after an hour), or
        /// the backup key.
        case other
    }

    /// The authenticated data a value was sealed with.
    nonisolated enum AAD {
        /// `EncryptionScheme.v2_hybridPQ.aad`, one byte `[2]`: every value sealed by `Data.encrypt()` or
        /// `Manager.Crypto.encrypt(data:)`.
        case fixed
        /// The row's own `aad()` or `aad(for:)`, bound to the row's `id`.
        case row
        /// None.
        case none
    }

    /// Whether a container holds placeholders next to real values.
    nonisolated enum Filler {
        /// No placeholders: the value is real or absent.
        case none
        /// Placeholders are real seals of a benign fixed value: an empty record, a gate set to enabled.
        case sealed
        /// Placeholders are random bytes of the length of a real value. They open under no key.
        case random
    }

    /// What the reseal does with the value.
    nonisolated enum Treatment {
        /// Moved by the reseal: opens under the legacy key, is rewritten under the new key with the same AAD and
        /// the same length. This is also how a field that no code writes any more is handled, if a row holds one.
        case reseal
        /// Sealed under the local key and also stored as a value in other records, so rewriting it breaks those
        /// references. Not resealed by default (`bugs.md` Bug 171, Stage 2 settles it on the evidence).
        case reference
        /// Sealed under a key this fix doesn't change. Left as it is.
        case notAffected
        /// Nothing in the current code writes it: nil or empty on every row, or the whole type is retired. The
        /// reseal still rewrites a sealed value if one is found, so nothing is left under the legacy key.
        case retired
    }

    /// The type of the attribute, as the schema reports it with `Optional` removed.
    nonisolated enum Shape {
        case data
        case dataArray
        case nestedDataArray
        /// Base64 of a sealed `Data`; `""` means empty and was never sealed.
        case string
    }

    nonisolated struct Field {
        /// The entity's name in `OccultaApp.schema`: `Profile` for `Contact.Profile`, `Draft` for `Message.Draft`.
        let model: String
        let attribute: String
        let shape: Shape
        let key: Key
        let aad: AAD
        let filler: Filler
        let treatment: Treatment
        let note: String

        init(
            _ model: String, _ attribute: String, _ shape: Shape,
            key: Key = .local, aad: AAD = .fixed, filler: Filler = .none,
            treatment: Treatment = .reseal, _ note: String = ""
        ) {
            self.model = model
            self.attribute = attribute
            self.shape = shape
            self.key = key
            self.aad = aad
            self.filler = filler
            self.treatment = treatment
            self.note = note
        }
    }

    /// An attribute of a type the guard looks at that holds nothing sealed.
    nonisolated struct Exempt {
        let model: String
        let attribute: String
        let reason: String
    }

    /// A file sealed outside SwiftData.
    nonisolated struct SealedFile {
        let name: String
        let location: String
        let key: Key
        /// The AAD, in words: a constant, or none.
        let aad: String
        let treatment: Treatment
        let note: String
    }
}

// MARK: - Fields

nonisolated extension KeyReseal {

    /// Every sealed `Data`, `[Data]`, `[[Data]]` and `String` attribute of `OccultaApp.schema`.
    static let fields: [Field] = [

        // MARK: Contact.Profile — strings
        //
        // Sealed by `ContactManager.save(contact:)` and `createContacts(from:)` as
        // `crypto.encrypt(data: …)?.base64EncodedString() ?? ""`. `convertToMutableCopy` reads `""` as empty.

        Field("Profile", "identifier", .string, treatment: .reference,
              "Reference key: the base64 ciphertext is stored as a value in `Group` member slots, `Draft.encryptedRecipientID`, the custody and shard payloads, the legacy keychain prekey tags `prekey.<identifier>.<uuid>`, and hashed into `TrusteeTag`. Rewriting it breaks all of them."),
        Field("Profile", "givenName", .string),
        Field("Profile", "familyName", .string),
        Field("Profile", "middleName", .string),
        Field("Profile", "namePrefix", .string),
        Field("Profile", "nameSuffix", .string),
        Field("Profile", "nickname", .string),
        Field("Profile", "organizationName", .string),
        Field("Profile", "departmentName", .string),
        Field("Profile", "jobTitle", .string),
        Field("Profile", "phoneticGivenName", .string, "No current code writes it; `\"\"` on every row."),
        Field("Profile", "phoneticMiddleName", .string, "No current code writes it; `\"\"` on every row."),
        Field("Profile", "phoneticFamilyName", .string, "No current code writes it; `\"\"` on every row."),
        Field("Profile", "birthday", .string),
        Field("Profile", "note", .string),

        // MARK: Contact.Profile — data

        Field("Profile", "thumbnailImageData", .data, "A photo: can be large."),
        Field("Profile", "imageData", .data, "A photo: can be large."),
        Field("Profile", "prekeyRecordEncrypted", .data, filler: .sealed,
              "`PrekeyRecordCodec.capacity` bytes of plaintext; an empty record for a contact without prekeys."),
        Field("Profile", "introductionCardEncrypted", .data, filler: .sealed,
              "`CardStateCodec.capacity` bytes of plaintext; the empty state for a contact without a card."),
        Field("Profile", "challengeStateEncrypted", .data, filler: .sealed,
              "`ChallengeStateCodec.capacity` bytes of plaintext; the empty state for a contact with no challenge at any depth."),
        Field("Profile", "forwardSecrecyEncrypted", .data, treatment: .retired,
              "`migratePrekeyRecords` carries it into `prekeyRecordEncrypted` and nils it. Private in the model; present in the schema."),
        Field("Profile", "signedAttributes", .data, treatment: .retired, "No code writes it."),
        Field("Profile", "deletionToken", .data, "nil on a live row; a sealed sentinel on a soft-deleted one."),
        Field("Profile", "visibleThroughDepth", .data, "Always set: a fixed-width `DepthCodec` value."),
        Field("Profile", "globalTrusteeDepth", .data, treatment: .retired, "Always a sealed -1 (Global Trustees are retired)."),
        Field("Profile", "maxBundleVersion", .data),
        Field("Profile", "originDepth", .data, "Always set: a fixed-width `DepthCodec` value."),

        // MARK: Contact.Profile.PhoneNumber, EmailAddress, PostalAddress, URLAddress

        Field("PhoneNumber", "label", .string),
        Field("PhoneNumber", "value", .string),
        Field("EmailAddress", "label", .string),
        Field("EmailAddress", "value", .string),
        Field("PostalAddress", "label", .string),
        Field("PostalAddress", "street", .string),
        Field("PostalAddress", "city", .string),
        Field("PostalAddress", "state", .string),
        Field("PostalAddress", "postalCode", .string),
        Field("PostalAddress", "country", .string),
        Field("PostalAddress", "isoCountryCode", .string),
        Field("URLAddress", "label", .string),
        Field("URLAddress", "value", .string),

        // MARK: Contact.Profile.Key

        Field("Key", "material", .data),
        Field("Key", "acquiredAt", .data),
        Field("Key", "owner", .data),
        Field("Key", "expiredOn", .data, "No current code sets it; only the v1 to v2 migration rewrote it."),
        Field("Key", "quantumKeyMaterialEncrypted", .data),

        // MARK: Contact.Message — retired

        Field("Message", "origin", .string, treatment: .retired, "Nothing reads or writes `Contact.Message`."),
        Field("Message", "recipients", .dataArray, treatment: .retired, "Nothing reads or writes `Contact.Message`."),
        Field("Message", "content", .data, treatment: .retired, "Nothing reads or writes `Contact.Message`."),

        // MARK: Message.Draft

        Field("Draft", "encryptedRecipientID", .data, aad: .row, "`aad(for: .recipientID)`: the draft's id ∥ 0x01."),
        Field("Draft", "encryptedContent", .data, aad: .row, "`aad(for: .content)`: the draft's id ∥ 0x02."),

        // MARK: Group

        Field("Group", "encryptedID", .data),
        Field("Group", "encryptedName", .data),
        Field("Group", "encryptedCreatedAt", .data),
        Field("Group", "realMemberSlots", .dataArray, filler: .random,
              "32 slots of 156 bytes; real ones are AES-GCM of a 128-byte padded identifier. Every depth's array changes together."),
        Field("Group", "duressMemberSlots", .dataArray, filler: .random, "As `realMemberSlots`."),
        Field("Group", "deeperMemberSlots", .nestedDataArray, filler: .random,
              "Depths 2...31, 32 slots each; empty on a group not yet edited since 1.9.1."),

        // MARK: VaultEntry

        Field("VaultEntry", "encryptedLabel", .data, key: .other, aad: .row, treatment: .notAffected,
              "Under the per-entry key, which `encryptedEntryKey` unwraps. `aad(for: .label)`."),
        Field("VaultEntry", "encryptedContent", .data, key: .other, aad: .row, treatment: .notAffected,
              "Under the per-entry key. `aad(for: .content)`."),
        Field("VaultEntry", "encryptedEntryKey", .data, key: .vault, aad: .row,
              "60 bytes: nonce, the 32-byte per-entry key, tag. `aad(for: .entryKey)`. Stage 4."),
        Field("VaultEntry", "shardDistributionEncrypted", .data, key: .other, treatment: .retired,
              "Retired with per-entry splitting; cleared on every row by `retireEntrySplittingIfNeeded`."),
        Field("VaultEntry", "visibleThroughDepth", .data, "A fixed-width `DepthCodec` value, or nil on an unclassified legacy entry."),
        Field("VaultEntry", "deletionToken", .data, "Always set: a live or orphaned one-byte sentinel."),

        // MARK: Shard custody

        Field("CustodyShard", "encryptedPayload", .data, key: .custody, aad: .row, "AAD is the row's id, as UTF-8."),
        Field("PendingShardDistribute", "encryptedPayload", .data, key: .custody, aad: .row, "AAD is the row's id, as UTF-8."),
        Field("PendingShardStatusUpdate", "encryptedPayload", .data, key: .custody, aad: .row, "AAD is the row's id, as UTF-8."),
        Field("PotentiallyLostShard", "encryptedPayload", .data, key: .custody, aad: .row, "AAD is the row's id, as UTF-8."),
        Field("GlobalShardConfig", "encryptedPayload", .data, key: .custody, aad: .row, treatment: .retired,
              "Retired; `migrateDeleteGlobalShardConfig` deletes any row. Still in the schema."),

        // MARK: Restore buffer

        Field("ReconstructShard", "encryptedPayload", .data, key: .restore, aad: .row, treatment: .retired,
              "Retired; `migrateReconstructShardsIfNeeded` moves any row into `PendingShamirSecretRestore` and deletes it, and deletes one it can't open."),
        Field("PendingShamirSecretRestore", "attributeID", .data, "A sealed UUID."),
        Field("PendingShamirSecretRestore", "deletionToken", .data, "Always set: a live or orphaned one-byte sentinel."),
        Field("PendingShamirSecretRestore", "shards", .data, key: .restore, aad: .row,
              "`ShardsCodec.payloadSize` bytes of plaintext, 255 padded slots inside. The AAD is the row's id, as UTF-8."),

        // MARK: BackupEncryptionKey
        //
        // A filler row (never claimed) has random bytes in all three fields. `depth` and `deletionToken` are under
        // the local key because orphaning runs without the vault unlocked.

        Field("BackupEncryptionKey", "depth", .data, filler: .random, "Random bytes on a filler row."),
        Field("BackupEncryptionKey", "deletionToken", .data, filler: .random, "Random bytes on a filler row."),
        Field("BackupEncryptionKey", "encryptedPayload", .data, key: .vault, aad: .row, filler: .random,
              "The AAD is the row's id, as UTF-8. Random bytes of the same length on a filler row. Stage 4."),

        // MARK: AppLayerConfig

        Field("AppLayerConfig", "sealedNormalVerifier", .data, key: .pin, aad: .none,
              "53 bytes: nonce, the 25-byte sentinel, tag. A flag more than a verifier: nil or not."),
        Field("AppLayerConfig", "sealedDuressVerifier", .data, key: .pin, aad: .none, "As `sealedNormalVerifier`."),
        Field("AppLayerConfig", "sealedNormalVerifiers", .dataArray, key: .pin, aad: .none, filler: .random,
              "32 entries of 53 bytes; random bytes on an unused slot."),
        Field("AppLayerConfig", "sealedDuressVerifiers", .dataArray, key: .pin, aad: .none, filler: .random,
              "As `sealedNormalVerifiers`."),
        Field("AppLayerConfig", "persistedDepth", .data, "Read by `Manager.Security.init`: it has to open before that runs."),
        Field("AppLayerConfig", "pinEnabled", .data, "Legacy scalar, read by the migration in `Manager.Security.init`."),
        Field("AppLayerConfig", "pinEnabledPerDepth", .dataArray, filler: .sealed,
              "32 entries of 29 bytes; a filler entry is a sealed `1`, like an enabled gate. Read by `Manager.Security.init`."),
        Field("AppLayerConfig", "coercerBaseDepth", .data),
        Field("AppLayerConfig", "lockoutCountEncrypted", .data, "nil means zero attempts."),
        Field("AppLayerConfig", "lockoutAnchorUptimeEncrypted", .data, "nil means not locked out."),
        Field("AppLayerConfig", "keyEpoch", .data, "Written by the pass itself, under the new key, as its last write: born new, so the pass never moves it."),
        Field("AppLayerConfig", "vaultKeyEpoch", .data, "Seeded under the new local key by the bootstrap. Stage 4 moves the vault tier by it."),
    ]

    /// Attributes of a type the guard looks at that hold nothing sealed.
    static let exempt: [Exempt] = [
        Exempt(model: "Message", attribute: "id",
               reason: "`Contact.Message.id`: a random UUID string, never sealed. The model is retired."),
    ]
}

// MARK: - Files

nonisolated extension KeyReseal {

    /// Every file the app seals or once sealed outside SwiftData.
    static let files: [SealedFile] = [
        SealedFile(
            name: "backup-export-meta.dat", location: "Application Support",
            key: .vault, aad: "the constant `occulta.backup-export-meta-v1`", treatment: .reseal,
            note: "32 depth slots in one blob, sealed under the vault key (`writeBackupExportMetadata`). Stage 4 reseals it as one blob, atomically, before the transaction that rewraps the rows commits."
        ),
        SealedFile(
            name: "<file id>[.<extension>]", location: "Application Support/Drafts/<draft id>/",
            key: .compose, aad: "none (chunked, per-file header)", treatment: .reseal,
            note: "A `Message.Draft` attachment of a group, or of a contact we hold no key for, sealed under the compose staging key (`Attachment+Manager`; tier U's). It never existed under a legacy key (dev builds only, not carried over), so the Stage 2 reseal has nothing to move; the Stage 6 upgrade moves each from the classical compose key to the hybrid one, file by file, found by trial, before the epoch is committed (`KeyReseal.upgradeTierU`)."
        ),
        SealedFile(
            name: "<file id>[.<extension>]", location: "Application Support/Drafts/<draft id>/",
            key: .other, aad: "none (chunked, per-file header)", treatment: .notAffected,
            note: "A `Message.Draft` attachment of a contact we hold a key for, sealed under the per-contact file key (`Attachment+Manager`), never under a key in this table. Same folder as the files above; the upgrade tells them apart by trial and leaves these alone."
        ),
        SealedFile(
            name: "manifest.enc and <n>.tmp", location: "App Group container/pending/<session id>/",
            key: .other, aad: "none", treatment: .notAffected,
            note: "A staged share session, sealed under the share staging key (`ShareStagingKeyManager`), in the Enclave-bound form since Stage 5. One the previous build staged opens through the legacy fallback in `decrypt`. Never resealed: sessions older than an hour are swept."
        ),
        SealedFile(
            name: "backup-import-cache.occbak, pending-restore.occbak", location: "Application Support",
            key: .other, aad: "the constant `occulta-backup-v1`", treatment: .retired,
            note: "Left by versions before the one-shot restore. Under the backup key. Deleted at every unlock (`deleteLegacyRestoreState`); never read."
        ),
        SealedFile(
            name: "pending-restore-shards.dat", location: "Application Support",
            key: .other, aad: "unknown", treatment: .retired,
            note: "Left by an older restore buffer (`bugs.md` Bug 127). Deleted at every unlock; never read, so what sealed it isn't recorded here."
        ),
        SealedFile(
            name: "<uuid>.occbak", location: "App Group container/blobs and /cache",
            key: .other, aad: "unknown", treatment: .retired,
            note: "`AppGroupLayerStoreBackend` has no consumer; a file here is a leftover from a build that had one. Nothing reads it."
        ),
    ]
}
