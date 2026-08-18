//
//  DatabaseMigration.swift
//  Occulta
//
//  One-time migration from EncryptionScheme.v1_identityDerived to v2_hybridPQ.
//
//  Responsibilities:
//    1. Decrypt every field with the v1 key (no AAD)
//    2. Re-encrypt with the v2 hybrid key (with AAD)
//    3. Encrypt identifierFromOutside and identifierAcquirer (previously plaintext)
//    4. Mark each record's encryptionScheme = 2 after successful re-encryption
//    5. Save per-record for crash safety
//

import Foundation
import SwiftData
import CryptoKit

struct DatabaseMigration {

    enum MigrationError: Error {
        case legacyDecryptionFailed(field: String, contactID: String)
        case encryptionFailed(field: String, contactID: String)
        case hybridKeyUnavailable
        case legacyKeyUnavailable
    }

    /// Run the v1 → v2 migration for all contacts in the given context.
    ///
    /// Processes one contact at a time. Each contact is fully re-encrypted
    /// and saved before moving to the next. If the app is killed mid-migration,
    /// already-migrated contacts have `encryptionScheme == 2` and will be skipped
    /// on the next launch.
    ///
    /// - Parameters:
    ///   - modelContext: The SwiftData context to fetch and save contacts.
    ///   - legacyCrypto: Crypto manager configured with the v1 key path.
    ///   - newCrypto: Crypto manager configured with the v2 hybrid key path.
    static func migrateToV2(modelContext: ModelContext, legacyCrypto: CryptoProtocol, newCrypto: CryptoProtocol) throws {
        let v1 = EncryptionScheme.v1_identityDerived.rawValue
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.encryptionScheme == v1 }
        )
        let contacts = try modelContext.fetch(descriptor)

        for contact in contacts {
            if contact.deletionToken == nil {
                #if DEBUG
                let debugName = contact.givenName.decrypt()
                #endif

                try self.migrateContact(contact, legacyCrypto: legacyCrypto, newCrypto: newCrypto)

                #if DEBUG
                debugPrint("Migrated contact to v2 encryption scheme, contact - \(debugName)")
                #endif
            }
            // Soft-deleted rows: skip re-encryption but advance the scheme marker
            // so they are never fetched again on subsequent launches.
            contact.encryptionScheme = EncryptionScheme.v2_hybridPQ.rawValue
            try modelContext.save()
        }
    }

    /// One-time backfill for contacts whose `visibleThroughDepth` predates the
    /// "never nil" creation-time stamp (Contact+Manager.swift). A lingering nil marks
    /// a contact as pre-dating that fix — a forensic tell distinct from its encrypted
    /// content, since column presence/absence is visible without decryption. Re-seals
    /// every nil row to encrypted Int.max (safe/never-classified), identical in meaning
    /// to nil but indistinguishable in column presence from every other contact. See
    /// forensic-trace-avoidance.md S6.
    ///
    /// Idempotent: the predicate only matches remaining nil rows, so already-backfilled
    /// contacts are skipped on subsequent launches.
    ///
    /// - Parameter modelContext: The SwiftData context to fetch and save contacts.
    static func migrateSafeContactVisibilityBackfill(modelContext: ModelContext) throws {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.visibleThroughDepth == nil }
        )
        let contacts = try modelContext.fetch(descriptor)
        guard !contacts.isEmpty else { return }

        for contact in contacts {
            contact.visibleThroughDepth = try DepthCodec.encode(Int.max).encrypt()
        }
        try modelContext.save()
    }

    /// One-time backfill for contacts predating the `globalTrusteeDepth` field —
    /// every pre-existing contact starts nil after the lightweight schema migration
    /// adds the column. Nil is not a valid steady state for this field (same invariant
    /// as `visibleThroughDepth`); backfills to encrypted -1 (not a trustee).
    ///
    /// Idempotent: the predicate only matches remaining nil rows.
    ///
    /// - Parameter modelContext: The SwiftData context to fetch and save contacts.
    static func migrateGlobalTrusteeDepthBackfill(modelContext: ModelContext) throws {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.globalTrusteeDepth == nil }
        )
        let contacts = try modelContext.fetch(descriptor)
        guard !contacts.isEmpty else { return }

        for contact in contacts {
            contact.globalTrusteeDepth = try DepthCodec.encode(-1).encrypt()
        }
        try modelContext.save()
    }

    /// One-time backfill for contacts predating the `originDepth` field — every
    /// pre-existing contact starts nil after the lightweight schema migration adds the
    /// column. Nil is not a valid steady state for this field (same invariant as
    /// `visibleThroughDepth`/`globalTrusteeDepth`); backfills to encrypted 0.
    ///
    /// 0 is the only safe default: there is no historical record of what depth any
    /// existing contact was actually added at, and 0 ("not duress-origin, defer to the
    /// existing ceiling") guarantees no existing contact is ever retroactively confined
    /// to a wrong guessed depth.
    ///
    /// Idempotent: the predicate only matches remaining nil rows.
    ///
    /// - Parameter modelContext: The SwiftData context to fetch and save contacts.
    static func migrateOriginDepthBackfill(modelContext: ModelContext) throws {
        let descriptor = FetchDescriptor<Contact.Profile>(
            predicate: #Predicate { $0.originDepth == nil }
        )
        let contacts = try modelContext.fetch(descriptor)
        guard !contacts.isEmpty else { return }

        for contact in contacts {
            contact.originDepth = try DepthCodec.encode(0).encrypt()
        }
        try modelContext.save()
    }

    /// One-time consolidation onto a single trustee mechanism: reads any existing
    /// `GlobalShardConfig.trusteeIDs` (the old depth-0-only global trustee list) and
    /// stamps `globalTrusteeDepth = encrypt(0)` on each of those contacts, then wipes
    /// the `GlobalShardConfig` rows. `globalTrusteeDepth` is now the sole mechanism for
    /// global-trustee status at every depth, including depth 0 — see the shard-custody
    /// bug doc, item 3.
    ///
    /// `GlobalShardConfig` stays declared in the schema for this release only, rather
    /// than being removed outright — dropping a whole `@Model` type relies entirely on
    /// SwiftData's automatic lightweight-migration inference (this project has no
    /// `VersionedSchema`/`SchemaMigrationPlan`), untested here with real user data.
    /// The model is fully orphaned by app code after this migration runs; actual
    /// removal is deferred to a later release.
    ///
    /// Idempotent: once the rows are deleted, the guard below makes every subsequent
    /// run a no-op.
    ///
    /// - Parameters:
    ///   - modelContext: The SwiftData context to fetch and save contacts and config rows.
    ///   - shardCustodyManager: Used only to decrypt the existing `GlobalShardConfig`
    ///     payload — the shard-custody key is separate from the local DB key.
    static func migrateGlobalShardConfigToPerContact(modelContext: ModelContext, shardCustodyManager: ShardCustodyManager) throws {
        let rows = try modelContext.fetch(FetchDescriptor<GlobalShardConfig>())
        guard !rows.isEmpty else { return }

        if let payload = try shardCustodyManager.globalShardConfig() {
            let trusteeIDs = Set(payload.trusteeIDs)
            let contacts = try modelContext.fetch(FetchDescriptor<Contact.Profile>())
            for contact in contacts where trusteeIDs.contains(contact.identifier) {
                contact.globalTrusteeDepth = try DepthCodec.encode(0).encrypt()
            }
        }

        for row in rows { modelContext.delete(row) }
        try modelContext.save()
    }

    // MARK: - Per-contact migration

    private static func migrateContact(_ contact: Contact.Profile, legacyCrypto: CryptoProtocol, newCrypto: CryptoProtocol) throws {
        let id = contact.identifier

        // MARK: Scalar string fields (base64-encoded ciphertext)

        contact.givenName          = try reencryptString(contact.givenName,          field: "givenName",          id: id, legacy: legacyCrypto, new: newCrypto)
        contact.familyName         = try reencryptString(contact.familyName,         field: "familyName",         id: id, legacy: legacyCrypto, new: newCrypto)
        contact.middleName         = try reencryptString(contact.middleName,         field: "middleName",         id: id, legacy: legacyCrypto, new: newCrypto)
        contact.namePrefix         = try reencryptString(contact.namePrefix,         field: "namePrefix",         id: id, legacy: legacyCrypto, new: newCrypto)
        contact.nameSuffix         = try reencryptString(contact.nameSuffix,         field: "nameSuffix",         id: id, legacy: legacyCrypto, new: newCrypto)
        contact.nickname           = try reencryptString(contact.nickname,           field: "nickname",           id: id, legacy: legacyCrypto, new: newCrypto)
        contact.organizationName   = try reencryptString(contact.organizationName,   field: "organizationName",   id: id, legacy: legacyCrypto, new: newCrypto)
        contact.departmentName     = try reencryptString(contact.departmentName,     field: "departmentName",     id: id, legacy: legacyCrypto, new: newCrypto)
        contact.jobTitle           = try reencryptString(contact.jobTitle,           field: "jobTitle",           id: id, legacy: legacyCrypto, new: newCrypto)
        contact.phoneticGivenName  = try reencryptString(contact.phoneticGivenName,  field: "phoneticGivenName",  id: id, legacy: legacyCrypto, new: newCrypto)
        contact.phoneticMiddleName = try reencryptString(contact.phoneticMiddleName, field: "phoneticMiddleName", id: id, legacy: legacyCrypto, new: newCrypto)
        contact.phoneticFamilyName = try reencryptString(contact.phoneticFamilyName, field: "phoneticFamilyName", id: id, legacy: legacyCrypto, new: newCrypto)
        contact.note               = try reencryptString(contact.note,               field: "note",               id: id, legacy: legacyCrypto, new: newCrypto)
        contact.identifier         = try reencryptString(contact.identifier,         field: "identifier",         id: id, legacy: legacyCrypto, new: newCrypto)

        // Birthday is optional.
        if let birthday = contact.birthday {
            contact.birthday = try reencryptString(birthday, field: "birthday", id: id, legacy: legacyCrypto, new: newCrypto)
        }

        // MARK: Image data fields (raw encrypted Data, not base64 strings)

        contact.imageData          = try reencryptData(contact.imageData,          field: "imageData",          id: id, legacy: legacyCrypto, new: newCrypto)
        contact.thumbnailImageData = try reencryptData(contact.thumbnailImageData, field: "thumbnailImageData", id: id, legacy: legacyCrypto, new: newCrypto)

        // MARK: Forward secrecy blob

        contact.forwardSecrecyEncrypted = try reencryptData(
            contact.forwardSecrecyEncrypted,
            field: "forwardSecrecyEncrypted",
            id: id,
            legacy: legacyCrypto,
            new: newCrypto
        )

        // MARK: Relationship fields

        try contact.phoneNumbers?.forEach { phone in
            phone.label = try reencryptString(phone.label, field: "phone.label", id: id, legacy: legacyCrypto, new: newCrypto)
            phone.value = try reencryptString(phone.value, field: "phone.value", id: id, legacy: legacyCrypto, new: newCrypto)
        }

        try contact.emailAddresses?.forEach { email in
            email.label = try reencryptString(email.label, field: "email.label", id: id, legacy: legacyCrypto, new: newCrypto)
            email.value = try reencryptString(email.value, field: "email.value", id: id, legacy: legacyCrypto, new: newCrypto)
        }

        try contact.postalAddresses?.forEach { postal in
            postal.label          = try reencryptString(postal.label,          field: "postal.label",   id: id, legacy: legacyCrypto, new: newCrypto)
            postal.street         = try reencryptString(postal.street,         field: "postal.street",  id: id, legacy: legacyCrypto, new: newCrypto)
            postal.city           = try reencryptString(postal.city,           field: "postal.city",    id: id, legacy: legacyCrypto, new: newCrypto)
            postal.state          = try reencryptString(postal.state,          field: "postal.state",   id: id, legacy: legacyCrypto, new: newCrypto)
            postal.postalCode     = try reencryptString(postal.postalCode,     field: "postal.zip",     id: id, legacy: legacyCrypto, new: newCrypto)
            postal.isoCountryCode = try reencryptString(postal.isoCountryCode, field: "postal.country", id: id, legacy: legacyCrypto, new: newCrypto)
        }

        try contact.urlAddresses?.forEach { url in
            url.label = try reencryptString(url.label, field: "url.label", id: id, legacy: legacyCrypto, new: newCrypto)
            url.value = try reencryptString(url.value, field: "url.value", id: id, legacy: legacyCrypto, new: newCrypto)
        }

        // MARK: Contact public keys

        try contact.contactPublicKeys?.forEach { key in
            key.material = try reencryptData(key.material, field: "key.material", id: id, legacy: legacyCrypto, new: newCrypto)

            key.owner = try reencryptData(key.owner, field: "key.owner", id: id, legacy: legacyCrypto, new: newCrypto) ?? Data()

            if let acquiredAt = key.acquiredAt {
                key.acquiredAt = try reencryptData(acquiredAt, field: "key.acquiredAt", id: id, legacy: legacyCrypto, new: newCrypto)
            }

            if let expiredOn = key.expiredOn {
                key.expiredOn = try reencryptData(expiredOn, field: "key.expiredOn", id: id, legacy: legacyCrypto, new: newCrypto)
            }
        }
    }

    // MARK: - Field-level re-encryption helpers

    /// Re-encrypt a base64-encoded ciphertext string from v1 → v2.
    ///
    /// Empty strings are preserved as-is (they represent empty plaintext).
    private static func reencryptString(_ base64: String, field: String, id: String, legacy: CryptoProtocol, new: CryptoProtocol) throws -> String {
        guard !base64.isEmpty else { return "" }

        guard let ciphertext = Data(base64Encoded: base64) else {
            throw MigrationError.legacyDecryptionFailed(field: field, contactID: id)
        }

        // Empty ciphertext data means the field was empty when encrypted.
        guard !ciphertext.isEmpty else { return "" }

        guard let plaintext = try legacy.decryptLegacy(data: ciphertext) else {
            throw MigrationError.legacyDecryptionFailed(field: field, contactID: id)
        }

        guard let reencrypted = try new.encrypt(data: plaintext) else {
            throw MigrationError.encryptionFailed(field: field, contactID: id)
        }

        return reencrypted.base64EncodedString()
    }

    /// Re-encrypt raw Data ciphertext from v1 → v2.
    ///
    /// Returns nil if input is nil (field was never populated).
    private static func reencryptData(
        _ data: Data?,
        field: String,
        id: String,
        legacy: CryptoProtocol,
        new: CryptoProtocol
    ) throws -> Data? {
        guard let data, !data.isEmpty else { return nil }

        guard let plaintext = try legacy.decryptLegacy(data: data) else {
            throw MigrationError.legacyDecryptionFailed(field: field, contactID: id)
        }

        guard let reencrypted = try new.encrypt(data: plaintext) else {
            throw MigrationError.encryptionFailed(field: field, contactID: id)
        }

        return reencrypted
    }

    /// Encrypt a previously-plaintext string field for the first time.
    ///
    /// Used for fields that were stored unencrypted in v1
    /// (identifierFromOutside, identifierAcquirer).
    private static func encryptNewField(
        _ plaintext: String,
        field: String,
        id: String,
        crypto: CryptoProtocol
    ) throws -> String {
        guard !plaintext.isEmpty else { return "" }

        guard
            let data = plaintext.data(using: .utf8),
            let encrypted = try crypto.encrypt(data: data)
        else {
            throw MigrationError.encryptionFailed(field: field, contactID: id)
        }

        return encrypted.base64EncodedString()
    }
}
