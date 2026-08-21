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

        /// Legacy decryption *threw* rather than returning nil.
        ///
        /// The two are not interchangeable and only this one occurs in practice:
        /// `decryptLegacy` surfaces an AES-GCM tag mismatch as a thrown
        /// `CryptoKitError.authenticationFailure`, so `guard let … else { throw
        /// legacyDecryptionFailed }` never fires for it and the field and contact were
        /// being discarded in exactly the failure mode that happens. See Bug 90.
        ///
        /// `alreadyV2` is the diagnostic that matters: it records whether the field could
        /// be read with the *current* key, which means it had already been migrated and
        /// this row is half-converted — Bug 90's second defect, observed rather than
        /// inferred.
        case legacyDecryptionThrew(field: String, contactID: String, alreadyV2: Bool, underlying: Error)
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
            // One contact's failure must not end the pass (Bug 90). Before this, a bare
            // `try` here meant the first row whose legacy ciphertext would not authenticate
            // stopped every row after it, permanently — and the rows after it may be
            // perfectly migratable, which is what made it a bug rather than a row with
            // unrecoverable data.
            do {
                if contact.deletionToken == nil {
                    try self.migrateContact(contact, legacyCrypto: legacyCrypto, newCrypto: newCrypto)
                }
                // Soft-deleted rows: skip re-encryption but advance the scheme marker
                // so they are never fetched again on subsequent launches.
                //
                // Inside the `do` deliberately: a throwing save must roll back too.
                contact.encryptionScheme = EncryptionScheme.v2_hybridPQ.rawValue
                try modelContext.save()
            } catch {
                // Discard this contact's partial mutation. `migrateContact` assigns field by
                // field, so a throw partway leaves earlier fields already converted on the
                // live object; without this the next contact's `save()` would commit them and
                // create exactly the half-converted row this fix exists to repair.
                //
                // Safe because `migrate()` suspends autosave for the whole sequence and this
                // migration runs first, so nothing else has pending changes on this context —
                // correct by ordering, which is why it is written down here.
                modelContext.rollback()

                // The marker is deliberately not advanced: the row stays at v1 and is retried
                // next launch. Marking it v2 would collapse "not yet migrated" into "migrated"
                // and destroy the only evidence that a retry is possible — the same reasoning
                // as Bug 80's `reencryptPreserving`.
            }
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

    /// Converts any remaining legacy JSON depth plaintexts to `DepthCodec`'s fixed-width
    /// format, so every row's ciphertext is the same length regardless of value (Bug 85).
    ///
    /// Runs at launch rather than inside rotation, and that is the point: rotation only
    /// happens on devices that use Secure Mode, so a format transition riding it would
    /// leave the format mix correlated with the very secret the fix exists to hide. A
    /// launch pass runs identically on every install, which is what restores uniformity
    /// as the innocent baseline.
    ///
    /// Four cases are deliberately left byte-identical rather than rewritten:
    ///
    /// - **Absent (nil).** For `Contact.Profile` the three backfills above own that case, so
    ///   this pass must run after them and must not manufacture a value of its own. For
    ///   `VaultEntry` nil is a legitimate steady state rather than a gap — `isEntryVisible`
    ///   reads it as "visible at every depth" for entries pre-dating the field — so
    ///   inventing a value there would change what the user sees. Either way: leave it.
    /// - **Undecryptable.** This is the important one. `isVisible` fails *closed* on a
    ///   ciphertext it cannot read — "non-nil field that won't decrypt = sensitive shell;
    ///   exclude" — so a stranded row is currently *hidden*. Resolving it to a default
    ///   here would persist that default, and the only permissive default available
    ///   (`Int.max`) means visible at every duress depth. That is Bug 87's failure mode;
    ///   written into a migration it would fire on every stranded row at once instead of
    ///   one per rotation. Preserving the bytes keeps the fail-closed reading intact.
    /// - **Already fixed-width.** Makes the pass idempotent across launches.
    /// - **Would not survive the round-trip.** A belt-and-braces guard: the value is only
    ///   rewritten when decoding the re-encoded form reproduces it exactly, so the pass
    ///   can never quietly change a value it did not fully understand.
    ///
    /// - Parameter modelContext: The SwiftData context to fetch and save contacts.
    static func migrateDepthFieldsToFixedWidth(modelContext: ModelContext) throws {
        let contacts = try modelContext.fetch(FetchDescriptor<Contact.Profile>())
        var didChange = false

        for contact in contacts {
            if let rewritten = try Self.fixedWidthRewrite(of: contact.visibleThroughDepth) {
                contact.visibleThroughDepth = rewritten
                didChange = true
            }
            if let rewritten = try Self.fixedWidthRewrite(of: contact.globalTrusteeDepth) {
                contact.globalTrusteeDepth = rewritten
                didChange = true
            }
            if let rewritten = try Self.fixedWidthRewrite(of: contact.originDepth) {
                contact.originDepth = rewritten
                didChange = true
            }
        }

        // VaultEntry carries the same kind of stamp under the same local DB key. Its range
        // is narrower — no Int.max sentinel, only a depth — so the leak is the second-order
        // one: a depth of 10 or more is two JSON bytes where a smaller one is one. Same
        // defect, same fix.
        for entry in try modelContext.fetch(FetchDescriptor<VaultEntry>()) {
            if let rewritten = try Self.fixedWidthRewrite(of: entry.visibleThroughDepth) {
                entry.visibleThroughDepth = rewritten
                didChange = true
            }
        }

        // AppLayerConfig's two scalar depths. Only the scalars: the padded arrays on the
        // same model are Bug 86, where the format and `fillerSize` have to change together
        // and a sequence number does not fit a depth's one-byte payload at all.
        //
        // These are also written rarely — `coercerBaseDepth` only on a coercion event — so
        // without this pass they would sit in the old format almost indefinitely, unlike
        // fields that any classification change rewrites.
        for config in try modelContext.fetch(FetchDescriptor<AppLayerConfig>()) {
            if let rewritten = try Self.fixedWidthRewrite(of: config.persistedDepth) {
                config.persistedDepth = rewritten
                didChange = true
            }
            if let rewritten = try Self.fixedWidthRewrite(of: config.coercerBaseDepth) {
                config.coercerBaseDepth = rewritten
                didChange = true
            }
        }

        if didChange { try modelContext.save() }
    }


    /// The fixed-width re-encryption of `field`, or nil when it must be left untouched.
    /// Every nil return is a case the migration is required not to rewrite — see
    /// `migrateDepthFieldsToFixedWidth`.
    private static func fixedWidthRewrite(of field: Data?) throws -> Data? {
        if case .converted(let sealed) = try Self.rewriteOutcome(of: field) { return sealed }
        return nil
    }

    /// Why a field was or was not rewritten. Every non-`converted` case is one the migration
    /// is required not to touch — the distinction exists so a device can report *which*,
    /// since "nothing changed" has six very different causes and they are not equally benign.
    enum DepthRewriteOutcome {
        case converted(Data)
        case absent             // nil — the backfills own it, or VaultEntry's "visible" state
        case undecryptable      // present but the key cannot read it — leave the bytes alone
        case undecodable        // decrypts, but neither format parses
        case alreadyFixedWidth  // nothing to do; keeps the pass idempotent
        case wouldNotRoundTrip  // the value would not survive re-encoding — refuse to guess
        case sealFailed         // decoded fine, but could not be re-encrypted
    }

    static func rewriteOutcome(of field: Data?) throws -> DepthRewriteOutcome {
        guard let field                             else { return .absent }
        guard let plain = field.decrypt()           else { return .undecryptable }
        guard let value = DepthCodec.decode(plain)  else { return .undecodable }
        let reencoded = DepthCodec.encode(value)
        guard reencoded != plain                    else { return .alreadyFixedWidth }
        guard DepthCodec.decode(reencoded) == value else { return .wouldNotRoundTrip }
        guard let sealed = try reencoded.encrypt()  else { return .sealFailed }
        return .converted(sealed)
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

    /// Overwrites the depth stamps of already-soft-deleted rows with random bytes at
    /// `DepthCodec`'s uniform length (Bug 89).
    ///
    /// The repair half. `deleteContact` scrubs these at deletion time from now on, so this
    /// exists only for rows deleted before that shipped — nothing else will ever rewrite
    /// them, because rotation skips soft-deleted rows and the fixed-width pass cannot
    /// convert a field it cannot decrypt.
    ///
    /// **Needs no key, and never decrypts.** `deletionToken != nil` is the entire test.
    /// Whether the field is currently readable does not matter: for an erased row the value
    /// carries no meaning either way, so there is nothing to preserve and nothing to
    /// distinguish. That also means an unavailable key cannot block this pass — the hazard
    /// Bug 86's array migration has to manage, avoided rather than handled.
    ///
    /// Random rather than a fresh encryption: on a stranded row every other field fails to
    /// decrypt, so a depth field that decrypts cleanly is the outlier and implies something
    /// wrote after the erasure. This also normalises the half-readable rows the three
    /// backfills produced by stamping current-key values onto deleted rows without filtering
    /// `deletionToken`.
    ///
    /// Idempotent by length, so it does not re-randomise on every launch.
    ///
    /// - Parameter modelContext: The SwiftData context to fetch and save contacts.
    static func migrateScrubDeletedDepthStamps(modelContext: ModelContext) throws {
        let deleted = try modelContext.fetch(
            FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.deletionToken != nil })
        )
        var didChange = false

        for contact in deleted {
            if let scrubbed = Self.scrubbedStamp(contact.visibleThroughDepth) {
                contact.visibleThroughDepth = scrubbed
                didChange = true
            }
            if let scrubbed = Self.scrubbedStamp(contact.globalTrusteeDepth) {
                contact.globalTrusteeDepth = scrubbed
                didChange = true
            }
            if let scrubbed = Self.scrubbedStamp(contact.originDepth) {
                contact.originDepth = scrubbed
                didChange = true
            }
        }

        if didChange { try modelContext.save() }
    }

    /// Random bytes at the uniform length, or nil when the field is already that length.
    ///
    /// Per field, not per row: a deleted row can legitimately have one stamp readable and
    /// the others stranded, because the backfills do not filter `deletionToken`. Promoting
    /// this to "if any stamp is wrong, replace all three" would discard real values for no
    /// gain.
    ///
    /// A nil stamp is scrubbed too — nil is its own tell (S6), and random bytes make it
    /// non-nil and the same length as everything else.
    private static func scrubbedStamp(_ field: Data?) -> Data? {
        guard field?.count != DepthCodec.sealedSize else { return nil }
        return Data.randomBytes(DepthCodec.sealedSize)
    }

    /// Builds the error for a legacy decryption that threw, probing whether the field is
    /// readable with the **current** key on the way.
    ///
    /// That probe is the whole diagnostic. A field that fails the legacy key but succeeds
    /// the current one was already migrated, which means this row is half-converted and
    /// Bug 90's second defect has actually fired here — rather than being a hazard the code
    /// merely permits. It decides whether a fix needs resume-mode for mixed rows or only
    /// needs to stop creating them.
    private static func legacyThrew(
        _ ciphertext: Data, field: String, id: String, new: CryptoProtocol, error: Error
    ) -> MigrationError {
        let alreadyV2 = ((try? new.decrypt(data: ciphertext)) ?? nil) != nil
        return .legacyDecryptionThrew(field: field, contactID: id,
                                      alreadyV2: alreadyV2, underlying: error)
    }

    private static func reencryptString(_ base64: String, field: String, id: String, legacy: CryptoProtocol, new: CryptoProtocol) throws -> String {
        guard !base64.isEmpty else { return "" }

        guard let ciphertext = Data(base64Encoded: base64) else {
            throw MigrationError.legacyDecryptionFailed(field: field, contactID: id)
        }

        // Empty ciphertext data means the field was empty when encrypted.
        guard !ciphertext.isEmpty else { return "" }

        let decrypted: Data?
        do {
            decrypted = try legacy.decryptLegacy(data: ciphertext)
        } catch {
            let failure = Self.legacyThrew(ciphertext, field: field, id: id, new: new, error: error)
            // Resume: this field was already converted by an earlier run that failed partway
            // (Bug 90). It is correct as it stands, so return it untouched rather than
            // throwing — that is what lets a half-migrated row finish instead of being stuck
            // forever on the field it already converted.
            if case .legacyDecryptionThrew(_, _, alreadyV2: true, _) = failure { return base64 }
            throw failure
        }
        guard let plaintext = decrypted else {
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

        let decrypted: Data?
        do {
            decrypted = try legacy.decryptLegacy(data: data)
        } catch {
            let failure = Self.legacyThrew(data, field: field, id: id, new: new, error: error)
            // Resume — see reencryptString.
            if case .legacyDecryptionThrew(_, _, alreadyV2: true, _) = failure { return data }
            throw failure
        }
        guard let plaintext = decrypted else {
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
