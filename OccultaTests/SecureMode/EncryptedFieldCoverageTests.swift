//
//  EncryptedFieldCoverageTests.swift
//  OccultaTests
//
//  Guards the class of bug that stranded `Contact.Profile.maxBundleVersion`: an encrypted
//  field exists on a model, key rotation does not re-encrypt it, and nothing anywhere
//  says so. Step 11 then deletes the old key and the value is gone — silently, because
//  `reencryptAllFields` clears fields it cannot decrypt by design and every read accessor
//  has a fallback. The symptom surfaced months later and looked unrelated: contacts became
//  ineligible for groups with "they need to update", about apps that were current.
//
//  Two complementary guards:
//
//  1. **Tripwire** — the set of stored property names on each model must equal an explicit
//     classification. Adding any property fails the test until someone classifies it. This
//     cannot tell whether a new field needs re-keying; it forces the decision to be made,
//     which is precisely what did not happen for `maxBundleVersion`.
//
//  2. **Behavioural** — populate every encrypted field, rotate, assert each one still
//     reads. This catches the actual defect rather than a proxy for it.
//
//  **For `Contact.Profile`, both derive from one table** (`probes` / `unprobedFields`) as of
//  2026-08-16. That matters: previously the tripwire was silenced by adding a name to a list
//  of its own, which proved *awareness* while the behavioural fixture — a separate,
//  hand-maintained list — proved *coverage*. Acknowledging a field without re-keying it passed.
//  Now an entry must carry a key path and a probe value, so silencing the tripwire is the same
//  act as being checked by the round-trip.
//
//  `AppLayerConfig` followed on the same date, and its round-trip runs **without a Secure
//  Enclave** — the first field-level coverage check in the project that CI actually executes.
//  The difference is the signature: `AppLayerConfig.reencrypt(from:to:)` takes both keys, so the
//  test picks both, while `reencryptAllFields` decrypts ambiently and forces a gate.
//
//  `Group` and `Message.Draft` still keep a name list and a behavioural test of their own, in
//  `GroupKeyRotationTests` and `DraftKeyRotationTests`. Neither is a drop-in: Draft's two fields
//  are non-optional `Data`, and three of Group's six are `private(set)` arrays whose only writer
//  is a `private` method, so they cannot be populated by key path at all. See
//  `Docs/Features/Secure Mode/ROTATION_COVERAGE.md`.
//
//  Why names and not types: `Mirror` on a SwiftData `@Model` does enumerate every stored
//  property (prefixed `_`, plus `_$backingData` and `_$observationRegistrar`), but erases
//  every type to `_SwiftDataNoType`. Filtering by "is this a `Data?`" is therefore not
//  possible, so the tripwire keys on names.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

/// True when this host can derive the real hybrid local DB key. False on CI runners, which
/// have no Secure Enclave.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}


// MARK: - Helpers

private func canonicalKey() -> SymmetricKey? {
    try? Manager.Key().createHybridLocalEncryptionKey()
}

/// Stored property names of `model`, with SwiftData's leading `_` stripped and its two
/// synthesised `_$` members dropped.
private func storedPropertyNames(of model: Any) -> Set<String> {
    Set(
        Mirror(reflecting: model).children
            .compactMap(\.label)
            .filter { !$0.hasPrefix("_$") }
            .map { $0.hasPrefix("_") ? String($0.dropFirst()) : $0 }
    )
}

private let tripwireGuidance = """
A stored property was added, removed or renamed on this model.

If it holds ciphertext under the LOCAL DB KEY it must be re-encrypted during rotation, or \
it will be stranded the next time Secure Mode is activated or deactivated and lost when the \
superseded key is deleted:
  • Contact.Profile  → reencryptAllFields / reencryptKeyRecords
  • Group            → Group.reencrypt(from:to:)
  • AppLayerConfig   → AppLayerConfig.reencrypt(from:to:)
  • Message.Draft    → Message.Draft.reKeyOrPurgeAll

Whichever it is, it must be re-keyed in BOTH activateSecureMode AND deactivateSecureMode. They are separate code paths and nothing links them: drafts were correct in activation from the start and absent from deactivation until 2026-08-14. See Model Coverage in SecureMode+RotationContract.md.

Consider whether clearing it on an unreadable value is safe. If the field's PRESENCE carries \
meaning (as deletionToken's does), use the preserving helper — nil-ing it changes behaviour \
rather than merely losing a value.

If it also needs to survive a deactivation restore, add it to LayerContact / Contact.Draft too.

Then classify it here:
  • Contact.Profile / AppLayerConfig → add to that model's `probes` (with a key path and a \
distinct probe value) if the rotation must re-key it, or to `unprobedFields` (with the key that \
seals it instead, or "plaintext"). Adding to `probes` is what makes the round-trip test check it — \
a name alone is not enough, by design.
  • Group / Message.Draft → add the name to that model's list below, and extend its behavioural \
test by hand. These have not been moved to probe tables yet, and neither is a drop-in — see \
ROTATION_COVERAGE.md.
"""

// MARK: - Probe table

/// One field's contribution to rotation coverage: how to seal a known value into it, and how to
/// read that value back under a new key.
///
/// This exists so a **single** table can drive the three things that used to be maintained by
/// hand and separately — the tripwire's name list, the populate helper, and the round-trip
/// assertions. Adding a field to the table is therefore the same act as covering it: the
/// tripwire cannot be silenced by typing a name, because an entry must carry a key path and a
/// probe value, and once it does the round-trip below fails if `reencryptAllFields` does not
/// re-key it.
///
/// That closes the gap the old shape left. The tripwire's guidance used to end "then add the
/// name to the list in this test" — an edit that silenced the alarm without proving anything
/// had been re-keyed.
enum FieldProbe<M: AnyObject> {
    /// Base64 ciphertext in a non-optional `String`.
    case string(ReferenceWritableKeyPath<M, String>, String)
    /// Base64 ciphertext in an optional `String`.
    case optionalString(ReferenceWritableKeyPath<M, String?>, String)
    /// Raw ciphertext, cleared when unreadable — the ordinary case.
    case data(ReferenceWritableKeyPath<M, Data?>, Data)
    /// Raw ciphertext whose *presence* carries meaning independently of its content, so an
    /// unreadable value must be preserved byte-for-byte rather than cleared. `deletionToken` is
    /// the motivating case: nil there means "not deleted", so clearing an unreadable token
    /// un-deletes the contact.
    case preserving(ReferenceWritableKeyPath<M, Data?>, Data)
    /// An array of independently sealed ciphertexts, re-sealed entry by entry.
    ///
    /// Every entry is checked, not just one. `AppLayerConfig.pinEnabledPerDepth` is why: its
    /// filler *is* real ciphertext — encrypted `1`, chosen so enabled and disabled encode to
    /// equal lengths — and `reencrypt` re-seals all 32 entries rather than skipping unreadable
    /// ones, specifically so they stay equal-length and mutually indistinguishable. A probe
    /// checking one entry would pass a partial re-seal.
    case dataArray(ReferenceWritableKeyPath<M, [Data]>, [Data])
}

extension FieldProbe {

    /// Seals the probe value into the field.
    ///
    /// Pass `key` when the model's re-key function takes both keys explicitly — then the test
    /// picks both and needs no Secure Enclave. Omit it for models whose re-key path decrypts
    /// through the **ambient** `Manager.Key()`, which forces the probe to seal under the real
    /// canonical key and forces the test to be Enclave-gated.
    ///
    /// That split is not cosmetic: it is exactly why `Contact.Profile`'s round-trip is gated
    /// and `AppLayerConfig`'s is not. `reencryptAllFields` decrypts ambiently;
    /// `AppLayerConfig.reencrypt(from:to:)` does not. Removing the ambient dependency is
    /// step 4 of `Docs/Features/Secure Mode/ROTATION_COVERAGE.md`, and it would let the
    /// coverage check for contacts run in CI too.
    func populate(_ model: M, using key: SymmetricKey? = nil) throws {
        func seal(_ plain: Data) throws -> Data? {
            if let key { return try plain.encrypt(using: key) }
            return try plain.encrypt()
        }
        func sealText(_ value: String) throws -> String {
            guard let sealed = try seal(Data(value.utf8)) else { return "" }
            return sealed.base64EncodedString()
        }

        switch self {
        case let .string(keyPath, value):
            model[keyPath: keyPath] = try sealText(value)
        case let .optionalString(keyPath, value):
            model[keyPath: keyPath] = try sealText(value)
        case let .data(keyPath, value), let .preserving(keyPath, value):
            model[keyPath: keyPath] = try seal(value)
        case let .dataArray(keyPath, values):
            model[keyPath: keyPath] = try values.compactMap { try seal($0) }
        }
    }

    /// `nil` when the field reads back as the probe value under `key`; otherwise a description
    /// of what was found instead.
    func mismatch(in model: M, using key: SymmetricKey) -> String? {
        switch self {
        case let .string(keyPath, expected):
            let actual = decryptString(model[keyPath: keyPath], using: key)
            return actual == expected ? nil : "expected \"\(expected)\", read \(actual ?? "nil")"
        case let .optionalString(keyPath, expected):
            let actual = model[keyPath: keyPath].flatMap { decryptString($0, using: key) }
            return actual == expected ? nil : "expected \"\(expected)\", read \(actual ?? "nil")"
        case let .data(keyPath, expected), let .preserving(keyPath, expected):
            let actual = model[keyPath: keyPath]?.decrypt(using: key)
            return actual == expected
                ? nil
                : "expected \(Array(expected)), read \(actual.map { Array($0) }.map(String.init(describing:)) ?? "nil")"
        case let .dataArray(keyPath, expected):
            let stored = model[keyPath: keyPath]
            guard stored.count == expected.count else {
                return "expected \(expected.count) entries, found \(stored.count)"
            }
            let bad = zip(stored, expected).enumerated()
                .filter { $0.element.0.decrypt(using: key) != $0.element.1 }
                .map(\.offset)
            return bad.isEmpty ? nil : "entries \(bad) did not read back under the new key"
        }
    }

    /// Fields whose presence carries meaning — see `.preserving`.
    var isPreserving: Bool {
        if case .preserving = self { return true }
        return false
    }

    /// The raw-`Data` key path, for the stranded-value check. `nil` for string and array fields.
    var dataKeyPath: ReferenceWritableKeyPath<M, Data?>? {
        switch self {
        case let .data(keyPath, _), let .preserving(keyPath, _): return keyPath
        case .string, .optionalString, .dataArray:               return nil
        }
    }
}

extension Contact.Profile {

    /// Every field `reencryptAllFields` must re-key, with the means to populate and verify it.
    /// Each probe value is distinct so a mismatch names the field that moved.
    static let probes: [String: FieldProbe<Contact.Profile>] = [
        "givenName":              .string(\.givenName,          "given"),
        "familyName":             .string(\.familyName,         "family"),
        "middleName":             .string(\.middleName,         "middle"),
        "namePrefix":             .string(\.namePrefix,         "prefix"),
        "nameSuffix":             .string(\.nameSuffix,         "suffix"),
        "nickname":               .string(\.nickname,           "nick"),
        "organizationName":       .string(\.organizationName,   "org"),
        "departmentName":         .string(\.departmentName,     "dept"),
        "jobTitle":               .string(\.jobTitle,           "job"),
        "phoneticGivenName":      .string(\.phoneticGivenName,  "pgiven"),
        "phoneticMiddleName":     .string(\.phoneticMiddleName, "pmiddle"),
        "phoneticFamilyName":     .string(\.phoneticFamilyName, "pfamily"),
        "note":                   .string(\.note,               "note"),
        "birthday":               .optionalString(\.birthday,   "birthday"),

        "imageData":              .data(\.imageData,               Data([0xA1])),
        "thumbnailImageData":     .data(\.thumbnailImageData,      Data([0xA2])),
        "forwardSecrecyEncrypted":.data(\.forwardSecrecyEncrypted, Data([0xA3])),
        "signedAttributes":       .data(\.signedAttributes,        Data([0xA4])),
        "visibleThroughDepth":    .data(\.visibleThroughDepth,     Data([0xA5])),
        "globalTrusteeDepth":     .data(\.globalTrusteeDepth,      Data([0xA6])),
        "originDepth":            .data(\.originDepth,             Data([0xA7])),

        // Presence carries meaning — see `.preserving`.
        "maxBundleVersion":       .preserving(\.maxBundleVersion, Data([0x07])),
        "deletionToken":          .preserving(\.deletionToken,    Data([1])),
    ]

    /// Every other stored property, with why it is not probed.
    ///
    /// Encrypted-but-not-rotated belongs here too, not only plaintext: putting such a field
    /// through the rotation would re-seal it under the wrong key and strand it the other way
    /// round. `Contact.Profile` has none today, but `AppLayerConfig` does.
    static let unprobedFields: [String: String] = [
        "identifier":        "plaintext — queried with #Predicate, so it cannot be encrypted",
        "encryptionScheme":  "plaintext — plain Int discriminator",
        "phoneNumbers":      "relationship — swept by its own loop in reencryptAllFields; the sub-model has no tripwire of its own yet",
        "emailAddresses":    "relationship — as above",
        "postalAddresses":   "relationship — as above",
        "urlAddresses":      "relationship — as above",
        "contactPublicKeys": "relationship — re-keyed by reencryptKeyRecords, not reencryptAllFields",
    ]
}

extension AppLayerConfig {

    /// Distinct one-byte plaintexts for all 32 `pinEnabledPerDepth` entries.
    ///
    /// Exactly 32, which is `paddedArrayCount`, so `ensurePadded()` inside `reencrypt` is a
    /// no-op. That matters: its padding path seals through the **ambient** key
    /// (`AppLayerConfig+Model.swift:381`) and would drag this otherwise Enclave-free test back
    /// onto a real Secure Enclave, falling back to random filler where none exists.
    static let probeSlotPlaintexts: [Data] = (0..<32).map { Data([UInt8($0)]) }

    /// Every field `AppLayerConfig.reencrypt(from:to:)` must re-key.
    static let probes: [String: FieldProbe<AppLayerConfig>] = [
        "persistedDepth":               .data(\.persistedDepth,               Data([0xB1])),
        "pinEnabled":                   .data(\.pinEnabled,                   Data([0xB2])),
        "coercerBaseDepth":             .data(\.coercerBaseDepth,             Data([0xB3])),
        "lockoutCountEncrypted":        .data(\.lockoutCountEncrypted,        Data([0xB4])),
        "lockoutAnchorUptimeEncrypted": .data(\.lockoutAnchorUptimeEncrypted, Data([0xB5])),
        "pinEnabledPerDepth":           .dataArray(\.pinEnabledPerDepth, AppLayerConfig.probeSlotPlaintexts),
    ]

    /// Every other stored property, with the key that seals it.
    ///
    /// This is the model where `unprobedFields` earns its keep: **half of its encrypted fields
    /// must never be rotated.** Adding one of these to `reencrypt` would re-seal it under the
    /// local DB key and strand it the other way round — which the rotation contract calls as
    /// much a bug as leaving a rotated field out.
    static let unprobedFields: [String: String] = [
        "sealedNormalVerifier":  "SE Secure Mode key via PINManager — the scalar nil/non-nil flag behind requiresPIN. Never rotate",
        "sealedDuressVerifier":  "SE Secure Mode key via PINManager. Never rotate",
        "sealedNormalVerifiers": "SE Secure Mode key via PINManager — the array verify() scans. Never rotate; this is why PIN entry kept working across rotations while everything else on the row did not",
        "sealedDuressVerifiers": "SE Secure Mode key via PINManager. Never rotate",
        "sealedBlobSlots":       "AppLayerConfig.blobMetadataKey(from:), HKDF from the SE Secure Mode key — moved there by Bug 76's fix so no rotation can strand it by construction rather than by remembering",
        "layerSequenceNumbers":  "AppLayerConfig.blobMetadataKey(from:) — as above",
    ]
}

// MARK: - Tripwires

/// `AppLayerConfig`'s round-trip, in its own suite because — unlike `Contact.Profile`'s — it
/// needs **no Secure Enclave** and therefore runs on CI runners.
///
/// The reason is the signature: `AppLayerConfig.reencrypt(from:to:)` takes both keys explicitly,
/// so the test picks both and never touches `Manager.Key()`. `reencryptAllFields` decrypts
/// ambiently, which is what forces the contact suite to be gated. This is the first field-level
/// coverage check in the project that CI actually executes, and a preview of what step 4 of
/// `Docs/Features/Secure Mode/ROTATION_COVERAGE.md` would buy for contacts.
@Suite("Encrypted field coverage — AppLayerConfig rotation (no Enclave)")
struct AppLayerConfigFieldCoverageTests {

    @Test("Every AppLayerConfig field survives a rotation")
    func configFieldsSurvive() throws {
        let oldKey = SymmetricKey(size: .bits256)
        let newKey = SymmetricKey(size: .bits256)
        let config = AppLayerConfig()

        for probe in AppLayerConfig.probes.values {
            try probe.populate(config, using: oldKey)
        }

        try config.reencrypt(from: oldKey, to: newKey)

        for (name, probe) in AppLayerConfig.probes.sorted(by: { $0.key < $1.key }) {
            let mismatch = probe.mismatch(in: config, using: newKey)
            #expect(mismatch == nil, """
            `\(name)` did not survive AppLayerConfig.reencrypt: \(mismatch ?? "").

            It is listed in `AppLayerConfig.probes`, so it is claimed to be re-keyed. Either add
            it to `reencrypt(from:to:)`, or move it to `unprobedFields` with the key that
            actually seals it — the SE Secure Mode key for verifiers, the blob metadata key for
            slot indices.
            """)
        }
    }

    /// The other direction, and the one specific to this model: a field sealed under the SE
    /// Secure Mode key must come out of `reencrypt` untouched. Re-sealing it under the local DB
    /// key would strand it exactly as omitting a rotated field does — the contract calls that
    /// "as much a bug as leaving one of the above out".
    @Test("Fields outside the rotation are left byte-identical")
    func unprobedFieldsAreUntouched() throws {
        let oldKey = SymmetricKey(size: .bits256)
        let newKey = SymmetricKey(size: .bits256)
        let config = AppLayerConfig()

        // Stand-ins for SE-sealed material: `reencrypt` must not read or rewrite these.
        config.sealedNormalVerifier = Data([0xC1])
        config.sealedDuressVerifier = Data([0xC2])
        let before = (config.sealedNormalVerifier, config.sealedDuressVerifier)

        try config.reencrypt(from: oldKey, to: newKey)

        #expect(config.sealedNormalVerifier == before.0,
                "sealedNormalVerifier was rewritten — it is sealed under the SE Secure Mode key")
        #expect(config.sealedDuressVerifier == before.1,
                "sealedDuressVerifier was rewritten — it is sealed under the SE Secure Mode key")
    }
}

@Suite("Encrypted field coverage — tripwires")
struct EncryptedFieldTripwireTests {

    /// Derives from `probes` and `unprobedFields` rather than a list of its own, so silencing
    /// this tripwire requires supplying the means to populate and verify the field — which the
    /// round-trip test below then uses. Adding the name is no longer enough.
    @Test("Contact.Profile has no unreviewed stored properties")
    func profilePropertiesReviewed() {
        let actual     = storedPropertyNames(of: makeProbeProfile())
        let classified = Set(Contact.Profile.probes.keys)
            .union(Contact.Profile.unprobedFields.keys)

        // Report the difference, not the two sets. Comparing them directly makes the failure
        // print sixty names and leaves the reader to diff by eye, at exactly the moment they
        // are trying to ship.
        let unreviewed = actual.subtracting(classified)
        let stale      = classified.subtracting(actual)

        #expect(unreviewed.isEmpty, """
        Unreviewed stored properties on Contact.Profile: \(unreviewed.sorted())

        \(tripwireGuidance)
        """)

        #expect(stale.isEmpty, """
        Classified in `probes` / `unprobedFields` but no longer on the model: \(stale.sorted())

        The property was removed or renamed — delete the entry, or correct its key.
        """)
    }

    /// A field cannot be in both tables — that would mean claiming it is both re-keyed and
    /// deliberately outside the rotation.
    @Test("No Contact.Profile field is both probed and unprobed")
    func profileClassificationsAreDisjoint() {
        let both = Set(Contact.Profile.probes.keys)
            .intersection(Contact.Profile.unprobedFields.keys)

        #expect(both.isEmpty, "Classified twice: \(both.sorted())")
    }

    // Needs a Secure Enclave only because constructing a `Group` seals its fields; the
    // Profile and AppLayerConfig tripwires below have no such dependency and run everywhere.
    @Test("Group has no unreviewed stored properties", .enabled(if: secureEnclaveAvailable()))
    func groupPropertiesReviewed() throws {
        let expected: Set<String> = [
            "encryptedID", "encryptedName", "encryptedCreatedAt",
            "realMemberSlots", "duressMemberSlots", "deeperMemberSlots",
        ]

        #expect(storedPropertyNames(of: try Group(name: "probe")) == expected, "\(tripwireGuidance)")
    }

    /// Added after `Message.Draft` was found missing from `deactivateSecureMode` entirely.
    /// Its fields were never stranded by a *field* omission — the whole model was skipped by
    /// one of the two rotation paths — so this tripwire would not have caught that bug. It is
    /// here for the next one: a third field on `Draft` added without a matching change to
    /// `reKeyOrPurgeAll`, which handles exactly two and would silently carry neither.
    @Test("Message.Draft has no unreviewed stored properties")
    func draftPropertiesReviewed() {
        let expected: Set<String> = [
            // Plaintext — row identity and the on-disk attachment folder name. Also the AAD
            // input for both fields below, so it cannot itself be encrypted.
            "id",
            // Local DB key — must be covered by Message.Draft.reKeyOrPurgeAll, in both paths.
            "encryptedRecipientID", "encryptedContent",
        ]

        let probe = Message.Draft(id: UUID(), encryptedRecipientID: Data(), encryptedContent: Data())
        #expect(storedPropertyNames(of: probe) == expected, "\(tripwireGuidance)")
    }

    /// Derives from `probes` / `unprobedFields`, like Contact.Profile's above.
    @Test("AppLayerConfig has no unreviewed stored properties")
    func appLayerConfigPropertiesReviewed() {
        let actual     = storedPropertyNames(of: AppLayerConfig())
        let classified = Set(AppLayerConfig.probes.keys)
            .union(AppLayerConfig.unprobedFields.keys)

        let unreviewed = actual.subtracting(classified)
        let stale      = classified.subtracting(actual)

        #expect(unreviewed.isEmpty, """
        Unreviewed stored properties on AppLayerConfig: \(unreviewed.sorted())

        \(tripwireGuidance)
        """)

        #expect(stale.isEmpty, """
        Classified but no longer on AppLayerConfig: \(stale.sorted())
        """)
    }

    @Test("No AppLayerConfig field is both probed and unprobed")
    func appLayerConfigClassificationsAreDisjoint() {
        let both = Set(AppLayerConfig.probes.keys)
            .intersection(AppLayerConfig.unprobedFields.keys)

        #expect(both.isEmpty, "Classified twice: \(both.sorted())")
    }
}

// MARK: - Behavioural

/// `reencryptAllFields` decrypts through `Manager.Key()` internally, so the behavioural
/// half needs a Secure Enclave. The tripwires above do not, and keep running everywhere.
@Suite("Encrypted field coverage — survives rotation", .enabled(if: secureEnclaveAvailable()))
struct EncryptedFieldRotationTests {

    /// Every encrypted field on a profile must be readable after a rotation. This is the
    /// test that would have caught `maxBundleVersion` directly.
    @Test("Every encrypted Contact.Profile field survives a rotation")
    func profileFieldsSurvive() throws {
        _ = try #require(canonicalKey())
        let aad     = EncryptionScheme.v2_hybridPQ.aad
        let profile = makeProbeProfile()
        try populateEncryptedFields(of: profile)

        let newKey = SymmetricKey(size: .bits256)
        try profile.reencryptAllFields(to: newKey, aad: aad)

        // Driven by the probe table, so a field added there is checked here without any
        // further edit. This is the assertion that converts the tripwire's *awareness* into
        // *coverage*: it fails if `reencryptAllFields` does not re-key a probed field.
        for (name, probe) in Contact.Profile.probes.sorted(by: { $0.key < $1.key }) {
            let mismatch = probe.mismatch(in: profile, using: newKey)
            #expect(mismatch == nil, """
            `\(name)` did not survive the rotation: \(mismatch ?? "").

            It is listed in `Contact.Profile.probes`, so it is claimed to be re-keyed — but
            after `reencryptAllFields` it does not read back under the new key. Either add it
            to that function, or move it to `unprobedFields` with the key that actually seals it.
            """)
        }
    }

    /// The regression that motivated the preserving helper, generalised. A value stranded by an
    /// earlier rotation must stay non-nil and byte-identical — for `deletionToken`, clearing it
    /// makes `fetchAllContacts` return contacts the user deleted; for `maxBundleVersion`, it
    /// collapses "present but unreadable" into "never seen" and forecloses Bug 80's fix.
    ///
    /// Driven by the table, so a **third** `.preserving` field gets this coverage for free.
    /// Both cases were hand-written before 2026-08-16 and a new one would have had none.
    @Test("Every preserving field survives as stranded bytes, not cleared")
    func preservingFieldsAreNotCleared() throws {
        _ = try #require(canonicalKey())
        let aad = EncryptionScheme.v2_hybridPQ.aad

        for (name, probe) in Contact.Profile.probes.sorted(by: { $0.key < $1.key })
        where probe.isPreserving {
            guard let keyPath = probe.dataKeyPath else { continue }
            let profile = makeProbeProfile()

            // Sealed under a key nobody holds — the state a row stranded by an earlier
            // rotation is already in.
            profile[keyPath: keyPath] = try Data([0xEE])
                .encrypt(using: SymmetricKey(size: .bits256))
            let stranded = profile[keyPath: keyPath]

            try profile.reencryptAllFields(to: SymmetricKey(size: .bits256), aad: aad)

            #expect(profile[keyPath: keyPath] != nil,
                    "`\(name)` is marked .preserving but was cleared when unreadable")
            #expect(profile[keyPath: keyPath] == stranded,
                    "`\(name)` is marked .preserving but its stranded bytes were altered")
        }
    }

    /// A contact that was never soft-deleted must stay that way — the preserving helper
    /// must not fabricate a token out of nil.
    @Test("A nil deletionToken stays nil")
    func nilDeletionTokenStaysNil() throws {
        _ = try #require(canonicalKey())
        let profile = makeProbeProfile()
        profile.deletionToken = nil

        try profile.reencryptAllFields(
            to: SymmetricKey(size: .bits256), aad: EncryptionScheme.v2_hybridPQ.aad
        )

        #expect(profile.deletionToken == nil)
    }

    /// Why `maxBundleVersion` is `.preserving` rather than `.data`, recorded because the table
    /// entry alone does not carry it: this asserted the opposite until 2026-08-12. Clearing
    /// looked right — nil reads as "version unknown", which produces the accurate "send me a
    /// message" instead of the false "they need to update". But the field also gates a
    /// receive-side authentication check, and that gate can only be repaired if "present but
    /// unreadable" stays distinguishable from "never seen". Clearing collapses the two
    /// permanently, for exactly the installs that have the vulnerability. The message is fixed
    /// at the reading site instead. The behavioural assertion now lives in
    /// `preservingFieldsAreNotCleared`, driven by the table.
    ///
    /// The distinction Bug 80's fix depends on, asserted directly: three states, three answers.
    @Test("hasReadableBundleVersion separates stranded from never-seen")
    func readabilitySeparatesStrandedFromAbsent() throws {
        _ = try #require(canonicalKey())

        let neverSeen = makeProbeProfile()
        neverSeen.maxBundleVersion = nil
        #expect(!ContactManager.hasReadableBundleVersion(neverSeen))

        let stranded = makeProbeProfile()
        stranded.maxBundleVersion = try Data([0x07]).encrypt(using: SymmetricKey(size: .bits256))
        #expect(!ContactManager.hasReadableBundleVersion(stranded))
        #expect(stranded.maxBundleVersion != nil, "stranded must stay distinguishable from absent")

        let known = makeProbeProfile()
        known.maxBundleVersion = try Data([0x07]).encrypt()
        #expect(ContactManager.hasReadableBundleVersion(known))
    }
}

// MARK: - Fixture

private func makeProbeProfile() -> Contact.Profile {
    Contact.Profile(
        identifier: "probe", givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: "",
        phoneticGivenName: "", phoneticMiddleName: "", phoneticFamilyName: "", note: ""
    )
}

/// Seals a distinct known value into every probed field, under the canonical key that
/// `reencryptAllFields` reads with. Driven by the table, so a field added there is populated
/// here without a second edit.
private func populateEncryptedFields(of profile: Contact.Profile) throws {
    for probe in Contact.Profile.probes.values {
        try probe.populate(profile)
    }
}

private func sealString(_ value: String) throws -> String {
    guard let sealed = try Data(value.utf8).encrypt() else { return "" }
    return sealed.base64EncodedString()
}

private func decryptString(_ stored: String, using key: SymmetricKey) -> String? {
    guard let ciphertext = Data(base64Encoded: stored),
          let plain = ciphertext.decrypt(using: key)
    else { return nil }
    return String(decoding: plain, as: UTF8.self)
}
