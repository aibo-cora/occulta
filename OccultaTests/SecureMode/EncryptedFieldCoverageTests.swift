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
//     list here. Adding any property fails the test until someone acknowledges it. This
//     cannot tell whether a new field needs re-keying; it forces the decision to be made,
//     which is precisely what did not happen for `maxBundleVersion`.
//
//  2. **Behavioural** — populate every encrypted field, rotate, assert each one still
//     reads. This catches the actual defect rather than a proxy for it. The tripwire is
//     what forces this fixture to be updated when a field is added.
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

Then add the name to the list in this test.
"""

// MARK: - Tripwires

@Suite("Encrypted field coverage — tripwires")
struct EncryptedFieldTripwireTests {

    @Test("Contact.Profile has no unreviewed stored properties")
    func profilePropertiesReviewed() {
        let expected: Set<String> = [
            // Plaintext — `identifier` is queried with #Predicate and cannot be encrypted;
            // `encryptionScheme` is a plain Int discriminator.
            "identifier", "encryptionScheme",
            // Encrypted strings (base64 ciphertext).
            "givenName", "familyName", "middleName", "namePrefix", "nameSuffix", "nickname",
            "organizationName", "departmentName", "jobTitle", "phoneticGivenName",
            "phoneticMiddleName", "phoneticFamilyName", "birthday", "note",
            // Encrypted Data.
            "thumbnailImageData", "imageData", "forwardSecrecyEncrypted", "signedAttributes",
            "deletionToken", "visibleThroughDepth", "globalTrusteeDepth", "maxBundleVersion",
            "originDepth",
            // Relationships — re-encrypted via their own loops.
            "phoneNumbers", "emailAddresses", "postalAddresses", "urlAddresses",
            "contactPublicKeys",
        ]

        #expect(storedPropertyNames(of: makeProbeProfile()) == expected, "\(tripwireGuidance)")
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

    @Test("AppLayerConfig has no unreviewed stored properties")
    func appLayerConfigPropertiesReviewed() {
        let expected: Set<String> = [
            // Sealed by PINManager under the SE Secure Mode key — never rotate.
            "sealedNormalVerifier", "sealedDuressVerifier",
            "sealedNormalVerifiers", "sealedDuressVerifiers",
            // Sealed under the SE-derived blob metadata key — never rotate.
            "sealedBlobSlots", "layerSequenceNumbers",
            // Local DB key — must be covered by AppLayerConfig.reencrypt.
            "persistedDepth", "pinEnabled", "pinEnabledPerDepth", "coercerBaseDepth",
            "lockoutCountEncrypted", "lockoutAnchorUptimeEncrypted",
        ]

        #expect(storedPropertyNames(of: AppLayerConfig()) == expected, "\(tripwireGuidance)")
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

        // Encrypted strings.
        #expect(decryptString(profile.givenName,          using: newKey) == "given")
        #expect(decryptString(profile.familyName,         using: newKey) == "family")
        #expect(decryptString(profile.middleName,         using: newKey) == "middle")
        #expect(decryptString(profile.namePrefix,         using: newKey) == "prefix")
        #expect(decryptString(profile.nameSuffix,         using: newKey) == "suffix")
        #expect(decryptString(profile.nickname,           using: newKey) == "nick")
        #expect(decryptString(profile.organizationName,   using: newKey) == "org")
        #expect(decryptString(profile.departmentName,     using: newKey) == "dept")
        #expect(decryptString(profile.jobTitle,           using: newKey) == "job")
        #expect(decryptString(profile.phoneticGivenName,  using: newKey) == "pgiven")
        #expect(decryptString(profile.phoneticMiddleName, using: newKey) == "pmiddle")
        #expect(decryptString(profile.phoneticFamilyName, using: newKey) == "pfamily")
        #expect(decryptString(profile.note,               using: newKey) == "note")
        #expect(decryptString(profile.birthday ?? "",     using: newKey) == "birthday")

        // Encrypted Data.
        #expect(profile.imageData?.decrypt(using: newKey)               == Data([0xA1]))
        #expect(profile.thumbnailImageData?.decrypt(using: newKey)      == Data([0xA2]))
        #expect(profile.forwardSecrecyEncrypted?.decrypt(using: newKey) == Data([0xA3]))
        #expect(profile.signedAttributes?.decrypt(using: newKey)        == Data([0xA4]))
        #expect(profile.visibleThroughDepth?.decrypt(using: newKey)     == Data([0xA5]))
        #expect(profile.globalTrusteeDepth?.decrypt(using: newKey)      == Data([0xA6]))
        #expect(profile.originDepth?.decrypt(using: newKey)             == Data([0xA7]))

        // The field this whole suite exists for.
        #expect(profile.maxBundleVersion?.decrypt(using: newKey) == Data([0x07]))

        // Presence-carrying field: still present, and now readable under the new key.
        #expect(profile.deletionToken != nil)
        #expect(profile.deletionToken?.decrypt(using: newKey) == Data([1]))
    }

    /// The regression that motivated the preserving helper. A token stranded by an earlier
    /// rotation must stay non-nil, or `fetchAllContacts` starts returning contacts the user
    /// deleted.
    @Test("An unreadable deletionToken is preserved, not cleared")
    func strandedDeletionTokenPreserved() throws {
        _ = try #require(canonicalKey())
        let aad     = EncryptionScheme.v2_hybridPQ.aad
        let profile = makeProbeProfile()

        // Sealed under a key nobody holds — the state every row soft-deleted before this
        // field was covered is already in.
        profile.deletionToken = try Data([1]).encrypt(using: SymmetricKey(size: .bits256))
        let stranded = profile.deletionToken

        try profile.reencryptAllFields(to: SymmetricKey(size: .bits256), aad: aad)

        #expect(profile.deletionToken != nil)
        #expect(profile.deletionToken == stranded)
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

    /// An unreadable `maxBundleVersion` must be **preserved**, not cleared (Bug 80).
    ///
    /// This asserted the opposite until 2026-08-12. Clearing looked right — nil reads as
    /// "version unknown", which produces the accurate "send me a message" instead of the false
    /// "they need to update". But this field also gates a receive-side authentication check,
    /// and that gate can only be repaired if "present but unreadable" stays distinguishable
    /// from "never seen". Clearing collapses the two permanently, for exactly the installs that
    /// have the vulnerability. The message is fixed at the reading site instead.
    @Test("An unreadable maxBundleVersion is preserved, not cleared")
    func strandedMaxBundleVersionPreserved() throws {
        _ = try #require(canonicalKey())
        let profile = makeProbeProfile()
        profile.maxBundleVersion = try Data([0x07]).encrypt(using: SymmetricKey(size: .bits256))
        let stranded = profile.maxBundleVersion

        try profile.reencryptAllFields(
            to: SymmetricKey(size: .bits256), aad: EncryptionScheme.v2_hybridPQ.aad
        )

        #expect(profile.maxBundleVersion != nil)
        #expect(profile.maxBundleVersion == stranded)
    }

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

/// Seals a distinct known value into every encrypted field, under the canonical key that
/// `reencryptAllFields` reads with.
private func populateEncryptedFields(of profile: Contact.Profile) throws {
    profile.givenName          = try sealString("given")
    profile.familyName         = try sealString("family")
    profile.middleName         = try sealString("middle")
    profile.namePrefix         = try sealString("prefix")
    profile.nameSuffix         = try sealString("suffix")
    profile.nickname           = try sealString("nick")
    profile.organizationName   = try sealString("org")
    profile.departmentName     = try sealString("dept")
    profile.jobTitle           = try sealString("job")
    profile.phoneticGivenName  = try sealString("pgiven")
    profile.phoneticMiddleName = try sealString("pmiddle")
    profile.phoneticFamilyName = try sealString("pfamily")
    profile.note               = try sealString("note")
    profile.birthday           = try sealString("birthday")

    profile.imageData               = try Data([0xA1]).encrypt()
    profile.thumbnailImageData      = try Data([0xA2]).encrypt()
    profile.forwardSecrecyEncrypted = try Data([0xA3]).encrypt()
    profile.signedAttributes        = try Data([0xA4]).encrypt()
    profile.visibleThroughDepth     = try Data([0xA5]).encrypt()
    profile.globalTrusteeDepth      = try Data([0xA6]).encrypt()
    profile.originDepth             = try Data([0xA7]).encrypt()
    profile.maxBundleVersion        = try Data([0x07]).encrypt()
    profile.deletionToken           = try Data([1]).encrypt()
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
