//
//  DepthCodecTests.swift
//  OccultaTests
//
//  Guards for Bug 85. AES-GCM is length-preserving, so a stored depth field is
//  exactly its plaintext + 28 bytes and the plaintext's length is readable from the
//  store file with no key. The property under test is therefore the plaintext
//  format, not the ciphertext — which is why none of this needs the Secure Enclave.
//  The one test that seals anything uses a locally generated SymmetricKey rather
//  than Manager.Key(), so the whole suite runs on CI runners.
//
//  `plaintextLengthIsUniform` was written against the old JSON format and failed
//  against it — [1, 2, 19] distinct lengths, Int.max at 19 bytes. It passes now that
//  the format is fixed-width, and is kept as the regression guard.
//
//  The DepthFixedWidthMigrationTests suite at the bottom needs a real Secure Enclave:
//  the migration goes through Data.encrypt()/decrypt(), which hardcode
//  Manager.Crypto() with no injection seam.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

@Suite("DepthCodec — Bug 85 plaintext format")
struct DepthCodecTests {

    /// Every value the three `Contact.Profile` depth fields actually write.
    /// `Int.max` is not an edge case — it is the default for every new contact and
    /// the value written for every contact marked safe.
    private static let allWrittenValues: [Int] = [
        Int.max,   // visibleThroughDepth — always visible (safe)
        -1,        // globalTrusteeDepth  — not a trustee
        0,         // hidden at all duress depths; also originDepth's sentinel
        1, 9,      // depths whose JSON is one byte
        10, 31,    // depths whose JSON is two bytes
    ]

    // MARK: - Bug 85: the length must not carry the value

    /// The guard the entry says was missing. Fails against the JSON format
    /// (`Int.max` is 19 bytes, an ordinary depth 1–2), passes once the plaintext is
    /// fixed-width.
    @Test("Plaintext length is identical for every value written — Bug 85")
    func plaintextLengthIsUniform() throws {
        var lengthsByValue: [Int: Int] = [:]
        for value in Self.allWrittenValues {
            lengthsByValue[value] = try DepthCodec.encode(value).count
        }
        let distinct = Set(lengthsByValue.values)
        #expect(distinct.count == 1, """
            DepthCodec.encode produces \(distinct.sorted()) distinct plaintext lengths: \
            \(lengthsByValue.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)B" }.joined(separator: ", ")).
            AES-GCM does not pad, so each distinct plaintext length is a distinct \
            ciphertext length in the store file. A contact marked safe (Int.max) must not \
            be distinguishable from a hidden one (a small depth) by column length alone.
            """)
    }

    /// Why the test above is sufficient on its own: sealing adds a constant, so
    /// uniform plaintext is exactly equivalent to uniform ciphertext. If this ever
    /// fails, `plaintextLengthIsUniform` has stopped implying what it claims to.
    @Test("Sealed length is plaintext + 28, so uniform plaintext is the whole fix")
    func sealedLengthTracksPlaintextByAConstant() throws {
        let key = SymmetricKey(size: .bits256)
        for value in Self.allWrittenValues {
            let plain  = try DepthCodec.encode(value)
            let sealed = try AES.GCM.seal(plain, using: key).combined
            #expect(sealed?.count == plain.count + 28,
                    "AES-GCM .combined is nonce(12) + ciphertext + tag(16) for value \(value)")
        }
    }

    // MARK: - Round-trip

    /// A format change that loses a value is worse than the leak it fixes: the
    /// deactivation path re-seals whatever it decodes, so a value that fails to
    /// round-trip is written back wrong and permanently.
    @Test("Every written value survives encode → decode unchanged")
    func everyWrittenValueRoundTrips() throws {
        for value in Self.allWrittenValues {
            let decoded = DepthCodec.decode(try DepthCodec.encode(value))
            #expect(decoded == value, "\(value) did not survive the round-trip (got \(String(describing: decoded)))")
        }
    }

    // MARK: - The migration contract

    /// `decode` must report failure rather than inventing a value. This is the
    /// precondition that lets a normalisation pass tell "this row is stranded, leave
    /// its bytes alone" apart from "this row reads as 0".
    ///
    /// Without it a migration cannot be written safely at all: substituting a default
    /// for an unreadable ceiling persists that default, and the only fail-open default
    /// available (`Int.max`) means *visible at every duress depth*.
    @Test("decode reports failure instead of substituting a default")
    func decodeNeverSubstitutesADefault() {
        #expect(DepthCodec.decode(Data()) == nil, "empty plaintext must not decode to a value")
        #expect(DepthCodec.decode(Data([0xA5, 0x5A, 0x3C])) == nil, "garbage must not decode to a value")
    }

    /// The state a normalisation pass must not overwrite.
    ///
    /// A `visibleThroughDepth` that will not decrypt currently keeps the contact
    /// hidden — `isVisible` fails closed, per its own comment: "non-nil field that
    /// won't decrypt = sensitive shell; exclude". Any pass that rewrites such a row to
    /// a readable `Int.max` converts a hidden contact into one visible at every duress
    /// depth, irreversibly, because the original ciphertext is gone.
    ///
    /// Enclave-independent by construction: the field is garbage, so `decrypt()`
    /// returns nil whether or not a real key is available.
    @Test("An unreadable ceiling keeps the contact hidden — the state a migration must preserve")
    @MainActor
    func unreadableCeilingFailsClosed() throws {
        let profile = Contact.Profile(
            identifier: "stranded", givenName: "Test", familyName: "Contact", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.visibleThroughDepth = Data([0xA5, 0x5A])   // present, will not decrypt

        #expect(profile.isVisible(atDepth: 0) == false,
                "a contact whose ceiling will not decrypt must be treated as hidden, not visible")
        #expect(profile.isVisible(atDepth: 1) == false,
                "the same at any deeper duress depth")
    }

    // MARK: - Legacy format

    /// The dual-format read, which has to keep working for as long as un-migrated rows
    /// exist. A legacy plaintext is a JSON integer — ASCII — so it can never begin with
    /// the 0xFF tag, which is what makes the two formats separable at all.
    @Test("Legacy JSON plaintexts still decode, and cannot be confused with the new format")
    func legacyPlaintextsStillDecode() throws {
        for value in Self.allWrittenValues {
            let legacy = try JSONEncoder().encode(value)
            #expect(legacy.first != 0xFF, "a legacy plaintext must never begin with the format tag")
            #expect(DepthCodec.decode(legacy) == value,
                    "legacy JSON \(String(data: legacy, encoding: .utf8) ?? "?") must still decode to \(value)")
        }
    }

    /// `encode` is called between the staged-key creation and the commit in
    /// `deactivateSecureMode`, where a throw rolls back but a trap kills the process.
    /// Depth is not structurally bounded, so out-of-range input must clamp, not trap.
    @Test("encode is total — no input traps, and out-of-range clamps fail-closed")
    func encodeIsTotal() {
        #expect(DepthCodec.encode(DepthCodec.maxEncodableDepth + 1).count == 2)
        #expect(DepthCodec.encode(Int.max - 1).count == 2)
        #expect(DepthCodec.encode(Int.min).count == 2)
        #expect(DepthCodec.encode(-999).count == 2)

        // Clamping is downward: a ceiling above the encodable range hides the contact
        // deeper rather than exposing it, and never collides with the always-visible
        // sentinel.
        #expect(DepthCodec.decode(DepthCodec.encode(DepthCodec.maxEncodableDepth + 1)) == DepthCodec.maxEncodableDepth)
        #expect(DepthCodec.decode(DepthCodec.encode(Int.max - 1)) != Int.max,
                "a large-but-finite ceiling must not be promoted to always-visible")
    }
}

// MARK: - Migration

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        VaultEntry.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

@MainActor
@discardableResult
private func insertContact(
    identifier: String,
    visibleThroughDepth: Data?,
    in context: ModelContext
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "Test", familyName: "Contact", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.visibleThroughDepth = visibleThroughDepth
    context.insert(profile)
    try context.save()
    return profile
}

@Suite("Depth fields — fixed-width normalisation", .enabled(if: secureEnclaveAvailable()))
@MainActor
struct DepthFixedWidthMigrationTests {

    /// The point of the whole exercise: after the pass, a safe contact's column is
    /// indistinguishable in length from a hidden one's.
    @Test("Legacy rows converge to one ciphertext length, values intact")
    func legacyRowsConverge() throws {
        let context = ModelContext(try makeContainer())
        try insertContact(identifier: "safe",
                          visibleThroughDepth: JSONEncoder().encode(Int.max).encrypt(), in: context)
        try insertContact(identifier: "hidden",
                          visibleThroughDepth: JSONEncoder().encode(0).encrypt(), in: context)
        try insertContact(identifier: "deep",
                          visibleThroughDepth: JSONEncoder().encode(12).encrypt(), in: context)

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)

        let rows = try context.fetch(FetchDescriptor<Contact.Profile>())
        let lengths = Set(rows.compactMap { $0.visibleThroughDepth?.count })
        #expect(lengths.count == 1,
                "after normalisation every row must be one length, got \(lengths.sorted()) — Bug 85")

        func ceiling(_ id: String) -> Int? {
            rows.first { $0.identifier == id }?.visibleThroughDepth
                .flatMap { $0.decrypt() }.flatMap { DepthCodec.decode($0) }
        }
        #expect(ceiling("safe")   == Int.max, "the safe contact's ceiling must survive verbatim")
        #expect(ceiling("hidden") == 0,       "the hidden contact's ceiling must survive verbatim")
        #expect(ceiling("deep")   == 12,      "a two-digit legacy depth must survive verbatim")
    }

    /// Bug 87's failure mode, written into a migration: it would fire on every stranded
    /// row at once. An unreadable ceiling currently keeps the contact hidden, and the
    /// only permissive default available (`Int.max`) means visible at every duress depth.
    @Test("A row that will not decrypt is left byte-identical")
    func undecryptableRowIsUntouched() throws {
        let context = ModelContext(try makeContainer())
        let stranded = Data([0xA5, 0x5A, 0x3C, 0x7E])
        try insertContact(identifier: "stranded", visibleThroughDepth: stranded, in: context)

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)

        let row = try context.fetch(FetchDescriptor<Contact.Profile>()).first
        #expect(row?.visibleThroughDepth == stranded, """
            A ceiling that will not decrypt must be preserved exactly. Resolving it to a \
            default persists that default, and Int.max means visible at every duress \
            depth — permanently, because the original ciphertext is gone.
            """)
        #expect(row?.isVisible(atDepth: 1) == false, "and it must still read as hidden")
    }

    /// nil is the never-classified default that the three backfills own; this pass must
    /// not invent a value for it.
    @Test("A nil field is left nil — the backfills own that case")
    func nilFieldIsUntouched() throws {
        let context = ModelContext(try makeContainer())
        try insertContact(identifier: "never-classified", visibleThroughDepth: nil, in: context)

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)

        let row = try context.fetch(FetchDescriptor<Contact.Profile>()).first
        #expect(row?.visibleThroughDepth == nil)
    }

    // MARK: - VaultEntry

    /// `VaultEntry` carries the same stamp under the same key, with a narrower range — no
    /// `Int.max` sentinel, just a depth — so its leak is the second-order one: depth ≥ 10
    /// is two JSON bytes where a smaller depth is one. Same defect, same fix.
    @Test("Vault entries converge too, values intact")
    func vaultEntriesConverge() throws {
        let context = ModelContext(try makeContainer())
        let shallow = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
        shallow.visibleThroughDepth = try JSONEncoder().encode(2).encrypt()
        let deep = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
        deep.visibleThroughDepth = try JSONEncoder().encode(12).encrypt()   // 2 JSON bytes
        context.insert(shallow)
        context.insert(deep)
        try context.save()

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)

        let rows = try context.fetch(FetchDescriptor<VaultEntry>())
        let lengths = Set(rows.compactMap { $0.visibleThroughDepth?.count })
        #expect(lengths.count == 1,
                "a depth of 12 must not be distinguishable from 2 by length, got \(lengths.sorted())")

        func depth(_ id: UUID) -> Int? {
            rows.first { $0.id == id }?.visibleThroughDepth
                .flatMap { $0.decrypt() }.flatMap { DepthCodec.decode($0) }
        }
        #expect(depth(shallow.id) == 2)
        #expect(depth(deep.id)    == 12)
    }

    /// `VaultEntry`'s nil means something `Contact.Profile`'s does not. `isEntryVisible`
    /// reads nil as *visible at every depth* — the documented state for entries pre-dating
    /// the field — so manufacturing a value here would change what the user sees, not just
    /// the bytes. There is no backfill that owns this case either.
    @Test("A nil vault stamp stays nil — it means visible, not missing")
    func nilVaultStampIsUntouched() throws {
        let context = ModelContext(try makeContainer())
        let entry = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
        entry.visibleThroughDepth = nil
        context.insert(entry)
        try context.save()

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)

        let row = try context.fetch(FetchDescriptor<VaultEntry>()).first
        #expect(row?.visibleThroughDepth == nil,
                "stamping a value here would hide an entry the user can currently see")
    }

    /// It runs on every launch, so a second run must be a no-op rather than re-sealing
    /// with a fresh nonce — which would churn the WAL on every start.
    @Test("Running twice changes nothing the second time")
    func migrationIsIdempotent() throws {
        let context = ModelContext(try makeContainer())
        try insertContact(identifier: "safe",
                          visibleThroughDepth: JSONEncoder().encode(Int.max).encrypt(), in: context)

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)
        let afterFirst = try context.fetch(FetchDescriptor<Contact.Profile>()).first?.visibleThroughDepth

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)
        let afterSecond = try context.fetch(FetchDescriptor<Contact.Profile>()).first?.visibleThroughDepth

        #expect(afterFirst == afterSecond, "the second run must not re-seal an already-converted row")
    }
}
