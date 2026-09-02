//
//  RotationRegistryTests.swift
//  OccultaTests
//
//  Type-level coverage for Secure Mode key rotation: every persisted model must be classified
//  as either re-keyed by a rotation or deliberately outside it. This is the guard for the bug
//  class that stranded `Group` and `AppLayerConfig` (Bugs 75 and 76) — whole models nobody had
//  asked the model-level question about.
//
//  No crypto and no Secure Enclave: this compares two lists of names. It runs on CI runners,
//  unlike the behavioural rotation tests.
//
//  What this does NOT prove, so a green result is not over-read:
//    • that a FIELD on a classified model is covered — `EncryptedFieldCoverageTests`
//    • that a model listed as rotated is actually re-keyed in BOTH paths — behavioural tests
//  See `Docs/Features/Secure Mode/ROTATION_COVERAGE.md`.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@Suite("Rotation registry — every persisted model is classified")
struct RotationRegistryTests {

    /// SwiftData entity names for every model the app persists.
    private var schemaEntityNames: Set<String> {
        Set(OccultaApp.schema.entities.map(\.name))
    }

    private var classified: Set<String> {
        Set(RotationRegistry.rotated.keys).union(RotationRegistry.notRotated.keys)
    }

    @Test("Every model in the schema is classified exactly once")
    func schemaIsFullyClassified() {
        let unclassified = self.schemaEntityNames.subtracting(self.classified)

        #expect(unclassified.isEmpty, """
        A persisted model is not classified in `RotationRegistry`.

        Unclassified: \(unclassified.sorted())

        Decide which key seals its data and add it to exactly one list:

          • RotationRegistry.rotated — it holds ciphertext under the LOCAL DB KEY. It must then
            be re-keyed in BOTH activateSecureMode AND deactivateSecureMode. Leaving it out of
            either path strands it when the superseded key is deleted, permanently, and
            silently: that is Bugs 75, 76 and the 2026-08-14 Message.Draft gap.

          • RotationRegistry.notRotated — it is sealed under a key that never rotates (SE Secure
            Mode key, shard custody key, vault key, return-buffer key), or holds no ciphertext.
            Putting one of these through the rotation is as much a bug as leaving one out: it
            re-seals under the wrong key and strands the value the other way round.

        If it holds BOTH kinds of field, it belongs in `rotated` — the type-level question is
        whether any local-DB ciphertext exists. Record the exception in its note, as VaultEntry
        does. Whether each individual field is covered is a separate check
        (EncryptedFieldCoverageTests).
        """)
    }

    @Test("No registry entry names a model that is no longer persisted")
    func registryHasNoStaleEntries() {
        let stale = self.classified.subtracting(self.schemaEntityNames)

        #expect(stale.isEmpty, """
        `RotationRegistry` classifies a model that is not in `OccultaApp.schema`.

        Stale: \(stale.sorted())

        Either the model was removed from the schema — in which case delete its registry entry —
        or the entry's key does not match the SwiftData entity name. Entity names are the simple
        type name, so `Contact.Profile` is "Profile" and `Message.Draft` is "Draft".
        """)
    }

    @Test("No model is classified as both rotated and not rotated")
    func classificationsAreDisjoint() {
        let both = Set(RotationRegistry.rotated.keys)
            .intersection(RotationRegistry.notRotated.keys)

        #expect(both.isEmpty, """
        A model appears in both `rotated` and `notRotated`: \(both.sorted())

        The type-level question is whether ANY of its ciphertext is under the local DB key. If
        some fields are and some are not — VaultEntry is the live example — it belongs in
        `rotated`, with the exception recorded in its note.
        """)
    }

    @Test("Every classification carries a reason")
    func everyEntryExplainsItself() {
        let empty = RotationRegistry.rotated.merging(RotationRegistry.notRotated) { a, _ in a }
            .filter { $0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .keys
            .sorted()

        #expect(empty.isEmpty, """
        These entries have no reason recorded: \(empty)

        The reason is the only place the "why" survives — which key seals the data, and what
        happens if it moves. The rotation contract's own table shows these are non-obvious.
        """)
    }
}
