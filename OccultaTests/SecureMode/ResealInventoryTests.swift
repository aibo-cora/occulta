//
//  ResealInventoryTests.swift
//  OccultaTests
//
//  Bug 171 (`Docs/Features/Secure Mode/bugs.md`): the schema guard for the reseal inventory
//  (`KeyReseal+Inventory.swift`).
//
//  The reseal moves every value sealed under a legacy key onto its Enclave-bound key. A sealed field missing
//  from the inventory is a field the reseal skips, and a skipped field stays readable by anyone holding Q. So
//  every `Data`, `[Data]` and `String` attribute of `OccultaApp.schema` has to be in the inventory or on the
//  exempt list with a reason, so adding one later fails here and not on a user's device.
//
//  Strings are guarded too: a contact's names, phone numbers, addresses and the identifier are base64 of a
//  sealed `Data`, and a reseal that looked at `Data` alone would leave every one of them under the old key.
//
//  Runs without a Secure Enclave.
//

import Testing
import Foundation
import SwiftData

@testable import Occulta

@Suite("Reseal inventory — every sealed attribute is listed")
struct ResealInventoryTests {

    /// The attribute types that can hold neither a sealed value nor a reference to one. Anything not here and
    /// not guarded (`[String]`, `[UInt8]`, a transformable) fails `everyAttributeTypeIsKnown`: it has to be
    /// looked at and added to one list or the other.
    private static let plainTypes: [Any.Type] = [
        UUID.self, UUID?.self, Date.self, Date?.self, Int.self, Int?.self, Bool.self, Bool?.self, Double.self, Double?.self
    ]

    private static func shape(of type: Any.Type) -> KeyReseal.Shape? {
        if type == Data.self     || type == Data?.self     { return .data }
        if type == [Data].self   || type == [Data]?.self   { return .dataArray }
        if type == [[Data]].self || type == [[Data]]?.self { return .nestedDataArray }
        if type == String.self   || type == String?.self   { return .string }
        return nil
    }

    private struct SchemaAttribute: Hashable, CustomStringConvertible {
        let model: String
        let attribute: String
        let shape: KeyReseal.Shape?
        let typeName: String

        var description: String { "\(self.model).\(self.attribute) (\(self.typeName))" }
    }

    /// Every stored attribute of every entity in the schema.
    private static let schemaAttributes: [SchemaAttribute] = OccultaApp.schema.entities.flatMap { entity in
        entity.attributes.map {
            SchemaAttribute(model: entity.name, attribute: $0.name, shape: Self.shape(of: $0.valueType), typeName: String(describing: $0.valueType))
        }
    }

    private static func key(_ model: String, _ attribute: String) -> String { "\(model).\(attribute)" }

    @Test("Every Data, [Data] and String attribute is in the inventory or on the exempt list")
    func everyGuardedAttributeIsListed() {
        let listed = Set(KeyReseal.fields.map { Self.key($0.model, $0.attribute) })
            .union(KeyReseal.exempt.map { Self.key($0.model, $0.attribute) })

        let missing = Self.schemaAttributes
            .filter { $0.shape != nil }
            .filter { !listed.contains(Self.key($0.model, $0.attribute)) }

        #expect(missing.isEmpty, "not in `KeyReseal.fields` or `KeyReseal.exempt`, so the reseal would skip it: \(missing.map(\.description).sorted())")
    }

    @Test("Every inventory and exempt entry names an attribute the schema still has, with the shape it lists")
    func noEntryIsStaleOrMisshaped() {
        let byKey = Dictionary(uniqueKeysWithValues: Self.schemaAttributes.map { (Self.key($0.model, $0.attribute), $0) })

        for field in KeyReseal.fields {
            let schema = byKey[Self.key(field.model, field.attribute)]
            #expect(schema != nil, "\(field.model).\(field.attribute) is in the inventory but not in the schema")
            #expect(schema?.shape == field.shape, "\(field.model).\(field.attribute): the inventory says \(field.shape), the schema says \(schema?.typeName ?? "nothing")")
        }
        for entry in KeyReseal.exempt {
            let schema = byKey[Self.key(entry.model, entry.attribute)]
            #expect(schema != nil, "\(entry.model).\(entry.attribute) is exempt but not in the schema")
            #expect(schema?.shape != nil, "\(entry.model).\(entry.attribute) is exempt but the guard doesn't look at its type, so the entry is dead")
            #expect(!entry.reason.isEmpty, "\(entry.model).\(entry.attribute) is exempt without a reason")
        }
    }

    @Test("No attribute is listed twice, or in both the inventory and the exempt list")
    func noDuplicates() {
        let fieldKeys  = KeyReseal.fields.map { Self.key($0.model, $0.attribute) }
        let exemptKeys = KeyReseal.exempt.map { Self.key($0.model, $0.attribute) }

        #expect(Set(fieldKeys).count == fieldKeys.count, "duplicated in the inventory: \(Dictionary(grouping: fieldKeys, by: { $0 }).filter { $0.value.count > 1 }.keys.sorted())")
        #expect(Set(exemptKeys).count == exemptKeys.count)
        #expect(Set(fieldKeys).isDisjoint(with: exemptKeys))
    }

    @Test("Every attribute type is one the guard understands or knows to be plain")
    func everyAttributeTypeIsKnown() {
        let unknown = Self.schemaAttributes.filter { attribute in
            attribute.shape == nil && !Self.plainTypes.contains { String(describing: $0) == attribute.typeName }
        }

        #expect(unknown.isEmpty, "a type the guard hasn't been taught, which could hold sealed bytes: \(unknown.map(\.description).sorted())")
    }

    @Test("The schema has the entities the inventory was written against")
    func entitiesAreAccountedFor() {
        let entities = Set(OccultaApp.schema.entities.map(\.name))
        let inventoried = Set(KeyReseal.fields.map(\.model)).union(KeyReseal.exempt.map(\.model))
        // Entities with no sealed attribute: `Vault` holds an id and a relationship.
        let withoutSealedAttributes: Set<String> = ["Vault"]

        #expect(entities.subtracting(inventoried).subtracting(withoutSealedAttributes).isEmpty,
                "an entity with no entry: \(entities.subtracting(inventoried).subtracting(withoutSealedAttributes).sorted())")
        #expect(inventoried.subtracting(entities).isEmpty)
    }

    // MARK: Consistency of the entries themselves

    @Test("Contact.Profile.identifier is the one reference key, and is not resealed by default")
    func identifierIsTheReference() {
        let references = KeyReseal.fields.filter { $0.treatment == .reference }

        #expect(references.map { Self.key($0.model, $0.attribute) } == ["Profile.identifier"])
        #expect(references.first?.key == .local)
        #expect(references.first?.shape == .string)
    }

    @Test("What is resealed is sealed under a key the fix changes; what is not affected is under one it doesn't")
    func treatmentMatchesTheKey() {
        for field in KeyReseal.fields {
            switch field.treatment {
            case .reseal, .reference:
                #expect(field.key != .other, "\(field.model).\(field.attribute) is resealed, so it has to name its key")
            case .notAffected:
                #expect(field.key == .other, "\(field.model).\(field.attribute) is not affected, so its key is not one of ours")
            case .retired:
                break
            }
        }
    }

    @Test("PIN verifiers carry no AAD; custody, restore and vault payloads are bound to their row")
    func aadMatchesTheKey() {
        for field in KeyReseal.fields where field.key == .pin {
            #expect(field.aad == .none, "\(field.model).\(field.attribute)")
        }
        for field in KeyReseal.fields where field.key == .custody || field.key == .restore || field.key == .vault {
            #expect(field.aad == .row, "\(field.model).\(field.attribute)")
        }
    }

    @Test("The sealed files: backup-export-meta.dat is under the vault key and resealed; draft attachments under the compose key are tier U's and moved by the upgrade; those under a per-contact key are not affected")
    func files() throws {
        let meta = try #require(KeyReseal.files.first { $0.name == "backup-export-meta.dat" })
        #expect(meta.key == .vault)
        #expect(meta.treatment == .reseal)
        #expect(meta.aad.contains("occulta.backup-export-meta-v1"))

        let drafts = KeyReseal.files.filter { $0.location.contains("Drafts") }
        #expect(drafts.count == 2)
        let compose = try #require(drafts.first { $0.key == .compose })
        #expect(compose.treatment == .reseal, "tier U's, moved from the classical compose key to the hybrid one by the Stage 6 upgrade")
        let perContact = try #require(drafts.first { $0.key == .other })
        #expect(perContact.treatment == .notAffected)

        // The files the reseal and the upgrade move.
        #expect(Set(KeyReseal.files.filter { $0.treatment == .reseal }.map(\.key)) == [.vault, .compose])
    }

    @Test("The tiers: which fields each of the four keys the reseal moves seals")
    func fieldsPerKey() {
        func attributes(_ key: KeyReseal.Key) -> Set<String> {
            Set(KeyReseal.fields.filter { $0.key == key && $0.treatment != .retired }.map { "\($0.model).\($0.attribute)" })
        }

        #expect(attributes(.custody) == [
            "CustodyShard.encryptedPayload", "PendingShardDistribute.encryptedPayload",
            "PendingShardStatusUpdate.encryptedPayload", "PotentiallyLostShard.encryptedPayload"
        ])
        #expect(attributes(.restore) == ["PendingShamirSecretRestore.shards"])
        #expect(attributes(.vault) == ["VaultEntry.encryptedEntryKey", "BackupEncryptionKey.encryptedPayload"])
        #expect(attributes(.pin) == [
            "AppLayerConfig.sealedNormalVerifier", "AppLayerConfig.sealedDuressVerifier",
            "AppLayerConfig.sealedNormalVerifiers", "AppLayerConfig.sealedDuressVerifiers"
        ])
    }
}
