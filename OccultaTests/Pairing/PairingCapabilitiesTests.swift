//
//  PairingCapabilitiesTests.swift
//  OccultaTests
//
//  Bug 196: the upgrade glyph in the contact list and the rows in the detail view read `Contact.Profile.pairingCapabilities`.
//  It is computed from the contact's own sealed key row each time and stored nowhere: it shows an upgrade only where a
//  re-exchange would give the pairing pair keys, says the same at every depth, writes nothing, and clears itself when a
//  pairing with pair keys is saved.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    return ContactManager(modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
}

private func pairKeys(mldsa: Bool = false, peerMLDSA: Bool = false) -> PairKeys {
    func key(_ byte: UInt8) -> Data { Data(repeating: byte, count: 65) }
    return PairKeys(
        ourAgreementBlob: Data(repeating: 1, count: 143), ourAgreementKey: key(2), ourSigningBlob: Data(repeating: 3, count: 143),
        ourSigningKey: key(4), peerAgreementKey: key(5), peerSigningKey: key(6),
        ourMLDSABlob: mldsa ? Data(repeating: 7, count: 100) : nil,
        peerMLDSAKey: peerMLDSA ? Data(repeating: 8, count: PairingCodec.mldsaKeySize) : nil
    )
}

@MainActor
@discardableResult
private func insert(
    _ cm: ContactManager, state: PairingState = .empty, tier: OccultaBundle.Version? = .pairingCapable,
    quantum: Bool = false, hidden: Bool = false, keys: Int = 1
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    var rows: [Contact.Profile.Key] = []
    for index in 0..<keys {
        let row = Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: Data(repeating: UInt8(index + 4), count: 65)), owner: Data(), date: Data(),
            quantumKeyMaterialEncrypted: quantum ? try Manager.Crypto().encrypt(data: Data("{}".utf8)) : nil
        )
        try cm.store(state, in: row)
        rows.append(row)
    }
    profile.contactPublicKeys = rows
    if let byte = tier?.wireByte { profile.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([byte])) }
    if hidden { profile.visibleThroughDepth = try DepthCodec.encode(0).encrypt() }
    try cm.insertProfile(profile)
    return profile
}

@MainActor
@Suite("Bug 196 — the upgrade glyph and the capability rows", .serialized)
struct PairingCapabilitiesTests {

    @Test("A pairing with pair keys offers no upgrade and says so", .ambientTestKeyManager)
    func pairedHasNothingToUpgrade() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: pairKeys()))

        let caps = contact.pairingCapabilities
        #expect(caps.pairKeys && !caps.upgradeAvailable)
        #expect(!caps.postQuantumSignatures, "neither phone made an ML-DSA key")
    }

    @Test("A pairing without pair keys offers an upgrade when the contact's build could give one", .ambientTestKeyManager)
    func plainWithACapablePeerOffersAnUpgrade() throws {
        let cm = try makeContactManager()
        let capable = try insert(cm, tier: .pairingCapable)
        let newer = try insert(cm, tier: .pairingCapable)
        #expect(capable.pairingCapabilities.upgradeAvailable)
        #expect(newer.pairingCapabilities == capable.pairingCapabilities)
    }

    @Test("A contact on an older build, or one never heard from, shows no upgrade: a re-exchange could not help", .ambientTestKeyManager)
    func olderPeerShowsNothing() throws {
        let cm = try makeContactManager()
        for tier in [OccultaBundle.Version.streamedBodyCapable, .bodyDigestCapable, .v3fs, nil] as [OccultaBundle.Version?] {
            let contact = try insert(cm, tier: tier)
            #expect(!contact.pairingCapabilities.upgradeAvailable, "tier \(String(describing: tier))")
            #expect(!contact.pairingCapabilities.pairKeys)
        }
    }

    @Test("A contact with no current key has nothing to upgrade", .ambientTestKeyManager)
    func noKeyNoUpgrade() throws {
        let cm = try makeContactManager()
        #expect(try insert(cm, keys: 0).pairingCapabilities == .none)
    }

    @Test("ML-KEM comes from the exchange being hybrid, and ML-DSA only when both phones made a key", .ambientTestKeyManager)
    func postQuantumRows() throws {
        let cm = try makeContactManager()
        let hybrid = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: pairKeys(mldsa: true, peerMLDSA: true)), quantum: true)
        let classical = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: pairKeys(mldsa: true)), quantum: false)

        #expect(hybrid.pairingCapabilities.postQuantumAgreement && hybrid.pairingCapabilities.postQuantumSignatures)
        #expect(!classical.pairingCapabilities.postQuantumAgreement && !classical.pairingCapabilities.postQuantumSignatures, "one side's key is not enough")
    }

    @Test("The ML-DSA row never drives the upgrade", .ambientTestKeyManager)
    func mldsaNeverDrivesTheIcon() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: pairKeys()))
        #expect(!contact.pairingCapabilities.postQuantumSignatures)
        #expect(!contact.pairingCapabilities.upgradeAvailable)
    }

    @Test("A contact hidden at the current depth reads exactly as a visible one with the same row", .ambientTestKeyManager)
    func sameAtEveryDepth() throws {
        let cm = try makeContactManager()
        let visible = try insert(cm, tier: .pairingCapable)
        let hidden = try insert(cm, tier: .pairingCapable, hidden: true)
        let before = visible.pairingCapabilities

        #expect(hidden.pairingCapabilities == before)
        // Another contact's row, hidden or not, changes nothing of a contact's own.
        try insert(cm, state: .paired(routingKey: Data(repeating: 9, count: 32), keys: pairKeys()), hidden: true)
        #expect(visible.pairingCapabilities == before)
    }

    @Test("Reading it writes nothing", .ambientTestKeyManager)
    func readingWritesNothing() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm)
        try cm.modelContext.save()
        let column = contact.currentKey?.pairingEncrypted
        let tier = contact.maxBundleVersion

        for _ in 0..<5 { _ = contact.pairingCapabilities }

        #expect(!cm.modelContext.hasChanges)
        #expect(contact.currentKey?.pairingEncrypted == column && contact.maxBundleVersion == tier)
    }

    @Test("It clears itself when a pairing with pair keys is saved", .ambientTestKeyManager)
    func clearsAfterARePair() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm, tier: .pairingCapable)
        #expect(contact.pairingCapabilities.upgradeAvailable)

        let draft = try #require(Contact.Draft.Key(
            material: Data(repeating: 4, count: 65), owner: Data(repeating: 1, count: 65), date: "2",
            routingKey: Data(repeating: 1, count: 32), pairKeys: pairKeys()
        ))
        try cm.update(key: draft, for: contact.identifier)

        #expect(!contact.pairingCapabilities.upgradeAvailable)
        #expect(contact.pairingCapabilities.pairKeys)
    }

    @Test("A revoked key offers nothing: there is no current key to upgrade", .ambientTestKeyManager)
    func revokedKeyOffersNothing() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm, tier: .pairingCapable)
        #expect(contact.pairingCapabilities.upgradeAvailable)

        try cm.reset(identity: contact.identifier)

        #expect(contact.pairingCapabilities == .none)
    }
}
