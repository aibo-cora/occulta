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
import CryptoKit
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
        let contact = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys()))

        let caps = contact.pairingCapabilities
        #expect(caps.pairKeys && !caps.upgradeAvailable)
        #expect(!caps.postQuantumSignatures, "neither phone made an ML-DSA key")
    }

    @Test("A pairing without pair keys offers an upgrade when the contact's build could give one", .ambientTestKeyManager)
    func plainWithACapablePeerOffersAnUpgrade() throws {
        let cm = try makeContactManager()
        let capable = try insert(cm, tier: .pairingCapable)
        #expect(capable.pairingCapabilities.upgradeAvailable)
        #expect(capable.pairingCapabilities.peerCanPair && !capable.pairingCapabilities.pairKeys)
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
        let hybrid = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys(mldsa: true, peerMLDSA: true)), quantum: true)
        let classical = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys(mldsa: true)), quantum: false)

        #expect(hybrid.pairingCapabilities.postQuantumAgreement && hybrid.pairingCapabilities.postQuantumSignatures)
        #expect(!classical.pairingCapabilities.postQuantumAgreement && !classical.pairingCapabilities.postQuantumSignatures, "one side's key is not enough")
    }

    @Test("The ML-DSA row never drives the upgrade", .ambientTestKeyManager)
    func mldsaNeverDrivesTheIcon() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys()))
        #expect(!contact.pairingCapabilities.postQuantumSignatures)
        #expect(!contact.pairingCapabilities.upgradeAvailable)
    }

    @Test("A contact hidden at the current depth reads exactly as a visible one with the same row", .ambientTestKeyManager)
    func sameAtEveryDepth() throws {
        let cm = try makeContactManager()
        let visible = try insert(cm, tier: .pairingCapable)
        let hidden = try insert(cm, tier: .pairingCapable, hidden: true)
        // One level deeper than the hidden contact is visible through: it really is hidden here, and the other is not.
        cm.security.applyVerifyState(for: .normal(depth: 1))
        #expect(!hidden.isVisible(atDepth: cm.security.currentDepth))
        let before = visible.pairingCapabilities

        #expect(hidden.pairingCapabilities == before)
        // Another contact's row, hidden or not, changes nothing of a contact's own.
        try insert(cm, state: .paired(routingKey: Data(repeating: 9, count: 32), keys: samplePairKeys()), hidden: true)
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
            pairing: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys())
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

// MARK: - What a re-exchange would add (hardening step 7a)

/// The detail screen's prompt: shown when the pairing lacks pair keys (and with them the routing key) or quantum-resistant key
/// agreement, and a re-exchange in person could give it. It reads this pairing, this phone's OS and nothing else, so a contact
/// reads the same at every depth.
@MainActor
@Suite("Hardening step 7a — the re-exchange prompt", .serialized)
struct PairingUpgradePromptTests {

    private func caps(pairKeys: Bool, quantum: Bool, peerCanPair: Bool) -> PairingCapabilities {
        PairingCapabilities(pairKeys: pairKeys, postQuantumAgreement: quantum, postQuantumSignatures: false, peerCanPair: peerCanPair)
    }

    @Test("Every state of a pairing with a current key, on a phone that can make ML-KEM")
    func everyStateOnAPostQuantumPhone() {
        // pair keys, ML-KEM, peer's recorded build can pair: what a re-exchange adds
        #expect(self.caps(pairKeys: false, quantum: false, peerCanPair: true).upgrade(thisPhoneCanPostQuantum: true) == .both)
        #expect(self.caps(pairKeys: false, quantum: true,  peerCanPair: true).upgrade(thisPhoneCanPostQuantum: true) == .pairKeys)
        #expect(self.caps(pairKeys: true,  quantum: false, peerCanPair: true).upgrade(thisPhoneCanPostQuantum: true) == .postQuantum)
        #expect(self.caps(pairKeys: true,  quantum: true,  peerCanPair: true).upgrade(thisPhoneCanPostQuantum: true) == nil)

        // A pairing with pair keys has a peer that can pair, whatever tier is recorded.
        #expect(self.caps(pairKeys: true,  quantum: false, peerCanPair: false).upgrade(thisPhoneCanPostQuantum: true) == .postQuantum)
        #expect(self.caps(pairKeys: true,  quantum: true,  peerCanPair: false).upgrade(thisPhoneCanPostQuantum: true) == nil)

        // No pair keys and a peer that could not make them: a re-exchange could not help, ML-KEM included.
        #expect(self.caps(pairKeys: false, quantum: false, peerCanPair: false).upgrade(thisPhoneCanPostQuantum: true) == nil)
        #expect(self.caps(pairKeys: false, quantum: true,  peerCanPair: false).upgrade(thisPhoneCanPostQuantum: true) == nil)
    }

    @Test("A phone that cannot make ML-KEM is never told to exchange for it")
    func everyStateOnAnOlderPhone() {
        #expect(self.caps(pairKeys: false, quantum: false, peerCanPair: true).upgrade(thisPhoneCanPostQuantum: false) == .pairKeys)
        #expect(self.caps(pairKeys: false, quantum: true,  peerCanPair: true).upgrade(thisPhoneCanPostQuantum: false) == .pairKeys)
        #expect(self.caps(pairKeys: true,  quantum: false, peerCanPair: true).upgrade(thisPhoneCanPostQuantum: false) == nil)
        #expect(self.caps(pairKeys: true,  quantum: true,  peerCanPair: true).upgrade(thisPhoneCanPostQuantum: false) == nil)
        #expect(self.caps(pairKeys: false, quantum: false, peerCanPair: false).upgrade(thisPhoneCanPostQuantum: false) == nil)
    }

    @Test("The list glyph's rule is the pair-keys half of the prompt")
    func glyphAgreesWithThePrompt() {
        for pairKeys in [false, true] {
            for quantum in [false, true] {
                for peer in [false, true] {
                    for phone in [false, true] {
                        let caps = self.caps(pairKeys: pairKeys, quantum: quantum, peerCanPair: peer)
                        let upgrade = caps.upgrade(thisPhoneCanPostQuantum: phone)
                        #expect(caps.upgradeAvailable == (upgrade == .pairKeys || upgrade == .both), "\(pairKeys) \(quantum) \(peer) \(phone)")
                    }
                }
            }
        }
    }

    @Test("No current key, a card contact that has not met, and a revoked pairing offer nothing")
    func noKeyOffersNothing() {
        #expect(PairingCapabilities.none.upgrade(thisPhoneCanPostQuantum: true) == nil)
        #expect(PairingCapabilities.none.upgrade(thisPhoneCanPostQuantum: false) == nil)
    }

    @Test("The copy is plain: it says the fix is in person, and names no authority, adversary or danger")
    func copyIsPlain() {
        let prompts = [PairingCapabilities.Upgrade.pairKeys, .postQuantum, .both].map(\.prompt)

        #expect(Set(prompts).count == 3)
        // The words OnboardingTests bans, and the ones that would make the line a warning.
        let forbidden = [
            "police", "government", "authority", "authorities", "law enforcement", "subpoena", "border", "seize", "seizure",
            "forensic", "adversary", "coerc", "surveil", "attack", "hack", "vulnerab", "insecure", "unsafe", "danger", "risk",
            "warning", "weak", "exposed", "compromis", "leak", "unbreakable", "military", "guarantee", "fully protected",
        ]
        for prompt in prompts {
            #expect(prompt.localizedCaseInsensitiveContains("in person"), "\(prompt)")
            for word in forbidden {
                #expect(!prompt.localizedCaseInsensitiveContains(word), "\"\(word)\" in: \(prompt)")
            }
        }
        #expect(PairingCapabilities.Upgrade.postQuantum.prompt.contains("iOS 26"))
    }

    @Test("From a stored contact: each state reads what its row holds", .ambientTestKeyManager)
    func fromTheRow() throws {
        let cm = try makeContactManager()
        let keys = samplePairKeys()
        let paired = PairingState.paired(routingKey: Data(repeating: 1, count: 32), keys: keys)

        #expect(try insert(cm).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == .both)
        #expect(try insert(cm, quantum: true).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == .pairKeys)
        #expect(try insert(cm, state: paired).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == .postQuantum)
        #expect(try insert(cm, state: paired, quantum: true).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == nil)
        // A pairing with pair keys from a contact never heard from since: the keys say the peer could pair.
        #expect(try insert(cm, state: paired, tier: nil).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == .postQuantum)
        // Without them, a contact on an older build, or never heard from, offers nothing.
        #expect(try insert(cm, tier: .v3fs).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == nil)
        #expect(try insert(cm, tier: nil).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == nil)
        // No key at all.
        #expect(try insert(cm, keys: 0).pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == nil)
    }

    @Test("A revoked pairing offers nothing, and a new one clears it", .ambientTestKeyManager)
    func revokedAndRePaired() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm)
        #expect(contact.pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == .both)

        try cm.reset(identity: contact.identifier)
        #expect(contact.pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == nil)
    }

    @Test("A contact hidden at the current depth reads exactly as a visible one with the same row", .ambientTestKeyManager)
    func sameAtEveryDepth() throws {
        let cm = try makeContactManager()
        let visible = try insert(cm)
        let hidden = try insert(cm, hidden: true)
        cm.security.applyVerifyState(for: .normal(depth: 1))
        #expect(!hidden.isVisible(atDepth: cm.security.currentDepth))

        for phone in [false, true] {
            #expect(hidden.pairingCapabilities.upgrade(thisPhoneCanPostQuantum: phone) == visible.pairingCapabilities.upgrade(thisPhoneCanPostQuantum: phone))
        }
        // Another contact's row, hidden or not, changes nothing of a contact's own.
        let before = visible.pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true)
        try insert(cm, state: .paired(routingKey: Data(repeating: 9, count: 32), keys: samplePairKeys()), quantum: true, hidden: true)
        #expect(visible.pairingCapabilities.upgrade(thisPhoneCanPostQuantum: true) == before)
    }

    @Test("Reading the prompt writes nothing", .ambientTestKeyManager)
    func readingWritesNothing() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm)
        try cm.modelContext.save()
        let column = contact.currentKey?.pairingEncrypted

        for _ in 0..<5 { _ = contact.pairingCapabilities.upgrade() }

        #expect(!cm.modelContext.hasChanges)
        #expect(contact.currentKey?.pairingEncrypted == column)
    }
}

// MARK: - Under one key

/// The detail screen opens the pairing and the scheme label under the pass's key (`Docs/Bugs/v2.1.0/`). They have to
/// read exactly what the per-call forms read, or the glyph and the rows would disagree with the list.
@MainActor
@Suite("Bug 196 — capabilities and scheme label under one key", .serialized)
struct PairingCapabilitiesUnderKeyTests {

    private func key() throws -> SymmetricKey {
        try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
    }

    @Test("The capabilities read the same under a derived key", .ambientTestKeyManager)
    func capabilitiesMatch() throws {
        let cm = try makeContactManager()
        let key = try self.key()
        let contacts: [(String, Contact.Profile)] = [
            ("paired",            try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys()))),
            ("upgradeable",       try insert(cm)),
            ("quantum",           try insert(cm, quantum: true)),
            ("older build",       try insert(cm, tier: nil)),
            ("no key at all",     try insert(cm, keys: 0)),
        ]

        for (name, contact) in contacts {
            #expect(contact.pairingCapabilities(using: key) == contact.pairingCapabilities, "\(name)")
        }
        #expect(try insert(cm).pairingCapabilities(using: key).upgradeAvailable)
    }

    @Test("The scheme label reads the same under a derived key, and says classical without one", .ambientTestKeyManager)
    func schemeLabelMatches() throws {
        let cm = try makeContactManager()
        let key = try self.key()
        let plain   = try insert(cm)
        let blob    = try insert(cm, quantum: true)

        #expect(plain.encryptionSchemeLabel(using: key) == plain.encryptionSchemeLabel)
        #expect(blob.encryptionSchemeLabel(using: key) == blob.encryptionSchemeLabel)
        #expect(blob.encryptionSchemeLabel(using: nil) == "Classical (v1) · exchange again to restore full protection")
        #expect(plain.encryptionSchemeLabel(using: nil) == plain.encryptionSchemeLabel)
    }
}
