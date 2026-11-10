//
//  AttachmentKeyResealTests.swift
//  OccultaTests
//
//  Bug 196: the base key a contact's attachments are sealed under at rest was the same value as a classical long-term slot's
//  key. It is now the same ECDH under a label of its own, and `ContactManager.resealAttachmentKeys` moves the draft files this
//  phone keeps from the old key to the new one, draft by draft: a draft's row names its recipient, and the files in its folder
//  move to that contact's current key. These tests run the pass on temporary directories with a software key manager; nothing
//  here needs an Enclave.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self, Message.Draft.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return ContactManager(modelContainer: container, security: security)
}

/// `publicKeys` as one contact's key rows on this device, oldest first, the last one current.
@MainActor
@discardableResult
private func insertContact(publicKeys: [Data], hidden: Bool = false, in cm: ContactManager) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    var rows: [Contact.Profile.Key] = []
    for (index, key) in publicKeys.enumerated() {
        let row = Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: key), owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )
        if index < publicKeys.count - 1 { row.expiredOn = try Manager.Crypto().encrypt(data: Data("1".utf8)) }
        rows.append(row)
    }
    profile.contactPublicKeys = rows
    if hidden { profile.visibleThroughDepth = try DepthCodec.encode(0).encrypt() }
    try cm.insertProfile(profile)
    return profile
}

/// A draft addressed to `recipient`, with the recipient sealed as `DraftStore` seals it, and its attachment folder under `root`.
@MainActor
@discardableResult
private func insertDraft(to recipient: String, root: URL, in cm: ContactManager) throws -> URL {
    let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
    let id = UUID()
    let sealed = try AES.GCM.seal(
        Data(recipient.utf8), using: key, authenticating: Message.Draft.aad(id: id, field: .recipientID)
    ).combined!
    cm.modelContext.insert(Message.Draft(id: id, encryptedRecipientID: sealed, encryptedContent: Data()))
    try cm.modelContext.save()
    let folder = root.appendingPathComponent(id.uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    return folder
}

private func scratchDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("attachment-reseal-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private let plaintext = Data((0..<200_000).map { UInt8($0 & 0xFF) })

// MARK: - Suite

@MainActor
@Suite("Bug 196 — the attachment base key and the pass that moves files to it", .serialized)
struct AttachmentKeyResealTests {

    private let me = TestKeyManager()
    private let peer = TestKeyManager()

    private func oldKey(for peer: TestKeyManager) throws -> SymmetricKey {
        try #require(self.me.createSharedSecret(using: try peer.retrieveIdentity()))
    }
    private func newKey(for peer: TestKeyManager) throws -> SymmetricKey {
        try #require(self.me.createAttachmentBaseKey(using: try peer.retrieveIdentity()))
    }

    // MARK: The key

    @Test("The new base key is not the transport key, and both ends derive it")
    func keyIsSeparateAndShared() throws {
        let a = TestKeyManager(), b = TestKeyManager()
        let fromA = try #require(a.createAttachmentBaseKey(using: try b.retrieveIdentity()))
        let fromB = try #require(b.createAttachmentBaseKey(using: try a.retrieveIdentity()))
        let transport = try #require(a.createSharedSecret(using: try b.retrieveIdentity()))
        func bytes(_ k: SymmetricKey) -> Data { k.withUnsafeBytes { Data($0) } }

        #expect(bytes(fromA) == bytes(fromB))
        #expect(bytes(fromA) != bytes(transport), "one key is no longer both a slot's AEAD key and the attachments' HKDF input")
        #expect(a.createAttachmentBaseKey(using: nil) == nil)
    }

    // MARK: The pass

    /// A draft addressed to `contact`, and a file sealed under the old key in that draft's folder.
    @discardableResult
    private func draftWithOldFile(
        for contact: Contact.Profile, sealedAs sealer: TestKeyManager? = nil, root: URL, in cm: ContactManager, name: String = "a.bin"
    ) throws -> URL {
        let folder = try insertDraft(to: contact.identifier, root: root, in: cm)
        let file = folder.appendingPathComponent(name)
        try AttachmentManager(contactKey: try self.oldKey(for: sealer ?? self.peer)).encrypt(plaintext, to: file)
        return file
    }

    @Test("A file sealed under the old key opens under the new one afterwards, with the same content", .ambientTestKeyManager)
    func movesAFile() async throws {
        let cm = try makeContactManager()
        let contact = try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = try self.draftWithOldFile(for: contact, root: root, in: cm)

        let result = await cm.resealAttachmentKeys(in: root, using: self.me)

        #expect(result == .init(resealed: 1, failed: 0))
        let new = AttachmentManager(contactKey: try self.newKey(for: self.peer))
        #expect(new.opens(at: file))
        #expect(!AttachmentManager(contactKey: try self.oldKey(for: self.peer)).opens(at: file))
        #expect(try new.plaintextBlocking(at: file) == plaintext)
    }

    @Test("A second run finds nothing to move and leaves every byte as it was", .ambientTestKeyManager)
    func isIdempotent() async throws {
        let cm = try makeContactManager()
        let contact = try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = try self.draftWithOldFile(for: contact, root: root, in: cm)

        await cm.resealAttachmentKeys(in: root, using: self.me)
        let after = try Data(contentsOf: file)
        let second = await cm.resealAttachmentKeys(in: root, using: self.me)

        #expect(second == .init(resealed: 0, failed: 0))
        #expect(try Data(contentsOf: file) == after)
    }

    @Test("A temporary a killed run left is removed, and the file beside it still moves", .ambientTestKeyManager)
    func killedRunLeavesNothing() async throws {
        let cm = try makeContactManager()
        let contact = try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = try self.draftWithOldFile(for: contact, root: root, in: cm)
        let leftover = AttachmentManager.resealingURL(for: file)
        try Data("half written".utf8).write(to: leftover)

        let result = await cm.resealAttachmentKeys(in: root, using: self.me)

        #expect(result.resealed == 1)
        #expect(!FileManager.default.fileExists(atPath: leftover.path))
        #expect(AttachmentManager(contactKey: try self.newKey(for: self.peer)).opens(at: file))
    }

    @Test("A file that will not move stays exactly as it was, with no temporary left, and does not hold back the files after it", .ambientTestKeyManager)
    func failureLeavesTheOriginalAndTheRunGoesOn() async throws {
        let cm = try makeContactManager()
        let contact = try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let poison = try self.draftWithOldFile(for: contact, root: root, in: cm, name: "a-poison.bin")
        let good = poison.deletingLastPathComponent().appendingPathComponent("b-good.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: good)

        // The header still authenticates, so the file is found; a byte in a chunk is wrong, so it cannot be read through.
        var bytes = try Data(contentsOf: poison)
        bytes[bytes.count - 40] ^= 0xFF
        try bytes.write(to: poison)

        let result = await cm.resealAttachmentKeys(in: root, using: self.me)

        #expect(result == .init(resealed: 1, failed: 1))
        #expect(try Data(contentsOf: poison) == bytes)
        #expect(!FileManager.default.fileExists(atPath: AttachmentManager.resealingURL(for: poison).path))
        #expect(AttachmentManager(contactKey: try self.newKey(for: self.peer)).opens(at: good), "the file after the poison one moved")
    }

    @Test("Two rows that hold one identity key are tried once, and a file for either still moves", .ambientTestKeyManager)
    func duplicateKeysAreDeduplicated() async throws {
        let cm = try makeContactManager()
        let key = try self.peer.retrieveIdentity()
        let contact = try insertContact(publicKeys: [key, key], in: cm)
        #expect(cm.attachmentKeyPairs(for: contact, using: self.me).count == 1)

        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        try self.draftWithOldFile(for: contact, root: root, in: cm)
        #expect(await cm.resealAttachmentKeys(in: root, using: self.me) == .init(resealed: 1, failed: 0))
    }

    @Test("A plaintext file, a file under another key and a file under the new key are left alone", .ambientTestKeyManager)
    func leavesOthersAlone() async throws {
        let cm = try makeContactManager()
        let contact = try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let folder = try insertDraft(to: contact.identifier, root: root, in: cm)

        let plain = folder.appendingPathComponent("plain.txt")
        try Data("not sealed".utf8).write(to: plain)
        let other = folder.appendingPathComponent("other.bin")
        try AttachmentManager(contactKey: SymmetricKey(size: .bits256)).encrypt(plaintext, to: other)
        let alreadyNew = folder.appendingPathComponent("new.bin")
        try AttachmentManager(contactKey: try self.newKey(for: self.peer)).encrypt(plaintext, to: alreadyNew)
        let before = [try Data(contentsOf: plain), try Data(contentsOf: other), try Data(contentsOf: alreadyNew)]

        let result = await cm.resealAttachmentKeys(in: root, using: self.me)

        #expect(result == .init(resealed: 0, failed: 0))
        #expect([try Data(contentsOf: plain), try Data(contentsOf: other), try Data(contentsOf: alreadyNew)] == before)
    }

    @Test("A draft for a contact with no key, for no contact, or whose recipient will not open is skipped", .ambientTestKeyManager)
    func unresolvableDraftsAreSkipped() async throws {
        let cm = try makeContactManager()
        let keyless = try insertContact(publicKeys: [], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let forKeyless = try self.draftWithOldFile(for: keyless, root: root, in: cm)
        let forGroup = try insertDraft(to: UUID().uuidString, root: root, in: cm).appendingPathComponent("g.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: forGroup)
        // A row whose recipient was sealed for another draft's id fails authentication.
        let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
        let id = UUID()
        let wrongAAD = try AES.GCM.seal(
            Data(keyless.identifier.utf8), using: key, authenticating: Message.Draft.aad(id: UUID(), field: .recipientID)
        ).combined!
        cm.modelContext.insert(Message.Draft(id: id, encryptedRecipientID: wrongAAD, encryptedContent: Data()))
        try cm.modelContext.save()
        let folder = root.appendingPathComponent(id.uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let unreadable = folder.appendingPathComponent("u.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: unreadable)
        let before = [try Data(contentsOf: forKeyless), try Data(contentsOf: forGroup), try Data(contentsOf: unreadable)]

        #expect(await cm.resealAttachmentKeys(in: root, using: self.me) == .init(resealed: 0, failed: 0))
        #expect([try Data(contentsOf: forKeyless), try Data(contentsOf: forGroup), try Data(contentsOf: unreadable)] == before)
    }

    @Test("A folder with no draft row is left alone", .ambientTestKeyManager)
    func orphanFolderIsLeftAlone() async throws {
        let cm = try makeContactManager()
        try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let folder = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let file = folder.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: file)
        let before = try Data(contentsOf: file)

        #expect(await cm.resealAttachmentKeys(in: root, using: self.me) == .init(resealed: 0, failed: 0))
        #expect(try Data(contentsOf: file) == before)
    }

    @Test("A contact hidden at the current depth has its drafts' files moved exactly as a visible one does", .ambientTestKeyManager)
    func hiddenContactsFilesMove() async throws {
        let cm = try makeContactManager()
        let visible = TestKeyManager(), hidden = TestKeyManager()
        let visibleContact = try insertContact(publicKeys: [try visible.retrieveIdentity()], in: cm)
        let hiddenContact = try insertContact(publicKeys: [try hidden.retrieveIdentity()], hidden: true, in: cm)
        // The session is one level deeper than the contact is visible through, so it really is hidden here.
        cm.security.applyVerifyState(for: .normal(depth: 1))
        #expect(!hiddenContact.isVisible(atDepth: cm.security.currentDepth))
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let one = try self.draftWithOldFile(for: visibleContact, sealedAs: visible, root: root, in: cm, name: "one.bin")
        let two = try self.draftWithOldFile(for: hiddenContact, sealedAs: hidden, root: root, in: cm, name: "two.bin")

        let result = await cm.resealAttachmentKeys(in: root, using: self.me)

        #expect(result == .init(resealed: 2, failed: 0))
        #expect(AttachmentManager(contactKey: try self.newKey(for: visible)).opens(at: one))
        #expect(AttachmentManager(contactKey: try self.newKey(for: hidden)).opens(at: two))
    }

    @Test("A file sealed under an earlier key row's old key moves to the current row's new key, so it opens again", .ambientTestKeyManager)
    func earlierRowsFilesFollowTheCurrentKey() async throws {
        let cm = try makeContactManager()
        let first = TestKeyManager(), current = TestKeyManager()
        let contact = try insertContact(publicKeys: [try first.retrieveIdentity(), try current.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = try self.draftWithOldFile(for: contact, sealedAs: first, root: root, in: cm)

        await cm.resealAttachmentKeys(in: root, using: self.me)

        let reader = AttachmentManager(contactKey: try self.newKey(for: current))
        #expect(reader.opens(at: file))
        #expect(try reader.plaintextBlocking(at: file) == plaintext)
    }

    @Test("Two records that held one identity key, one of them re-keyed since, each get their own current key", .ambientTestKeyManager)
    func twinRecordsEachGetTheirOwnKey() async throws {
        let cm = try makeContactManager()
        let shared = TestKeyManager(), rotatedTo = TestKeyManager()
        // One record still holds `shared`; the other held it too and has since moved to `rotatedTo`.
        let stays = try insertContact(publicKeys: [try shared.retrieveIdentity()], in: cm)
        let moved = try insertContact(publicKeys: [try shared.retrieveIdentity(), try rotatedTo.retrieveIdentity()], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let forStays = try self.draftWithOldFile(for: stays, sealedAs: shared, root: root, in: cm)
        let forMoved = try self.draftWithOldFile(for: moved, sealedAs: shared, root: root, in: cm)

        let result = await cm.resealAttachmentKeys(in: root, using: self.me)

        #expect(result == .init(resealed: 2, failed: 0))
        #expect(AttachmentManager(contactKey: try self.newKey(for: shared)).opens(at: forStays), "the draft to the unchanged record")
        #expect(AttachmentManager(contactKey: try self.newKey(for: rotatedTo)).opens(at: forMoved), "the draft to the re-keyed record")
    }

    @Test("A re-pair, which changes the pair keys and not the identity key, leaves the key and the files alone", .ambientTestKeyManager)
    func rePairDoesNotMoveFiles() async throws {
        let cm = try makeContactManager()
        let peerKey = try self.peer.retrieveIdentity()
        let contact = try insertContact(publicKeys: [peerKey], in: cm)
        let root = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let folder = try insertDraft(to: contact.identifier, root: root, in: cm)
        let file = folder.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.newKey(for: self.peer)).encrypt(plaintext, to: file)
        let before = try Data(contentsOf: file)

        let draft = try #require(Contact.Draft.Key(material: peerKey, owner: Data(repeating: 1, count: 65), date: "2", pairing: .paired(routingKey: Data(repeating: 7, count: 32), keys: samplePairKeys())))
        try cm.update(key: draft, for: contact.identifier)

        let result = await cm.resealAttachmentKeys(in: root, using: self.me)
        #expect(result == .init(resealed: 0, failed: 0))
        #expect(try Data(contentsOf: file) == before)
        #expect(AttachmentManager(contactKey: try self.newKey(for: self.peer)).opens(at: file), "the new key is a function of the identity keys only")
    }
}
