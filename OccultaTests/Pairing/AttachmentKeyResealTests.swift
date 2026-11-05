//
//  AttachmentKeyResealTests.swift
//  OccultaTests
//
//  Bug 196: the base key a contact's attachments are sealed under at rest was the same value as a classical long-term slot's
//  key. It is now the same ECDH under a label of its own, and `ContactManager.resealAttachmentKeys` moves the files this
//  phone keeps (drafts, and received attachments not yet opened) from the old key to the new one. These tests run the pass
//  on temporary directories with a software key manager; nothing here needs an Enclave.
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
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
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

    @Test("The new base key is not the transport key, both ends derive it, and it is not a function of anything a re-pair changes")
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

    @Test("A file sealed under the old key opens under the new one afterwards, with the same content", .ambientTestKeyManager)
    func movesAFile() async throws {
        let cm = try makeContactManager()
        try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: file)

        let result = await cm.resealAttachmentKeys(in: [directory], using: self.me)

        #expect(result == .init(resealed: 1, failed: 0))
        let new = AttachmentManager(contactKey: try self.newKey(for: self.peer))
        #expect(new.opens(at: file))
        #expect(!AttachmentManager(contactKey: try self.oldKey(for: self.peer)).opens(at: file))
        #expect(try new.plaintextBlocking(at: file) == plaintext)
    }

    @Test("A second run finds nothing to move and leaves every byte as it was", .ambientTestKeyManager)
    func isIdempotent() async throws {
        let cm = try makeContactManager()
        try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: file)

        await cm.resealAttachmentKeys(in: [directory], using: self.me)
        let after = try Data(contentsOf: file)
        let second = await cm.resealAttachmentKeys(in: [directory], using: self.me)

        #expect(second == .init(resealed: 0, failed: 0))
        #expect(try Data(contentsOf: file) == after)
    }

    @Test("A temporary a killed run left is removed, and the file beside it still moves", .ambientTestKeyManager)
    func killedRunLeavesNothing() async throws {
        let cm = try makeContactManager()
        try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: file)
        let leftover = AttachmentManager.resealingURL(for: file)
        try Data("half written".utf8).write(to: leftover)

        let result = await cm.resealAttachmentKeys(in: [directory], using: self.me)

        #expect(result.resealed == 1)
        #expect(!FileManager.default.fileExists(atPath: leftover.path))
        #expect(AttachmentManager(contactKey: try self.newKey(for: self.peer)).opens(at: file))
    }

    @Test("A file that will not move stops the run and stays exactly as it was, with no temporary left", .ambientTestKeyManager)
    func failureLeavesTheOriginal() async throws {
        let cm = try makeContactManager()
        try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: file)

        // The header still authenticates, so the file is found; a byte in a chunk is wrong, so it cannot be read through.
        var bytes = try Data(contentsOf: file)
        bytes[bytes.count - 40] ^= 0xFF
        try bytes.write(to: file)

        let result = await cm.resealAttachmentKeys(in: [directory], using: self.me)

        #expect(result == .init(resealed: 0, failed: 1))
        #expect(try Data(contentsOf: file) == bytes)
        #expect(!FileManager.default.fileExists(atPath: AttachmentManager.resealingURL(for: file).path))
    }

    @Test("A plaintext file, a file under another key and a file under the new key are left alone", .ambientTestKeyManager)
    func leavesOthersAlone() async throws {
        let cm = try makeContactManager()
        try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let plain = directory.appendingPathComponent("plain.txt")
        try Data("not sealed".utf8).write(to: plain)
        let other = directory.appendingPathComponent("other.bin")
        try AttachmentManager(contactKey: SymmetricKey(size: .bits256)).encrypt(plaintext, to: other)
        let alreadyNew = directory.appendingPathComponent("new.bin")
        try AttachmentManager(contactKey: try self.newKey(for: self.peer)).encrypt(plaintext, to: alreadyNew)
        let before = [try Data(contentsOf: plain), try Data(contentsOf: other), try Data(contentsOf: alreadyNew)]

        let result = await cm.resealAttachmentKeys(in: [directory], using: self.me)

        #expect(result == .init(resealed: 0, failed: 0))
        #expect([try Data(contentsOf: plain), try Data(contentsOf: other), try Data(contentsOf: alreadyNew)] == before)
    }

    @Test("A contact with no key is skipped, and with no contacts there is nothing to do", .ambientTestKeyManager)
    func noKeyNoWork() async throws {
        let cm = try makeContactManager()
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: self.peer)).encrypt(plaintext, to: file)
        let before = try Data(contentsOf: file)

        #expect(await cm.resealAttachmentKeys(in: [directory], using: self.me) == .init(resealed: 0, failed: 0))
        try insertContact(publicKeys: [], in: cm)
        #expect(await cm.resealAttachmentKeys(in: [directory], using: self.me) == .init(resealed: 0, failed: 0))
        #expect(try Data(contentsOf: file) == before)
    }

    @Test("A contact hidden at the current depth has its files moved exactly as a visible one does", .ambientTestKeyManager)
    func hiddenContactsFilesMove() async throws {
        let cm = try makeContactManager()
        let visible = TestKeyManager(), hidden = TestKeyManager()
        try insertContact(publicKeys: [try visible.retrieveIdentity()], in: cm)
        try insertContact(publicKeys: [try hidden.retrieveIdentity()], hidden: true, in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let one = directory.appendingPathComponent("one.bin"), two = directory.appendingPathComponent("two.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: visible)).encrypt(plaintext, to: one)
        try AttachmentManager(contactKey: try self.oldKey(for: hidden)).encrypt(plaintext, to: two)

        let result = await cm.resealAttachmentKeys(in: [directory], using: self.me)

        #expect(result == .init(resealed: 2, failed: 0))
        #expect(AttachmentManager(contactKey: try self.newKey(for: visible)).opens(at: one))
        #expect(AttachmentManager(contactKey: try self.newKey(for: hidden)).opens(at: two))
    }

    @Test("A file sealed under an earlier key row's old key moves to the current row's new key, so it opens again", .ambientTestKeyManager)
    func earlierRowsFilesFollowTheCurrentKey() async throws {
        let cm = try makeContactManager()
        let first = TestKeyManager(), current = TestKeyManager()
        try insertContact(publicKeys: [try first.retrieveIdentity(), try current.retrieveIdentity()], in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.oldKey(for: first)).encrypt(plaintext, to: file)

        await cm.resealAttachmentKeys(in: [directory], using: self.me)

        let reader = AttachmentManager(contactKey: try self.newKey(for: current))
        #expect(reader.opens(at: file))
        #expect(try reader.plaintextBlocking(at: file) == plaintext)
    }

    @Test("It reaches files in nested folders and in every directory it is given", .ambientTestKeyManager)
    func walksDirectories() async throws {
        let cm = try makeContactManager()
        try insertContact(publicKeys: [try self.peer.retrieveIdentity()], in: cm)
        let drafts = try scratchDirectory(), temporary = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: drafts); try? FileManager.default.removeItem(at: temporary) }
        let draftFolder = drafts.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: draftFolder, withIntermediateDirectories: true)
        let inDraft = draftFolder.appendingPathComponent("a.mp4"), inTemporary = temporary.appendingPathComponent("b.bin")
        let old = AttachmentManager(contactKey: try self.oldKey(for: self.peer))
        try old.encrypt(plaintext, to: inDraft)
        try old.encrypt(plaintext, to: inTemporary)

        let result = await cm.resealAttachmentKeys(in: [drafts, temporary], using: self.me)

        #expect(result.resealed == 2)
    }

    @Test("A re-pair, which changes the pair keys and not the identity key, leaves the key and the files alone", .ambientTestKeyManager)
    func rePairDoesNotMoveFiles() async throws {
        let cm = try makeContactManager()
        let peerKey = try self.peer.retrieveIdentity()
        let contact = try insertContact(publicKeys: [peerKey], in: cm)
        let directory = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("a.bin")
        try AttachmentManager(contactKey: try self.newKey(for: self.peer)).encrypt(plaintext, to: file)
        let before = try Data(contentsOf: file)

        let draft = try #require(Contact.Draft.Key(material: peerKey, owner: Data(repeating: 1, count: 65), date: "2", routingKey: Data(repeating: 7, count: 32)))
        try cm.update(key: draft, for: contact.identifier)

        let result = await cm.resealAttachmentKeys(in: [directory], using: self.me)
        #expect(result == .init(resealed: 0, failed: 0))
        #expect(try Data(contentsOf: file) == before)
        #expect(AttachmentManager(contactKey: try self.newKey(for: self.peer)).opens(at: file), "the new key is a function of the identity keys only")
    }
}
