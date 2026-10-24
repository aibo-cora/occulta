//
//  ReceivedAttachmentKeyTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §6 / Bug 184. A received attachment is sealed under the sender's file key, else the
//  compose staging key, else refused. It is never written as plaintext, and the writer and the
//  message sheet's reader resolve the same key.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

private struct FixedStagingKey: ComposeStagingKeyProviding {
    let key = SymmetricKey(size: .bits256)
    func deriveComposeStagingKey() throws -> SymmetricKey { self.key }
}

private struct NoStagingKey: ComposeStagingKeyProviding {
    func deriveComposeStagingKey() throws -> SymmetricKey { throw ImportError.stagingKeyUnavailable }
}

private func scratchDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("received-key-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func bytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

/// A file with a recognisable marker that spans several 256 KB chunks.
private func makeFile(extension ext: String = "mp4") -> (file: OccultaFormats.File, plaintext: Data, marker: Data) {
    let marker = Data("RECEIVED-MARKER-\(UUID().uuidString)".utf8)
    var data = Data()
    while data.count < 600_000 { data.append(marker) }
    let file = OccultaFormats.File(content: data, format: .file(.init(name: "clip", extension: ext)), date: Date())
    return (file, data, marker)
}

private func directoryHolds(_ marker: Data, in directory: URL) -> Bool {
    let urls = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
    return urls.contains { (try? Data(contentsOf: $0))?.range(of: marker) != nil }
}

private func enclaveAvailable() -> Bool { TestSupport.secureEnclaveAvailable() }

@Suite("Received-attachment key resolver")
@MainActor struct ReceivedAttachmentKeyTests {

    @Test("a sender we hold no key for resolves to the staging key", .ambientTestKeyManager)
    func unknownSenderUsesStagingKey() throws {
        let staging = FixedStagingKey()
        let cm = try TestSupport.makeContactManager()

        let key = try #require(cm.receivedAttachmentKey(for: "never-met", stagingKeyProvider: staging))

        #expect(bytes(key) == bytes(staging.key))
    }

    @Test("a sender's profile with no public key resolves to the staging key too", .ambientTestKeyManager)
    func keylessProfileUsesStagingKey() throws {
        let staging = FixedStagingKey()
        let cm = try TestSupport.makeContactManager()
        try cm.insertProfile(Contact.Profile(
            identifier: "card-contact", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        ))

        let key = try #require(cm.receivedAttachmentKey(for: "card-contact", stagingKeyProvider: staging))

        #expect(bytes(key) == bytes(staging.key))
    }

    @Test("with neither key there is nothing to seal under", .ambientTestKeyManager)
    func noKeyResolvesToNil() throws {
        let cm = try TestSupport.makeContactManager()

        #expect(cm.receivedAttachmentKey(for: "never-met", stagingKeyProvider: NoStagingKey()) == nil)
    }

    @Test("a sender we hold a key for resolves to their file key, not the staging key", .enabled(if: enclaveAvailable()))
    func knownSenderUsesFileKey() async throws {
        let cm = try TestSupport.makeContactManager()
        let encryptedKey = try #require(try Manager.Crypto().encrypt(data: try Manager.Key().retrieveIdentity()))
        let profile = Contact.Profile(
            identifier: "alice", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: encryptedKey, owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]
        try cm.insertProfile(profile)

        let staging = FixedStagingKey()
        let resolved = try #require(cm.receivedAttachmentKey(for: "alice", stagingKeyProvider: staging))

        #expect(bytes(resolved) == bytes(try cm.fileEncryptionKey(for: "alice")))
        #expect(bytes(resolved) != bytes(staging.key))
    }
}

@Suite("Received files are sealed, never plaintext")
@MainActor struct ReceivedFilesSealedTests {

    @Test("a key-less sender's attachment is sealed on disk and opens through the reader's key", .ambientTestKeyManager)
    func keylessSenderIsSealed() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let staging = FixedStagingKey()
        let cm = try TestSupport.makeContactManager()
        let (file, plaintext, marker) = makeFile()
        let basket = Basket(files: [file], date: Date())

        let owned = try await cm.sealReceivedFiles(
            of: basket, owner: "never-met", stagingKeyProvider: staging, in: dir
        )

        let url = try #require(owned.basket.files.first?.url)
        #expect(AttachmentManager.isSealed(at: url))
        #expect(!directoryHolds(marker, in: dir))

        // The sheet resolves its reader's key through the same call.
        let readerKey = try #require(cm.receivedAttachmentKey(for: owned.owner, stagingKeyProvider: staging))
        #expect(try await AttachmentManager(contactKey: readerKey).data(at: url) == plaintext)
    }

    @Test("with no key nothing is written and the message is refused", .ambientTestKeyManager)
    func noKeyWritesNothing() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let cm = try TestSupport.makeContactManager()
        let (file, _, marker) = makeFile()
        let basket = Basket(files: [file], date: Date())

        await #expect(throws: ImportError.self) {
            _ = try await cm.sealReceivedFiles(
                of: basket, owner: "never-met", stagingKeyProvider: NoStagingKey(), in: dir
            )
        }

        #expect((try FileManager.default.contentsOfDirectory(atPath: dir.path)).isEmpty)
        #expect(!directoryHolds(marker, in: dir))
    }

    @Test("a text-only message needs no key", .ambientTestKeyManager)
    func textNeedsNoKey() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let cm = try TestSupport.makeContactManager()
        let text = OccultaFormats.File(content: Data("hello".utf8), format: .text, date: Date())

        let owned = try await cm.sealReceivedFiles(
            of: Basket(files: [text], date: Date()), owner: "never-met", stagingKeyProvider: NoStagingKey(), in: dir
        )

        #expect(owned.basket.files.count == 1)
        #expect((try FileManager.default.contentsOfDirectory(atPath: dir.path)).isEmpty)
    }

    @Test("a hostile extension cannot steer the write out of the directory", .ambientTestKeyManager)
    func hostileExtensionStaysInDirectory() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let cm = try TestSupport.makeContactManager()
        let (file, _, _) = makeFile(extension: "../../escape")

        let owned = try await cm.sealReceivedFiles(
            of: Basket(files: [file], date: Date()), owner: "never-met", stagingKeyProvider: FixedStagingKey(), in: dir
        )

        let url = try #require(owned.basket.files.first?.url)
        #expect(url.deletingLastPathComponent().standardizedFileURL == dir.standardizedFileURL)
    }
}
