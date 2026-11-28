//
//  ShareIntakeTests.swift
//  OccultaTests
//
//  Register D5: `ShareViewController` can't be driven from the test host, so what it does with a file was untested. The
//  size limits, the choice of type, sealing a file into the session directory and writing the manifest are in
//  `ShareIntake`, which both the extension and the app compile, and which these tests call as the extension does. The
//  last test carries a session from `ShareIntake` through `ShareSession.staged`, the app's side of the same handoff.
//
//  Not covered, because it needs the system's `NSItemProvider` and extension context: asking a provider for its file,
//  opening the app by URL, and the inbound `.occ` handoff (Bug 188).
//

import Testing
import CryptoKit
import Foundation
import UniformTypeIdentifiers
@testable import Occulta
@testable import OccultaFormats

/// An in-memory stand-in for `ShareStagingKeyManager`: the app and the extension share one key on a device, so a session
/// staged with one instance opens with another.
private struct IntakeStagingKey: ShareSessionDecrypting {
    static let symmetric = SymmetricKey(size: .bits256)

    func encrypt(data: Data) throws -> Data {
        try AES.GCM.seal(data, using: Self.symmetric, nonce: AES.GCM.Nonce()).combined!
    }
    func decrypt(data: Data) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: Self.symmetric)
    }
    func stagingKeys() -> [SymmetricKey] { [Self.symmetric] }
}

private struct KeyUnavailable: Error {}

private func scratch() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("share-intake-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func write(_ data: Data, named name: String = "source.bin", in directory: URL) throws -> URL {
    let url = directory.appendingPathComponent(name)
    try data.write(to: url)
    return url
}

private func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

// MARK: - Limits and type

@Suite("ShareIntake — limits and the choice of type")
struct ShareIntakeTypeTests {

    @Test("the limits are the extension's: 100 MB for a file, 10 MB for what is held in memory")
    func limits() {
        #expect(ShareIntake.maxFileBytes == 100_000_000)
        #expect(ShareIntake.maxDataBytes == 10_000_000)
    }

    @Test("the first registered type is the one requested, with its preferred extension")
    func firstTypeWins() {
        let jpeg = ShareIntake.requestedType(registered: [UTType.jpeg.identifier, UTType.png.identifier])
        #expect(jpeg.uti == UTType.jpeg.identifier)
        #expect(jpeg.fileExtension == UTType.jpeg.preferredFilenameExtension)

        let pdf = ShareIntake.requestedType(registered: ["com.adobe.pdf", "public.data"])
        #expect(pdf.uti == "com.adobe.pdf")
        #expect(pdf.fileExtension == "pdf")

        let png = ShareIntake.requestedType(registered: ["public.png", "public.jpeg"])
        #expect(png.fileExtension == "png")
    }

    @Test("a provider that registers nothing is plain data, and a type with no extension is a bin")
    func fallbacks() {
        let none = ShareIntake.requestedType(registered: [])
        #expect(none.uti == UTType.data.identifier)
        #expect(none.fileExtension == "bin")

        // `public.data` has no preferred extension.
        #expect(ShareIntake.requestedType(registered: ["public.data"]).fileExtension == "bin")
        // A type the system doesn't know is kept as the one requested, and filed as data.
        let unknown = ShareIntake.requestedType(registered: ["com.example.not-a-registered-type"])
        #expect(unknown.uti == "com.example.not-a-registered-type")
        #expect(unknown.fileExtension == "bin")
    }
}

// MARK: - Sealing a file

@Suite("ShareIntake — a shared file is sealed into the session, a chunk at a time")
@MainActor
struct ShareIntakeSealTests {

    private let key = SymmetricKey(size: .bits256)

    @Test("a file of several chunks is sealed, in order, and opens under the key it was sealed with")
    func roundTrip() async throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let content = Data((0..<200_000).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
        let source = try write(content, in: directory)
        let destination = directory.appendingPathComponent("0.tmp")

        var chunks = 0
        try ShareIntake.seal(fileAt: source, to: destination, key: { self.key }, afterChunk: { chunks += 1 })

        #expect(chunks == (content.count + ShareIntake.chunkBytes - 1) / ShareIntake.chunkBytes, "read \(ShareIntake.chunkBytes) bytes at a time")
        #expect(AttachmentManager.isSealed(at: destination))
        #expect(try await AttachmentManager(contactKey: self.key).data(at: destination) == content)
        let other = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        await #expect(throws: (any Error).self, "opened under another key") { _ = try await other.data(at: destination) }
    }

    @Test("an empty file is sealed as an empty file")
    func emptyFile() async throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("0.tmp")

        try ShareIntake.seal(fileAt: try write(Data(), in: directory), to: destination, key: { self.key })

        #expect(try await AttachmentManager(contactKey: self.key).data(at: destination).isEmpty)
    }

    @Test("a file over 100 MB is refused before it is read, the key is not asked for, and nothing is written")
    func oversizeIsRefusedFirst() throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        // A sparse file: the length is declared and no block is written, so the test costs nothing.
        let source = try write(Data(), in: directory)
        let handle = try FileHandle(forWritingTo: source)
        try handle.truncate(atOffset: UInt64(ShareIntake.maxFileBytes + 1))
        try handle.close()
        let destination = directory.appendingPathComponent("0.tmp")

        var asked = false
        #expect(throws: ShareIntake.Refusal.fileTooLarge) {
            try ShareIntake.seal(fileAt: source, to: destination, key: { asked = true; return self.key })
        }
        #expect(!asked, "the Enclave is not touched for a file that will be refused")
        #expect(!exists(destination))
    }

    @Test("a source that is not there fails and writes nothing")
    func missingSource() throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("0.tmp")

        #expect(throws: (any Error).self) {
            try ShareIntake.seal(fileAt: directory.appendingPathComponent("absent"), to: destination, key: { self.key })
        }
        #expect(!exists(destination))
    }

    @Test("a key that can't be derived fails and writes nothing")
    func keyUnavailable() throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("0.tmp")

        #expect(throws: KeyUnavailable.self) {
            try ShareIntake.seal(fileAt: try write(Data(repeating: 1, count: 100), in: directory), to: destination, key: { throw KeyUnavailable() })
        }
        #expect(!exists(destination))
    }

    @Test("a source that shrinks while it is read fails, and the half-sealed file is removed")
    func sourceEndsEarly() throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let source = try write(Data(repeating: 5, count: 3 * ShareIntake.chunkBytes), in: directory)
        let destination = directory.appendingPathComponent("0.tmp")

        #expect(throws: (any Error).self) {
            try ShareIntake.seal(fileAt: source, to: destination, key: { self.key }, afterChunk: {
                // After the first chunk, the file loses the rest.
                if let handle = try? FileHandle(forWritingTo: source) { try? handle.truncate(atOffset: 10); try? handle.close() }
            })
        }
        #expect(!exists(destination), "a half-written staged file is a trace of its own")
    }
}

// MARK: - Sealing data

@Suite("ShareIntake — the in-memory fallback")
@MainActor
struct ShareIntakeDataTests {

    private let key = SymmetricKey(size: .bits256)

    @Test("data at the limit is sealed, one byte over is refused with nothing written and the key untouched")
    func limit() async throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let atLimit = directory.appendingPathComponent("0.tmp")
        let content = Data(repeating: 9, count: ShareIntake.maxDataBytes)

        try ShareIntake.seal(content, to: atLimit, key: { self.key })
        #expect(try await AttachmentManager(contactKey: self.key).plaintextSize(at: atLimit) == ShareIntake.maxDataBytes)

        let over = directory.appendingPathComponent("1.tmp")
        var asked = false
        #expect(throws: ShareIntake.Refusal.fileTooLarge) {
            try ShareIntake.seal(content + [0], to: over, key: { asked = true; return self.key })
        }
        #expect(!asked)
        #expect(!exists(over))
    }

    @Test("data round-trips, and a key that can't be derived writes nothing")
    func roundTripAndNoKey() async throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("0.tmp")
        try ShareIntake.seal(Data("hello".utf8), to: destination, key: { self.key })
        #expect(try await AttachmentManager(contactKey: self.key).data(at: destination) == Data("hello".utf8))

        let failed = directory.appendingPathComponent("1.tmp")
        #expect(throws: KeyUnavailable.self) { try ShareIntake.seal(Data("hello".utf8), to: failed, key: { throw KeyUnavailable() }) }
        #expect(!exists(failed))
    }
}

// MARK: - The manifest, and the handoff to the app

@Suite("ShareIntake — the manifest, and a session the app can read")
struct ShareIntakeManifestTests {

    private func manifest(_ id: String, uti: String = "public.plain-text", ext: String = "txt") -> ShareManifest {
        ShareManifest(sessionID: id, files: [ShareManifest.FileEntry(filename: "0.tmp", uti: uti, fileExtension: ext)], createdAt: .now)
    }

    @Test("the manifest is sealed by what the caller gives, and the file holds that and no plaintext")
    func manifestIsSealed() throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let id = UUID().uuidString
        let stagingKey = IntakeStagingKey()
        var plaintext: Data?

        try ShareIntake.writeManifest(self.manifest(id, ext: "marker-ext"), in: directory, encrypting: { data in
            plaintext = data
            return try stagingKey.encrypt(data: data)
        })

        let written = try Data(contentsOf: directory.appendingPathComponent("manifest.enc"))
        #expect(try stagingKey.decrypt(data: written) == plaintext)
        #expect(written.range(of: Data("marker-ext".utf8)) == nil, "the extension is on disk in the clear")
        #expect(written.range(of: Data(id.utf8)) == nil)

        let decoded = try JSONDecoder().decode(ShareManifest.self, from: try #require(plaintext))
        #expect(decoded.sessionID == id)
        #expect(decoded.files.map(\.fileExtension) == ["marker-ext"])
    }

    @Test("a manifest that can't be sealed is not written")
    func sealFailure() throws {
        let directory = try scratch(); defer { try? FileManager.default.removeItem(at: directory) }

        #expect(throws: KeyUnavailable.self) {
            try ShareIntake.writeManifest(self.manifest(UUID().uuidString), in: directory, encrypting: { _ in throw KeyUnavailable() })
        }
        #expect(!exists(directory.appendingPathComponent("manifest.enc")))
    }

    @Test("a session staged by ShareIntake is read by ShareSession.staged, text and image")
    @MainActor
    func appReadsWhatTheExtensionStaged() async throws {
        let container = try scratch(); defer { try? FileManager.default.removeItem(at: container) }
        let id = UUID().uuidString
        let sessionDirectory = ShareSession.directory(for: id, in: container)
        try FileManager.default.createDirectory(at: sessionDirectory, withIntermediateDirectories: true)
        let stagingKey = IntakeStagingKey()
        let sessionKey = ShareManifest.sessionKey(staging: IntakeStagingKey.symmetric, sessionID: id)

        // A text file by URL, and an image through the in-memory fallback, as the extension would for each.
        let text = Data("shared text".utf8)
        try ShareIntake.seal(fileAt: try write(text, in: container), to: sessionDirectory.appendingPathComponent("0.tmp"), key: { sessionKey })
        let image = try #require(ShareSessionTarget.image(as: .png))
        try ShareIntake.seal(image, to: sessionDirectory.appendingPathComponent("1.tmp"), key: { sessionKey })

        let types = ShareIntake.requestedType(registered: [UTType.plainText.identifier])
        let imageTypes = ShareIntake.requestedType(registered: [UTType.png.identifier])
        let manifest = ShareManifest(sessionID: id, files: [
            ShareManifest.FileEntry(filename: "0.tmp", uti: types.uti, fileExtension: types.fileExtension),
            ShareManifest.FileEntry(filename: "1.tmp", uti: imageTypes.uti, fileExtension: imageTypes.fileExtension),
        ], createdAt: .now)
        try ShareIntake.writeManifest(manifest, in: sessionDirectory, encrypting: stagingKey.encrypt(data:))

        let staged = try ShareSession.staged(id: id, in: container, keyManager: stagingKey)

        #expect(staged.files.count == 2)
        let textFile = try #require(staged.files.first)
        let textBytes: Data
        if let content = textFile.content { textBytes = content }
        else { textBytes = try await #require(staged.attachments).data(at: try #require(textFile.url)) }
        #expect(textBytes == text)
        #expect(staged.files.last?.content?.isEmpty == false, "the image came back, stripped")
    }

    @Test("a session whose manifest names another session is refused, and its files are removed")
    @MainActor
    func misplacedManifestIsRefused() throws {
        let container = try scratch(); defer { try? FileManager.default.removeItem(at: container) }
        let id = UUID().uuidString
        let sessionDirectory = ShareSession.directory(for: id, in: container)
        try FileManager.default.createDirectory(at: sessionDirectory, withIntermediateDirectories: true)
        let stagingKey = IntakeStagingKey()
        let sessionKey = ShareManifest.sessionKey(staging: IntakeStagingKey.symmetric, sessionID: id)

        try ShareIntake.seal(Data("x".utf8), to: sessionDirectory.appendingPathComponent("0.tmp"), key: { sessionKey })
        try ShareIntake.writeManifest(self.manifest(UUID().uuidString), in: sessionDirectory, encrypting: stagingKey.encrypt(data:))

        #expect(throws: ShareSession.Errors.misplaced) {
            try ShareSession.staged(id: id, in: container, keyManager: stagingKey)
        }
        #expect(!exists(sessionDirectory))
    }
}
