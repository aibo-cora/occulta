//
//  ShareSessionStreamedTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §8.4, the app's half: a share session staged as sealed `.eatt` files is read without decrypting
//  them, and one staged by the build before this one (a single AES-GCM blob per file) is still read and still sends.
//  The extension's own half needs a decision first, see the stage 4 notes.
//

import Testing
import CryptoKit
import Foundation
import ImageIO
import UniformTypeIdentifiers
@testable import Occulta
@testable import OccultaFormats

private struct StagingKey: ShareSessionDecrypting {
    static let key = SymmetricKey(size: .bits256)

    func encrypt(data: Data) throws -> Data {
        try #require(try AES.GCM.seal(data, using: Self.key, nonce: AES.GCM.Nonce()).combined)
    }
    func decrypt(data: Data) throws -> Data { try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: Self.key) }
    func stagingKey() throws -> SymmetricKey { Self.key }
}

private enum Format { case legacy, eatt }

private func container() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShareStreamed-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

/// A session staged the way the extension of either build stages it.
private func stage(
    _ files: [(data: Data, uti: String, ext: String, format: Format)], in container: URL, createdAt: Date = .now
) throws -> String {
    let id  = UUID().uuidString
    let dir = ShareSession.directory(for: id, in: container)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

    let keys = StagingKey()
    var entries: [ShareManifest.FileEntry] = []
    for (index, file) in files.enumerated() {
        let name = "\(index).tmp"
        let url  = dir.appendingPathComponent(name)
        switch file.format {
        case .legacy:
            try keys.encrypt(data: file.data).write(to: url)
        case .eatt:
            let encryptor = try AttachmentManager(contactKey: StagingKey.key).streamingEncryptor(to: url)
            var offset = 0
            while offset < file.data.count {
                let end = min(offset + 65_536, file.data.count)
                try encryptor.append(file.data[offset..<end])
                offset = end
            }
            try encryptor.finalize()
        }
        entries.append(ShareManifest.FileEntry(filename: name, uti: file.uti, fileExtension: file.ext))
    }
    try keys.encrypt(data: JSONEncoder().encode(ShareManifest(files: entries, createdAt: createdAt)))
        .write(to: dir.appendingPathComponent("manifest.enc"))
    return id
}

private func jpegWithGPS() throws -> Data {
    var pixels = [UInt8](repeating: 0x7F, count: 16)
    let context = CGContext(
        data: &pixels, width: 2, height: 2, bitsPerComponent: 8, bytesPerRow: 8, space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    )
    let out = NSMutableData()
    let destination = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, context!.makeImage()!, [
        kCGImagePropertyGPSDictionary: [
            kCGImagePropertyGPSLatitude: 51.5074, kCGImagePropertyGPSLatitudeRef: "N",
            kCGImagePropertyGPSLongitude: 0.1278, kCGImagePropertyGPSLongitudeRef: "W",
        ] as CFDictionary,
    ] as CFDictionary)
    #expect(CGImageDestinationFinalize(destination))
    return out as Data
}

private func hasGPS(_ data: Data) -> Bool {
    guard let source = CGImageSourceCreateWithData(data as CFData, nil),
          let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any] else { return false }
    return props[kCGImagePropertyGPSDictionary] != nil
}

@Suite("Share session — streamed staging")
@MainActor struct ShareSessionStreamedTests {

    @Test("a staged .eatt file is left on disk, sealed, and read back through the manager", arguments: [0, 1, 300_000, 800_000])
    func eattIsNotDecrypted(size: Int) async throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let plaintext = streamedPattern(size, seed: 4)
        let id = try stage([(plaintext, UTType.movie.identifier, "mp4", .eatt)], in: box)

        let staged = try ShareSession.staged(id: id, in: box, keyManager: StagingKey())

        let file = try #require(staged.files.first)
        #expect(file.content == nil)
        let url = try #require(file.url)
        #expect(AttachmentManager.isSealed(at: url))
        #expect(try await #require(staged.attachments).data(at: url) == plaintext)
        guard case .file(let metadata) = file.format else { Issue.record("not a file"); return }
        #expect(metadata.extension == "mp4")
    }

    @Test("a file the previous build staged is read whole, as before")
    func legacyIsRead() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let plaintext = streamedPattern(5_000, seed: 5)
        let id = try stage([(plaintext, UTType.pdf.identifier, "pdf", .legacy)], in: box)

        let staged = try ShareSession.staged(id: id, in: box, keyManager: StagingKey())

        #expect(staged.files.first?.content == plaintext)
        #expect(staged.files.first?.url == nil)
        #expect(staged.attachments == nil)
    }

    @Test("one session can hold both, in order")
    func mixed() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let a = streamedPattern(100, seed: 1), b = streamedPattern(400_000, seed: 2), c = streamedPattern(50, seed: 3)
        let id = try stage([
            (a, UTType.data.identifier, "bin", .legacy), (b, UTType.data.identifier, "bin", .eatt), (c, UTType.data.identifier, "bin", .legacy),
        ], in: box)

        let files = try ShareSession.load(id: id, in: box, keyManager: StagingKey())

        #expect(files.map(\.content) == [a, b, c])
        #expect(files.allSatisfy { $0.url == nil })
    }

    @Test("an image is read whole either way, and its location is stripped", arguments: [Format.legacy, .eatt])
    private func imageIsStripped(format: Format) throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let image = try jpegWithGPS()
        #expect(hasGPS(image), "precondition")
        let id = try stage([(image, UTType.jpeg.identifier, "jpg", format)], in: box)

        let staged = try ShareSession.staged(id: id, in: box, keyManager: StagingKey())

        let content = try #require(staged.files.first?.content)
        #expect(staged.files.first?.url == nil)
        #expect(!hasGPS(content))
    }

    @Test("an expired session is refused and deleted, whichever format")
    func stale() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let id = try stage([(Data([1]), UTType.data.identifier, "bin", .eatt)], in: box, createdAt: .now.addingTimeInterval(-7_200))

        #expect(throws: ShareSession.Errors.stale) { _ = try ShareSession.staged(id: id, in: box, keyManager: StagingKey()) }
        #expect(!FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: box).path))
    }

    @Test("a staged file that can't be opened deletes the session")
    func unreadableFileDeletesSession() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let id = try stage([(streamedPattern(1000), UTType.data.identifier, "bin", .eatt)], in: box)
        // A sealed file whose header has been damaged.
        let url = ShareSession.directory(for: id, in: box).appendingPathComponent("0.tmp")
        var bytes = try Data(contentsOf: url)
        bytes[60] ^= 0x01
        try bytes.write(to: url)

        #expect(throws: (any Error).self) { _ = try ShareSession.load(id: id, in: box, keyManager: StagingKey()) }
        #expect(!FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: box).path))
    }

    @Test("an introduction card staged as .eatt is recognised, and a large file is not read")
    @available(iOS 26, *)
    func cardInEattSession() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let card = try CardTestIssuer().card
        let id = try stage([(card.encoded, UTType.data.identifier, "", .eatt)], in: box)
        #expect(ShareSession.introductionCard(id: id, in: box, keyManager: StagingKey()) == card.encoded)

        let legacyID = try stage([(card.encoded, UTType.data.identifier, "", .legacy)], in: box)
        #expect(ShareSession.introductionCard(id: legacyID, in: box, keyManager: StagingKey()) == card.encoded)

        let big = try stage([(streamedPattern(2_000_000), UTType.data.identifier, "bin", .eatt)], in: box)
        #expect(ShareSession.introductionCard(id: big, in: box, keyManager: StagingKey()) == nil)
    }
}

// MARK: - Both sessions send

@Suite("Share session — sending what was staged")
@MainActor struct ShareSessionSendTests {

    let bob = TestKeyManager()

    @Test("a session staged by the previous build still sends, streamed when the recipient can read it", .ambientTestKeyManager)
    func legacySessionStillSends() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let plaintext = streamedPattern(700_000, seed: 9)
        let id = try stage([(plaintext, UTType.data.identifier, "bin", .legacy)], in: box)
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try self.bob.retrieveIdentity(), marker: .streamedBodyCapable, in: cm)

        let staged = try ShareSession.staged(id: id, in: box, keyManager: StagingKey())
        let out = box.appendingPathComponent("out.occ")
        let layout = try cm.encryptBundle(
            basket: Basket(files: staged.files), for: "bob",
            output: .file(destination: out, attachments: staged.attachments, memoryGuard: .system)
        )

        #expect(layout == .streamed)
        #expect(try Data(contentsOf: out)[4] == 0x0A)
    }

    @Test("a streamed-staged session sends from disk, to either layout", .ambientTestKeyManager,
          arguments: [OccultaBundle.Version.streamedBodyCapable, .bodyDigestCapable])
    func eattSessionSends(marker: OccultaBundle.Version) throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let plaintext = streamedPattern(700_000, seed: 9)
        let id = try stage([(plaintext, UTType.data.identifier, "bin", .eatt)], in: box)
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try self.bob.retrieveIdentity(), marker: marker, in: cm)

        let staged = try ShareSession.staged(id: id, in: box, keyManager: StagingKey())
        let out = box.appendingPathComponent("out.occ")
        let layout = try cm.encryptBundle(
            basket: Basket(files: staged.files), for: "bob",
            output: .file(destination: out, attachments: staged.attachments, memoryGuard: .system)
        )

        #expect(layout == (marker == .streamedBodyCapable ? .streamed : .inline))
    }
}

// MARK: - The extension's key

private func shareKeyAvailable() -> Bool {
    (try? ShareStagingKeyManager().deriveSymmetricKey()) != nil
}

@Suite("Share session — the extension's real key")
@MainActor struct ShareSessionRealKeyTests {

    /// What the extension does, with the key it has: the file sealed by `StreamingEncryptor` under
    /// `deriveSymmetricKey()`, the manifest by `encrypt(data:)`. The app must read both back.
    @Test("a session staged the way the extension stages one opens in the app", .enabled(if: shareKeyAvailable()))
    func extensionFormatOpens() async throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let keys = ShareStagingKeyManager()
        let plaintext = streamedPattern(700_000, seed: 31)

        let id  = UUID().uuidString
        let dir = ShareSession.directory(for: id, in: box)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let encryptor = try StreamingEncryptor(url: dir.appendingPathComponent("0.tmp"), contactKey: try keys.deriveSymmetricKey())
        var offset = 0
        while offset < plaintext.count {
            let end = min(offset + 65_536, plaintext.count)
            try encryptor.append(plaintext[offset..<end])
            offset = end
        }
        try encryptor.finalize()
        let manifest = ShareManifest(
            files: [ShareManifest.FileEntry(filename: "0.tmp", uti: UTType.movie.identifier, fileExtension: "mov")], createdAt: .now
        )
        try keys.encrypt(data: JSONEncoder().encode(manifest)).write(to: dir.appendingPathComponent("manifest.enc"))

        let staged = try ShareSession.staged(id: id, in: box, keyManager: keys)

        let url = try #require(staged.files.first?.url)
        #expect(staged.files.first?.content == nil)
        #expect(try await #require(staged.attachments).data(at: url) == plaintext)
    }
}
