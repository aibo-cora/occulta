//
//  ShareSessionStreamedTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §8.4, the app's half: a share session staged as sealed `.eatt` files, under the session's key, is
//  read without decrypting them. A file sealed whole, as builds before 2.0.0 staged them, is refused (Bug 213).
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
    func stagingKeys() -> [SymmetricKey] { [Self.key] }
}

private func container() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShareStreamed-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

/// A session staged the way the extension stages one: each file a `.eatt` under the session's key.
private func stage(
    _ files: [(data: Data, uti: String, ext: String)], in container: URL, createdAt: Date = .now
) throws -> String {
    let id  = UUID().uuidString
    let dir = ShareSession.directory(for: id, in: container)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

    let keys = StagingKey()
    let sessionKey = ShareManifest.sessionKey(staging: StagingKey.key, sessionID: id)
    var entries: [ShareManifest.FileEntry] = []
    for (index, file) in files.enumerated() {
        let name = "\(index).tmp"
        let url  = dir.appendingPathComponent(name)
        let encryptor = try AttachmentManager(contactKey: sessionKey).streamingEncryptor(to: url)
        var offset = 0
        while offset < file.data.count {
            let end = min(offset + 65_536, file.data.count)
            try encryptor.append(file.data[offset..<end])
            offset = end
        }
        try encryptor.finalize()
        entries.append(ShareManifest.FileEntry(filename: name, uti: file.uti, fileExtension: file.ext))
    }
    try keys.encrypt(data: JSONEncoder().encode(ShareManifest(sessionID: id, files: entries, createdAt: createdAt)))
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
        let id = try stage([(plaintext, UTType.movie.identifier, "mp4")], in: box)

        let staged = try ShareSession.staged(id: id, in: box, keyManager: StagingKey())

        let file = try #require(staged.files.first)
        #expect(file.content == nil)
        let url = try #require(file.url)
        #expect(AttachmentManager.isSealed(at: url))
        #expect(try await #require(staged.attachments).data(at: url) == plaintext)
        guard case .file(let metadata) = file.format else { Issue.record("not a file"); return }
        #expect(metadata.extension == "mp4")
    }

    @Test("an image is read whole, and its location is stripped")
    func imageIsStripped() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let image = try jpegWithGPS()
        #expect(hasGPS(image), "precondition")
        let id = try stage([(image, UTType.jpeg.identifier, "jpg")], in: box)

        let staged = try ShareSession.staged(id: id, in: box, keyManager: StagingKey())

        let content = try #require(staged.files.first?.content)
        #expect(staged.files.first?.url == nil)
        #expect(!hasGPS(content))
    }

    @Test("an expired session is refused and deleted")
    func stale() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let id = try stage([(Data([1]), UTType.data.identifier, "bin")], in: box, createdAt: .now.addingTimeInterval(-7_200))

        #expect(throws: ShareSession.Errors.stale) { _ = try ShareSession.staged(id: id, in: box, keyManager: StagingKey()) }
        #expect(!FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: box).path))
    }

    @Test("a staged file that can't be opened deletes the session")
    func unreadableFileDeletesSession() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let id = try stage([(streamedPattern(1000), UTType.data.identifier, "bin")], in: box)
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
        let id = try stage([(card.encoded, UTType.data.identifier, "")], in: box)
        #expect(ShareSession.introductionCard(id: id, in: box, keyManager: StagingKey()) == card.encoded)

        let big = try stage([(streamedPattern(2_000_000), UTType.data.identifier, "bin")], in: box)
        #expect(ShareSession.introductionCard(id: big, in: box, keyManager: StagingKey()) == nil)
    }

    /// Bug 213: a card file moved in from another session, or one sealed whole under the staging key, is not read.
    @Test("a card file from another session, or sealed whole, is not recognised")
    @available(iOS 26, *)
    func cardFromElsewhereIsNotRead() throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let card = try CardTestIssuer().card
        let other = try stage([(card.encoded, UTType.data.identifier, "")], in: box)
        let moved = try stage([(streamedPattern(IntroductionCard.byteCount), UTType.data.identifier, "")], in: box)
        let target = ShareSession.directory(for: moved, in: box).appendingPathComponent("0.tmp")
        try FileManager.default.removeItem(at: target)
        try FileManager.default.copyItem(at: ShareSession.directory(for: other, in: box).appendingPathComponent("0.tmp"), to: target)
        #expect(ShareSession.introductionCard(id: moved, in: box, keyManager: StagingKey()) == nil)

        let whole = try stage([(card.encoded, UTType.data.identifier, "")], in: box)
        try StagingKey().encrypt(data: card.encoded)
            .write(to: ShareSession.directory(for: whole, in: box).appendingPathComponent("0.tmp"))
        #expect(ShareSession.introductionCard(id: whole, in: box, keyManager: StagingKey()) == nil)
    }
}

// MARK: - Sending

@Suite("Share session — sending what was staged")
@MainActor struct ShareSessionSendTests {

    let bob = TestKeyManager()

    @Test("a streamed-staged session sends from disk, to either layout", .ambientTestKeyManager,
          arguments: [OccultaBundle.Version.streamedBodyCapable, .bodyDigestCapable])
    func eattSessionSends(marker: OccultaBundle.Version) throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let plaintext = streamedPattern(700_000, seed: 9)
        let id = try stage([(plaintext, UTType.data.identifier, "bin")], in: box)
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
    sharedKeychainAvailable() && (try? ShareStagingKeyManager().encrypt(data: Data([0]))) != nil
}

@Suite("Share session — the extension's real key")
@MainActor struct ShareSessionRealKeyTests {

    /// What the extension does, with the key it has: the file sealed by `StreamingEncryptor` under
    /// `deriveStreamSealingKey()` bound to the session, the manifest by `encrypt(data:)`. The app must read both back.
    @Test("a session staged the way the extension stages one opens in the app", .enabled(if: shareKeyAvailable()))
    func extensionFormatOpens() async throws {
        let box = try container(); defer { try? FileManager.default.removeItem(at: box) }
        let keys = ShareStagingKeyManager()
        let plaintext = streamedPattern(700_000, seed: 31)

        let id  = UUID().uuidString
        let dir = ShareSession.directory(for: id, in: box)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let encryptor = try StreamingEncryptor(
            url: dir.appendingPathComponent("0.tmp"),
            contactKey: ShareManifest.sessionKey(staging: try keys.deriveStreamSealingKey(), sessionID: id)
        )
        var offset = 0
        while offset < plaintext.count {
            let end = min(offset + 65_536, plaintext.count)
            try encryptor.append(plaintext[offset..<end])
            offset = end
        }
        try encryptor.finalize()
        let manifest = ShareManifest(
            sessionID: id,
            files: [ShareManifest.FileEntry(filename: "0.tmp", uti: UTType.movie.identifier, fileExtension: "mov")], createdAt: .now
        )
        try keys.encrypt(data: JSONEncoder().encode(manifest)).write(to: dir.appendingPathComponent("manifest.enc"))

        let staged = try ShareSession.staged(id: id, in: box, keyManager: keys)

        let url = try #require(staged.files.first?.url)
        #expect(staged.files.first?.content == nil)
        #expect(try await #require(staged.attachments).data(at: url) == plaintext)
    }
}
