//
//  ShareSessionTests.swift
//  OccultaTests
//
//  First coverage of the share-extension handoff. It had none: the whole lifecycle was a
//  private method on a SwiftUI `View`, and a path nothing can call from a test is a path
//  where a missing PIN gate survives review (Bug 84). `ShareSession` takes its container as
//  a parameter for exactly this reason — every case below runs against a temp directory.
//
//  The key is a parameter too: these run on `TestShareStagingKey`, an in-memory stand-in for
//  `ShareStagingKeyManager`, so they need no Secure Enclave. The real key manager keeps its
//  own small Enclave-gated suite at the end of the file. This type touches neither the
//  contact store nor `Manager.Key`.
//

import Testing
import Foundation
import CryptoKit
import Security
import ImageIO
import UniformTypeIdentifiers
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

private func shareKeyAvailable() -> Bool {
    (try? ShareStagingKeyManager().encrypt(data: Data([0]))) != nil
}

/// In-memory stand-in for `ShareStagingKeyManager`. One key per test process, as a device has
/// one share-staging key that the app and the extension both derive — so a session staged
/// with one instance opens with another, as it does in production. Same AES-GCM format.
private struct TestShareStagingKey: ShareSessionDecrypting {
    private static let key = SymmetricKey(size: .bits256)

    func encrypt(data: Data) throws -> Data {
        let sealed = try AES.GCM.seal(data, using: Self.key, nonce: AES.GCM.Nonce())
        return try #require(sealed.combined)
    }

    func decrypt(data: Data) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: Self.key)
    }

    func stagingKeys() -> [SymmetricKey] { [Self.key] }
}

private func makeContainer() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("ShareSessionTests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

/// Stage a session the way the extension does: encrypted files plus an encrypted manifest.
@discardableResult
private func stage(
    in container: URL,
    files: [(data: Data, uti: String, ext: String)] = [(Data("payload".utf8), UTType.plainText.identifier, "txt")],
    createdAt: Date = .now,
    writeManifest: Bool = true,
    corruptManifest: Bool = false
) throws -> String {
    let id  = UUID().uuidString
    let dir = ShareSession.directory(for: id, in: container)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

    let keyManager = TestShareStagingKey()
    var entries: [ShareManifest.FileEntry] = []

    for (index, file) in files.enumerated() {
        let name = "\(index).tmp"
        try keyManager.encrypt(data: file.data).write(to: dir.appendingPathComponent(name))
        entries.append(ShareManifest.FileEntry(filename: name, uti: file.uti, fileExtension: file.ext))
    }

    if writeManifest {
        let manifestURL = dir.appendingPathComponent("manifest.enc")
        if corruptManifest {
            try Data((0..<64).map { _ in UInt8.random(in: 0...255) }).write(to: manifestURL)
        } else {
            let manifest = ShareManifest(files: entries, createdAt: createdAt)
            try keyManager.encrypt(data: JSONEncoder().encode(manifest)).write(to: manifestURL)
        }
    }

    return id
}

private func exists(_ id: String, in container: URL) -> Bool {
    FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: container).path)
}

/// A 2x2 JPEG carrying EXIF and GPS dictionaries, so the strip has something to remove.
/// GPS is the point of the exercise — a shared photo must not carry where it was taken.
private func makeJPEGWithEXIF() throws -> Data {
    let width = 2, height = 2
    var pixels = [UInt8](repeating: 0x7F, count: width * height * 4)
    let context = CGContext(
        data: &pixels, width: width, height: height, bitsPerComponent: 8,
        bytesPerRow: width * 4, space: CGColorSpaceCreateDeviceRGB(),
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    )
    let image = context!.makeImage()!

    let out = NSMutableData()
    let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil)!
    let properties: [CFString: Any] = [
        kCGImagePropertyOrientation: 6,
        kCGImagePropertyExifDictionary: [
            kCGImagePropertyExifDateTimeOriginal: "2026:08:15 12:00:00"
        ] as CFDictionary,
        kCGImagePropertyGPSDictionary: [
            kCGImagePropertyGPSLatitude: 51.5074,
            kCGImagePropertyGPSLatitudeRef: "N",
            kCGImagePropertyGPSLongitude: 0.1278,
            kCGImagePropertyGPSLongitudeRef: "W"
        ] as CFDictionary
    ]
    CGImageDestinationAddImage(dest, image, properties as CFDictionary)
    #expect(CGImageDestinationFinalize(dest))
    return out as Data
}

private func properties(of data: Data) -> [CFString: Any] {
    guard
        let source = CGImageSourceCreateWithData(data as CFData, nil),
        let props  = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any]
    else { return [:] }
    return props
}

/// Whether the bytes still carry anything identifying.
///
/// Deliberately not "is there an Exif dictionary at all". ImageIO regenerates one for JPEG
/// holding nothing but PixelXDimension/PixelYDimension, which is derived from the image
/// itself and says nothing about where or on what it was taken. What must be gone is the
/// provenance: location, capture time, camera make and model.
private func hasIdentifyingMetadata(_ data: Data) -> Bool {
    let props = properties(of: data)

    if props[kCGImagePropertyGPSDictionary] != nil { return true }
    if props[kCGImagePropertyMakerAppleDictionary] != nil { return true }

    let exif = props[kCGImagePropertyExifDictionary] as? [CFString: Any] ?? [:]
    if exif[kCGImagePropertyExifDateTimeOriginal] != nil { return true }

    let tiff = props[kCGImagePropertyTIFFDictionary] as? [CFString: Any] ?? [:]
    return tiff[kCGImagePropertyTIFFMake] != nil || tiff[kCGImagePropertyTIFFModel] != nil
}

private func orientation(of data: Data) -> Int? {
    properties(of: data)[kCGImagePropertyOrientation] as? Int
}

// MARK: - load

@Suite("ShareSession — load")
struct ShareSessionLoadTests {

    @Test func load_returnsDecryptedFiles_inManifestOrder() throws {
        let container = try makeContainer()
        let id = try stage(in: container, files: [
            (Data("first".utf8),  UTType.plainText.identifier, "txt"),
            (Data("second".utf8), UTType.pdf.identifier,       "pdf")
        ])

        let files = try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())

        #expect(files.count == 2)
        #expect(files[0].content == Data("first".utf8))
        #expect(files[1].content == Data("second".utf8))
        if case .file(let metadata) = files[1].format {
            #expect(metadata.extension == "pdf")
        } else {
            Issue.record("Expected a .file format carrying the manifest's extension")
        }
    }

    /// The caller deletes on success too, but `load` must not be the thing that leaves
    /// plaintext behind — assert it survives a successful read so the caller has something
    /// to delete, then that the caller's delete works.
    @Test func load_leavesDirectoryForCallerToDelete() throws {
        let container = try makeContainer()
        let id = try stage(in: container)

        _ = try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())
        #expect(exists(id, in: container))

        ShareSession.delete(id: id, in: container)
        #expect(!exists(id, in: container))
    }

    @Test func load_rejectsSessionOlderThanTheCutoff() throws {
        let container = try makeContainer()
        let id = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter - 1))

        #expect(throws: ShareSession.Errors.stale) {
            try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())
        }
        #expect(!exists(id, in: container), "A refused session must not leave plaintext on disk")
    }

    @Test func load_acceptsSessionInsideTheCutoff() throws {
        let container = try makeContainer()
        let id = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter + 60))

        let files = try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())
        #expect(files.count == 1)
    }

    @Test func load_missingManifest_throwsAndDeletes() throws {
        let container = try makeContainer()
        let id = try stage(in: container, writeManifest: false)

        #expect(throws: (any Error).self) {
            try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())
        }
        #expect(!exists(id, in: container))
    }

    @Test func load_corruptManifest_throwsAndDeletes() throws {
        let container = try makeContainer()
        let id = try stage(in: container, corruptManifest: true)

        #expect(throws: (any Error).self) {
            try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())
        }
        #expect(!exists(id, in: container))
    }

    /// Guards the fixture itself. If this fails, the strip test below proves nothing.
    @Test func exifFixture_carriesMetadata() throws {
        #expect(hasIdentifyingMetadata(try makeJPEGWithEXIF()))
    }

    @Test func load_stripsEXIFFromImages() throws {
        let container = try makeContainer()
        let jpeg = try makeJPEGWithEXIF()

        let id = try stage(in: container, files: [(jpeg, UTType.jpeg.identifier, "jpg")])
        let files = try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())

        let loaded = try #require(files.first?.content)
        #expect(!hasIdentifyingMetadata(loaded))
    }

    /// Orientation must survive the strip — it says which way up to draw the photo, not
    /// where it was taken. Removing the whole TIFF dictionary without putting this back
    /// lays portrait images on their side.
    @Test func load_preservesOrientationThroughTheStrip() throws {
        let container = try makeContainer()
        let jpeg = try makeJPEGWithEXIF()
        let original = try #require(orientation(of: jpeg))

        let id = try stage(in: container, files: [(jpeg, UTType.jpeg.identifier, "jpg")])
        let files = try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())

        let loaded = try #require(files.first?.content)
        #expect(orientation(of: loaded) == original)
    }

    @Test func load_leavesNonImagesByteIdentical() throws {
        let container = try makeContainer()
        let pdfBytes = Data((0..<256).map { UInt8($0) })
        let id = try stage(in: container, files: [(pdfBytes, UTType.pdf.identifier, "pdf")])

        let files = try ShareSession.load(id: id, in: container, keyManager: TestShareStagingKey())
        #expect(files.first?.content == pdfBytes)
    }
}

// MARK: - sweep

@Suite("ShareSession — sweep")
struct ShareSessionSweepTests {

    @Test func sweep_keepsFreshSession() throws {
        let container = try makeContainer()
        let id = try stage(in: container)

        ShareSession.sweep(in: container, keyManager: TestShareStagingKey())
        #expect(exists(id, in: container))
    }

    @Test func sweep_deletesStaleSession() throws {
        let container = try makeContainer()
        let id = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter - 1))

        ShareSession.sweep(in: container, keyManager: TestShareStagingKey())
        #expect(!exists(id, in: container))
    }

    /// No manifest means the extension died mid-write. Those files are staged plaintext with
    /// nothing to date them, so they go immediately rather than aging out.
    @Test func sweep_deletesSessionWithNoManifest() throws {
        let container = try makeContainer()
        let id = try stage(in: container, writeManifest: false)

        ShareSession.sweep(in: container, keyManager: TestShareStagingKey())
        #expect(!exists(id, in: container))
    }

    @Test func sweep_deletesSessionWithUnreadableManifest() throws {
        let container = try makeContainer()
        let id = try stage(in: container, corruptManifest: true)

        ShareSession.sweep(in: container, keyManager: TestShareStagingKey())
        #expect(!exists(id, in: container))
    }

    @Test func sweep_keepsFreshWhileDeletingStale() throws {
        let container = try makeContainer()
        let fresh = try stage(in: container)
        let stale = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter - 1))

        ShareSession.sweep(in: container, keyManager: TestShareStagingKey())
        #expect(exists(fresh, in: container))
        #expect(!exists(stale, in: container))
    }

    @Test func sweep_onMissingPendingDirectory_doesNotThrow() throws {
        let container = try makeContainer()
        ShareSession.sweep(in: container, keyManager: TestShareStagingKey())
    }
}

// MARK: - Inbound sweep

/// Hand off a `.occ` the way the extension does, last modified `age` seconds ago.
private func handoff(in container: URL, age: TimeInterval = 0) throws -> URL {
    let inbound = container.appendingPathComponent("inbound")
    try FileManager.default.createDirectory(at: inbound, withIntermediateDirectories: true)

    let file = inbound.appendingPathComponent("\(UUID().uuidString).occ")
    try Data("sealed by the sender".utf8).write(to: file)
    try FileManager.default.setAttributes(
        [.modificationDate: Date.now.addingTimeInterval(-age)],
        ofItemAtPath: file.path
    )
    return file
}

@Suite("ShareSession — inbound sweep")
struct ShareSessionInboundSweepTests {

    /// A handoff whose open never reached the app. Nothing else reads `inbound/`, so without
    /// the sweep it stays until Erase All Data.
    @Test func sweepInbound_deletesStaleHandoff() throws {
        let container = try makeContainer()
        let file = try handoff(in: container, age: ShareSession.staleAfter + 1)

        ShareSession.sweepInbound(in: container)
        #expect(!FileManager.default.fileExists(atPath: file.path))
    }

    /// The sweep runs when the app comes to the foreground, which is also when a handoff
    /// opens it, so the file the app is about to read must survive.
    @Test func sweepInbound_keepsFreshHandoff() throws {
        let container = try makeContainer()
        let file = try handoff(in: container)

        ShareSession.sweepInbound(in: container)
        #expect(FileManager.default.fileExists(atPath: file.path))
    }

    @Test func sweepInbound_onMissingInboundDirectory_isANoOp() throws {
        let container = try makeContainer()

        ShareSession.sweepInbound(in: container)
        #expect(!FileManager.default.fileExists(atPath: container.appendingPathComponent("inbound").path))
    }
}

// MARK: - Legacy contact mirror

@Suite("ShareSession — legacy contact index removal")
struct ShareSessionLegacyIndexTests {

    /// An upgrade from a build that still mirrored the contact list must not leave the mirror
    /// in the App Group. Its rows are sealed, but its existence, row count, and mtime are
    /// relationship metadata with nothing left to read them.
    @Test func removeLegacyContactIndex_deletesStoreAndCompanions() throws {
        let container = try makeContainer()
        let names = ["ShareIndex.sqlite", "ShareIndex.sqlite-wal", "ShareIndex.sqlite-shm"]

        for name in names {
            try Data("stale".utf8).write(to: container.appendingPathComponent(name))
        }

        ShareSession.removeLegacyContactIndex(in: container)

        for name in names {
            #expect(!FileManager.default.fileExists(atPath: container.appendingPathComponent(name).path), "\(name) survived")
        }
    }

    @Test func removeLegacyContactIndex_whenAbsent_isANoOp() throws {
        let container = try makeContainer()
        ShareSession.removeLegacyContactIndex(in: container)
        ShareSession.removeLegacyContactIndex(in: container)
    }

    /// Removing the mirror must not take the staging directory with it. Built by hand rather
    /// than through `stage` so this case still runs where the share key is unavailable.
    @Test func removeLegacyContactIndex_leavesPendingSessionsAlone() throws {
        let container = try makeContainer()
        let id  = UUID().uuidString
        let dir = ShareSession.directory(for: id, in: container)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        ShareSession.removeLegacyContactIndex(in: container)
        #expect(exists(id, in: container))
    }
}

// MARK: - Erase

@Suite("ShareSession — erase")
struct ShareSessionEraseTests {

    /// Erase All Data must leave nothing of the share pipeline in the App Group (`bugs.md`
    /// Bug 170): no staged session, not even a fresh one `sweep` would keep; no `.occ`
    /// handoff, not even a fresh one `sweepInbound` would keep; and not the two directories,
    /// whose creation dates record the first share into Occulta.
    @Test func removeAll_deletesEverythingTheExtensionLeft() throws {
        let container = try makeContainer()
        try stage(in: container)

        let inbound = container.appendingPathComponent("inbound")
        try FileManager.default.createDirectory(at: inbound, withIntermediateDirectories: true)
        try Data("sealed by the sender".utf8).write(to: inbound.appendingPathComponent("\(UUID().uuidString).occ"))

        try Data("stale".utf8).write(to: container.appendingPathComponent("ShareIndex.sqlite"))

        ShareSession.removeAll(in: container)

        for name in ["pending", "inbound", "ShareIndex.sqlite"] {
            #expect(!FileManager.default.fileExists(atPath: container.appendingPathComponent(name).path), "\(name) survived")
        }
    }

    @Test func removeAll_whenNothingWasStaged_isANoOp() throws {
        let container = try makeContainer()
        ShareSession.removeAll(in: container)
        ShareSession.removeAll(in: container)
    }
}

// MARK: - The real key manager

/// The share-staging key's public key, or nil when there is none. Asks the keychain directly,
/// since every `ShareStagingKeyManager` entry point creates the key when it is missing. Tag
/// and group are written out rather than read from the type: both are persisted, so renaming
/// either has to fail here.
private func stagingPublicKey() -> Data? {
    let query: [String: Any] = [
        kSecClass as String:              kSecClassKey,
        kSecAttrApplicationTag as String: "share.index.se.key.occulta".data(using: .utf8)!,
        kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave,
        kSecAttrAccessGroup as String:    "group.com.occulta.shared",
        kSecReturnRef as String:          true
    ]
    var item: CFTypeRef?
    guard
        SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
        let publicKey = SecKeyCopyPublicKey(item as! SecKey)
    else { return nil }
    return SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
}

/// `ShareStagingKeyManager` itself, which the suites above stand in for. Its key lives in the
/// Secure Enclave, so this needs one. What the share handoff depends on is that two separate
/// instances derive the same key: the extension seals with its own and the app opens with
/// another.
///
/// Serialized because two cases delete the key, which would pull it out from under a
/// concurrent seal-then-open.
@Suite("ShareStagingKeyManager — Enclave key", .enabled(if: shareKeyAvailable()), .serialized)
struct ShareStagingKeyManagerTests {

    /// Erase All Data deletes this key (`bugs.md` Bug 170): it and its creation date outlived
    /// the wipe. The next access must create a fresh key rather than fail, and nothing sealed
    /// under the old one may open with the new.
    @Test("Deleting the key removes it, and the next access creates a fresh one")
    func deleteKeyRemovesItAndNextAccessCreatesAFreshOne() throws {
        let sealedBefore = try ShareStagingKeyManager().encrypt(data: Data("staged".utf8))
        let original     = try #require(stagingPublicKey())

        #expect(ShareStagingKeyManager().deleteKey())
        #expect(stagingPublicKey() == nil)

        let plaintext = Data("staged after the erase".utf8)
        let sealed    = try ShareStagingKeyManager().encrypt(data: plaintext)
        #expect(try ShareStagingKeyManager().decrypt(data: sealed) == plaintext)

        let fresh = try #require(stagingPublicKey())
        #expect(fresh != original)
        #expect(throws: (any Error).self) { try ShareStagingKeyManager().decrypt(data: sealedBefore) }
    }

    @Test("Deleting a key that is already gone succeeds")
    func deleteKeyWhenAbsentSucceeds() {
        ShareStagingKeyManager().deleteKey()
        #expect(stagingPublicKey() == nil)
        #expect(ShareStagingKeyManager().deleteKey())
    }

    /// `r_S`, the staging tier's Keychain secret, and its PQ record are dated like the key (`bugs.md` Bug 171): the
    /// wipe has to remove all three.
    @Test("Deleting the key also removes r_S and the PQ record")
    func deleteKeyAlsoRemovesTheTierSecretAndRecord() throws {
        let staging = ShareStagingKeyManager()
        try staging.createTierSecretIfAbsent()
        try staging.createTierPQRecordIfAbsent()
        #expect(try staging.tierSecret() != nil)
        #expect(try staging.tierPQRecord() != nil)

        #expect(staging.deleteKey())
        #expect(try staging.tierSecret() == nil)
        #expect(try staging.tierPQRecord() == nil)
    }

    @Test("What one instance seals, another opens")
    func separateInstancesShareTheKey() throws {
        let plaintext = Data("staged".utf8)
        let sealed    = try ShareStagingKeyManager().encrypt(data: plaintext)
        #expect(try ShareStagingKeyManager().decrypt(data: sealed) == plaintext)
    }

    @Test("A tampered ciphertext is rejected")
    func tamperedCiphertextIsRejected() throws {
        var sealed = try ShareStagingKeyManager().encrypt(data: Data("staged".utf8))
        sealed[sealed.count - 1] ^= 0x01
        #expect(throws: (any Error).self) { try ShareStagingKeyManager().decrypt(data: sealed) }
    }

    // MARK: Stage 5 (Bug 171): a real Enclave key, in each form

    /// Items of a test's own, so the canonical key, `r_S` and record that other tests and the extension use stay alone.
    private struct OwnItems {
        let keyTag = "test.stage5.enclave.key.\(UUID().uuidString)"
        let secret = "test.stage5.enclave.rs.\(UUID().uuidString)"
        let record = "test.stage5.enclave.pqs.\(UUID().uuidString)"

        func process(postQuantum: @escaping () -> (any StagingPostQuantum)?) -> ShareStagingKeyManager {
            ShareStagingKeyManager(keyTag: self.keyTag, tierSecretAccount: self.secret, tierPQRecordAccount: self.record, postQuantum: postQuantum)
        }
    }

    private func roundTrip(postQuantum: @escaping () -> (any StagingPostQuantum)?, expecting mode: ShareStagingKeyManager.PQRecord.Mode) throws {
        let items = OwnItems()
        let app = items.process(postQuantum: postQuantum), extension_ = items.process(postQuantum: postQuantum)
        defer { app.deleteKey() }

        let plaintext = Data("staged under the real Enclave key".utf8)
        let sealed = try extension_.encrypt(data: plaintext)

        #expect(try extension_.tierPQRecord()?.mode == mode)
        #expect(try app.decrypt(data: sealed) == plaintext, "a second instance on the same items opens it")
        #expect(try app.tierSecret() != nil)

        let legacy = try app.deriveLegacySymmetricKey()
        let box    = try AES.GCM.SealedBox(combined: sealed)
        #expect((try? AES.GCM.open(box, using: legacy)) == nil, "not under the legacy key")

        // And a session the previous build sealed under the legacy key still opens.
        let old = try #require(try AES.GCM.seal(plaintext, using: legacy).combined)
        #expect(try app.decrypt(data: old) == plaintext)
    }

    @Test("Classical form on the real Enclave key: sealed, opened by a second instance, not under the legacy key")
    func realEnclaveClassicalRoundTrip() throws {
        try self.roundTrip(postQuantum: { nil }, expecting: .classical)
    }

    @Test("Hybrid form on the real Enclave keys (P-256 and ML-KEM-1024): sealed, opened by a second instance, not under the legacy key",
          .enabled(if: ShareStagingKeyManager.platformPostQuantum() != nil))
    func realEnclaveHybridRoundTrip() throws {
        try self.roundTrip(postQuantum: ShareStagingKeyManager.platformPostQuantum, expecting: .hybrid)
    }
}
