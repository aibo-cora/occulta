//
//  ShareSessionTests.swift
//  OccultaTests
//
//  First coverage of the share-extension handoff. It had none: the whole lifecycle was a
//  private method on a SwiftUI `View`, and a path nothing can call from a test is a path
//  where a missing PIN gate survives review (Bug 84). `ShareSession` takes its container as
//  a parameter for exactly this reason — every case below runs against a temp directory.
//
//  Gated on the share-index SE key rather than the local DB key: this type touches neither
//  the contact store nor `Manager.Key`.
//

import Testing
import Foundation
import ImageIO
import UniformTypeIdentifiers
@testable import Occulta

// MARK: - Helpers

private func shareKeyAvailable() -> Bool {
    (try? ShareIndexKeyManager().encrypt(data: Data([0]))) != nil
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

    let keyManager = ShareIndexKeyManager()
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

@Suite("ShareSession — load", .enabled(if: shareKeyAvailable()))
struct ShareSessionLoadTests {

    @Test func load_returnsDecryptedFiles_inManifestOrder() throws {
        let container = try makeContainer()
        let id = try stage(in: container, files: [
            (Data("first".utf8),  UTType.plainText.identifier, "txt"),
            (Data("second".utf8), UTType.pdf.identifier,       "pdf")
        ])

        let files = try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())

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

        _ = try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())
        #expect(exists(id, in: container))

        ShareSession.delete(id: id, in: container)
        #expect(!exists(id, in: container))
    }

    @Test func load_rejectsSessionOlderThanTheCutoff() throws {
        let container = try makeContainer()
        let id = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter - 1))

        #expect(throws: ShareSession.Errors.stale) {
            try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())
        }
        #expect(!exists(id, in: container), "A refused session must not leave plaintext on disk")
    }

    @Test func load_acceptsSessionInsideTheCutoff() throws {
        let container = try makeContainer()
        let id = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter + 60))

        let files = try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())
        #expect(files.count == 1)
    }

    @Test func load_missingManifest_throwsAndDeletes() throws {
        let container = try makeContainer()
        let id = try stage(in: container, writeManifest: false)

        #expect(throws: (any Error).self) {
            try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())
        }
        #expect(!exists(id, in: container))
    }

    @Test func load_corruptManifest_throwsAndDeletes() throws {
        let container = try makeContainer()
        let id = try stage(in: container, corruptManifest: true)

        #expect(throws: (any Error).self) {
            try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())
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
        let files = try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())

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
        let files = try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())

        let loaded = try #require(files.first?.content)
        #expect(orientation(of: loaded) == original)
    }

    @Test func load_leavesNonImagesByteIdentical() throws {
        let container = try makeContainer()
        let pdfBytes = Data((0..<256).map { UInt8($0) })
        let id = try stage(in: container, files: [(pdfBytes, UTType.pdf.identifier, "pdf")])

        let files = try ShareSession.load(id: id, in: container, keyManager: ShareIndexKeyManager())
        #expect(files.first?.content == pdfBytes)
    }
}

// MARK: - sweep

@Suite("ShareSession — sweep", .enabled(if: shareKeyAvailable()))
struct ShareSessionSweepTests {

    @Test func sweep_keepsFreshSession() throws {
        let container = try makeContainer()
        let id = try stage(in: container)

        ShareSession.sweep(in: container, keyManager: ShareIndexKeyManager())
        #expect(exists(id, in: container))
    }

    @Test func sweep_deletesStaleSession() throws {
        let container = try makeContainer()
        let id = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter - 1))

        ShareSession.sweep(in: container, keyManager: ShareIndexKeyManager())
        #expect(!exists(id, in: container))
    }

    /// No manifest means the extension died mid-write. Those files are staged plaintext with
    /// nothing to date them, so they go immediately rather than aging out.
    @Test func sweep_deletesSessionWithNoManifest() throws {
        let container = try makeContainer()
        let id = try stage(in: container, writeManifest: false)

        ShareSession.sweep(in: container, keyManager: ShareIndexKeyManager())
        #expect(!exists(id, in: container))
    }

    @Test func sweep_deletesSessionWithUnreadableManifest() throws {
        let container = try makeContainer()
        let id = try stage(in: container, corruptManifest: true)

        ShareSession.sweep(in: container, keyManager: ShareIndexKeyManager())
        #expect(!exists(id, in: container))
    }

    @Test func sweep_keepsFreshWhileDeletingStale() throws {
        let container = try makeContainer()
        let fresh = try stage(in: container)
        let stale = try stage(in: container, createdAt: Date().addingTimeInterval(-ShareSession.staleAfter - 1))

        ShareSession.sweep(in: container, keyManager: ShareIndexKeyManager())
        #expect(exists(fresh, in: container))
        #expect(!exists(stale, in: container))
    }

    @Test func sweep_onMissingPendingDirectory_doesNotThrow() throws {
        let container = try makeContainer()
        ShareSession.sweep(in: container, keyManager: ShareIndexKeyManager())
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
