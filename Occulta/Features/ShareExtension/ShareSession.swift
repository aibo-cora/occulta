//
//  ShareSession.swift
//  Occulta
//
//  Lifecycle of a share-extension staging session: read, sweep, delete.
//  Main app only — the extension writes these directories, it never reads them back.
//
//  Every entry point takes the container URL rather than resolving the App Group itself,
//  so the whole lifecycle can be exercised against a temp directory in tests. The version
//  of this code that lived as a private method on `RootView` could not be tested at all,
//  which is why the share path shipped with a missing lock gate (Bug 84) unnoticed.
//

import Foundation
import ImageIO
import UniformTypeIdentifiers

enum ShareSession {

    /// Same cutoff `sweep` applies. A session older than this is refused rather than
    /// processed — guards against a re-tapped notification or a duplicate deep-link
    /// delivery reprocessing a session (SecurityReview2026-07-24, finding #11).
    static let staleAfter: TimeInterval = 3600

    enum Errors: Swift.Error, LocalizedError {
        case stale

        var errorDescription: String? {
            switch self {
            case .stale: "This share session has expired. Please share the content again."
            }
        }
    }

    // MARK: - Locations

    /// The App Group container both processes stage into.
    static var sharedContainer: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
    }

    static func directory(for id: String, in container: URL) -> URL {
        container
            .appendingPathComponent("pending")
            .appendingPathComponent(id)
    }

    // MARK: - Load

    /// Decrypt a staged session into plaintext files, ready for `encryptBundle`.
    ///
    /// Deletes the session directory on **any** throw. The caller deletes it on the success
    /// and cancellation paths, but the guarantee that a failed load leaves no plaintext on
    /// disk belongs here rather than in caller discipline — this is the function that knows
    /// the plaintext is there.
    ///
    /// Images are EXIF-stripped before they are returned, so location and camera metadata
    /// never reach the sealed payload. A format `CGImageSource` cannot parse is passed
    /// through unchanged: the metadata then stays inside the encrypted bundle, visible only
    /// to the recipient.
    static func load(
        id: String,
        in container: URL,
        keyManager: ShareIndexKeyManager,
        now: Date = .now
    ) throws -> [Occulta.File] {
        let sessionDir = self.directory(for: id, in: container)

        var files: [Occulta.File] = []

        do {
            var manifestData = try keyManager.decrypt(
                data: Data(contentsOf: sessionDir.appendingPathComponent("manifest.enc"))
            )
            let manifest = try JSONDecoder().decode(ShareManifest.self, from: manifestData)

            // Zero the plaintext manifest as soon as it is decoded.
            _ = manifestData.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            manifestData = Data()

            guard manifest.createdAt > now.addingTimeInterval(-Self.staleAfter) else {
                throw Errors.stale
            }

            for entry in manifest.files {
                var ciphertext = try Data(contentsOf: sessionDir.appendingPathComponent(entry.filename))
                var content = try keyManager.decrypt(data: ciphertext)
                _ = ciphertext.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                ciphertext = Data()

                if UTType(entry.uti)?.conforms(to: .image) == true,
                   let stripped = self.stripEXIF(from: content, uti: entry.uti) {
                    _ = content.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                    content = stripped
                }

                files.append(Occulta.File(
                    content: content,
                    format: .file(Occulta.File.Metadata(
                        name: UUID().uuidString,
                        extension: entry.fileExtension
                    ))
                ))
            }
        } catch {
            // Whatever was decrypted before the throw is heap plaintext with no owner.
            for i in files.indices {
                _ = files[i].content?.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            }
            self.delete(id: id, in: container)
            throw error
        }

        return files
    }

    // MARK: - Cleanup

    static func delete(id: String, in container: URL) {
        try? FileManager.default.removeItem(at: self.directory(for: id, in: container))
    }

    /// Delete stale or half-written sessions.
    ///
    /// - a manifest older than `staleAfter` → delete
    /// - no manifest (extension killed mid-write) → delete immediately; those files are plaintext
    /// - an unreadable manifest (corrupt or orphaned) → delete immediately
    static func sweep(in container: URL, keyManager: ShareIndexKeyManager, now: Date = .now) {
        let fm = FileManager.default

        guard let sessions = try? fm.contentsOfDirectory(
            at: container.appendingPathComponent("pending"),
            includingPropertiesForKeys: nil
        ) else { return }

        let cutoff = now.addingTimeInterval(-Self.staleAfter)

        for sessionDir in sessions where sessionDir.hasDirectoryPath {
            let manifestURL = sessionDir.appendingPathComponent("manifest.enc")

            if let encrypted = try? Data(contentsOf: manifestURL),
               let plaintext = try? keyManager.decrypt(data: encrypted),
               let manifest  = try? JSONDecoder().decode(ShareManifest.self, from: plaintext),
               manifest.createdAt > cutoff {
                continue
            }

            try? fm.removeItem(at: sessionDir)
        }
    }

    // MARK: - Private

    /// Strip EXIF, GPS, and camera metadata using CGImageSource/CGImageDestination.
    ///
    /// **The properties dictionary must name each dictionary to remove, with `kCFNull`.**
    /// `CGImageDestinationAddImageFromSource` treats its properties argument as a set of
    /// *overrides* onto what the source already carries — so the `[:]` this used to pass
    /// meant "override nothing", and every byte of EXIF and GPS was copied to the output
    /// unchanged. `ShareSessionTests.load_stripsEXIFFromImages` is what caught it.
    ///
    /// Orientation is deliberately carried over: it is display information rather than
    /// provenance, and dropping it leaves portrait photos lying on their side.
    private static func stripEXIF(from imageData: Data, uti: String) -> Data? {
        guard let source = CGImageSourceCreateWithData(imageData as CFData, nil) else { return nil }

        let destData = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            destData, uti as CFString, 1, nil
        ) else { return nil }

        var overrides: [CFString: Any] = [
            kCGImagePropertyExifDictionary:       kCFNull,
            kCGImagePropertyExifAuxDictionary:    kCFNull,
            kCGImagePropertyGPSDictionary:        kCFNull,
            kCGImagePropertyIPTCDictionary:       kCFNull,
            kCGImagePropertyTIFFDictionary:       kCFNull,
            kCGImagePropertyMakerAppleDictionary: kCFNull
        ]

        if let properties  = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
           let orientation = properties[kCGImagePropertyOrientation] {
            overrides[kCGImagePropertyOrientation] = orientation
        }

        CGImageDestinationAddImageFromSource(destination, source, 0, overrides as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { return nil }

        return destData as Data
    }
}
