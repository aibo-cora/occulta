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
//  which is why the share path shipped with a missing lock gate (Bug 84) unnoticed. The key
//  is a parameter for the same reason: production passes `ShareStagingKeyManager`, whose
//  key lives in the Secure Enclave; tests pass an in-memory key and run without one.
//

import Foundation
import CryptoKit
import ImageIO
import UniformTypeIdentifiers
import OccultaFormats

/// What `ShareSession` needs from the share-staging key: it only ever opens what the
/// extension sealed.
protocol ShareSessionDecrypting {
    func decrypt(data: Data) throws -> Data
    /// The keys a streamed (`.eatt`) staged file could be sealed under, most likely first. The one that opens the file
    /// is found by its header (`AttachmentManager.opens(at:)`).
    func stagingKeys() -> [SymmetricKey]
}

extension ShareStagingKeyManager: ShareSessionDecrypting {
    func stagingKeys() -> [SymmetricKey] { self.openingKeys() }
}

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

    /// A staged session, read: the files for `encryptBundle`, and what opens the ones still on disk.
    struct Staged {
        /// Each file either carries its `content`, or a `url` to a sealed `.eatt` in the session directory.
        var files: [OccultaFormats.File]
        /// Opens the `url` files. Nil when none has one.
        let attachments: AttachmentManager?
    }

    /// Reads a staged session without decrypting its streamed files.
    ///
    /// Two formats, told apart by `AttachmentManager.isSealed` (STREAMING_SPEC §8.4). A file the extension staged
    /// as `.eatt` stays on disk, sealed, and is read a chunk at a time when it is sent: its `url` is returned and
    /// nothing is decrypted. A file staged by the build before this one is one AES-GCM blob, read and decrypted
    /// whole as it always was. Sessions are deleted after use, so the legacy reader can go in the next release.
    ///
    /// An image is decrypted either way, because its EXIF is stripped (below), and that needs the whole image.
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
    static func staged(
        id: String,
        in container: URL,
        keyManager: any ShareSessionDecrypting,
        now: Date = .now
    ) throws -> Staged {
        let sessionDir = self.directory(for: id, in: container)

        var files: [OccultaFormats.File] = []

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

            var attachments: AttachmentManager?
            var attachmentsKey: Int?
            let keys = keyManager.stagingKeys()
            for entry in manifest.files {
                let url = sessionDir.appendingPathComponent(entry.filename)
                let isImage = UTType(entry.uti)?.conforms(to: .image) == true
                let format = OccultaFormats.File.Format.file(OccultaFormats.File.Metadata(
                    name: UUID().uuidString,
                    extension: entry.fileExtension
                ))

                var content: Data
                if AttachmentManager.isSealed(at: url) {
                    // The key that opens it is the one whose header check passes. One manager serves every file that
                    // stays on disk; a file sealed under another key, which a session staged across a key change
                    // could hold, is read whole instead.
                    guard let (index, manager) = Self.opener(of: url, among: keys) else { throw AttachmentError.headerMACFailed }
                    if attachments == nil { attachments = manager; attachmentsKey = index }
                    guard isImage || index != attachmentsKey else {
                        files.append(OccultaFormats.File(url: url, format: format))
                        continue
                    }
                    content = try manager.plaintextBlocking(at: url)
                } else {
                    var ciphertext = try Data(contentsOf: url)
                    content = try keyManager.decrypt(data: ciphertext)
                    _ = ciphertext.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                    ciphertext = Data()
                }

                if isImage, let stripped = self.stripEXIF(from: content, uti: entry.uti) {
                    _ = content.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                    content = stripped
                }

                files.append(OccultaFormats.File(content: content, format: format))
            }
            return Staged(files: files, attachments: attachments)
        } catch {
            // Whatever was decrypted before the throw is heap plaintext with no owner.
            for i in files.indices {
                _ = files[i].content?.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            }
            self.delete(id: id, in: container)
            throw error
        }
    }

    /// The manager, and its place in `keys`, whose key opens the sealed file at `url`.
    private static func opener(of url: URL, among keys: [SymmetricKey]) -> (index: Int, manager: AttachmentManager)? {
        for (index, key) in keys.enumerated() {
            let manager = AttachmentManager(contactKey: key)
            if manager.opens(at: url) { return (index, manager) }
        }
        return nil
    }

    /// Decrypt a staged session into plaintext files, ready for `encryptBundle`. Every file is read into memory;
    /// `staged` leaves the streamed ones on disk.
    static func load(
        id: String,
        in container: URL,
        keyManager: any ShareSessionDecrypting,
        now: Date = .now
    ) throws -> [OccultaFormats.File] {
        var staged = try self.staged(id: id, in: container, keyManager: keyManager, now: now)
        do {
            for index in staged.files.indices {
                guard let url = staged.files[index].url, let attachments = staged.attachments else { continue }
                staged.files[index].content = try attachments.plaintextBlocking(at: url)
                staged.files[index].url = nil
            }
        } catch {
            for i in staged.files.indices {
                _ = staged.files[i].content?.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            }
            self.delete(id: id, in: container)
            throw error
        }
        return staged.files
    }

    // MARK: - Introduction card

    /// The staged file's bytes, if the session is one file and it is an introduction card (Q-04: a card has no
    /// name or extension, so the extension can't tell it from any other attachment; the app can, once unlocked).
    ///
    /// Reads nothing but the manifest and, when it names one small file, that file. Doesn't delete the session
    /// and doesn't throw: anything else, including a stale or unreadable session, is nil and the caller carries on
    /// as before.
    static func introductionCard(
        id: String,
        in container: URL,
        keyManager: any ShareSessionDecrypting,
        now: Date = .now
    ) -> Data? {
        let sessionDir = self.directory(for: id, in: container)

        guard
            let manifestData = try? keyManager.decrypt(data: Data(contentsOf: sessionDir.appendingPathComponent("manifest.enc"))),
            let manifest = try? JSONDecoder().decode(ShareManifest.self, from: manifestData),
            manifest.createdAt > now.addingTimeInterval(-Self.staleAfter),
            manifest.files.count == 1,
            let entry = manifest.files.first
        else { return nil }

        let file = sessionDir.appendingPathComponent(entry.filename)
        // The sealed file is a little longer than the card, so this keeps a large attachment from being read.
        guard
            let size = try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize,
            size >= IntroductionCard.byteCount, size <= IntroductionCard.byteCount + 1024
        else { return nil }

        // A file the extension staged as `.eatt`, or one the build before it sealed whole.
        let plaintext: Data?
        if AttachmentManager.isSealed(at: file) {
            plaintext = Self.opener(of: file, among: keyManager.stagingKeys()).flatMap { try? $0.manager.plaintextBlocking(at: file) }
        } else {
            plaintext = try? keyManager.decrypt(data: Data(contentsOf: file))
        }
        guard let plaintext, IntroductionCard.recognize(plaintext) != nil else { return nil }

        return plaintext
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
    static func sweep(in container: URL, keyManager: any ShareSessionDecrypting, now: Date = .now) {
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

    /// Delete `.occ` handoffs the app never read.
    ///
    /// The extension writes `inbound/<uuid>.occ` and opens the app, which reads and deletes it
    /// at once, holding the bytes in memory if it is locked. One older than `staleAfter` is a
    /// handoff whose open never reached the app; nothing else reads `inbound/`, so it would
    /// stay until Erase All Data, recording that someone sent the user an Occulta file.
    ///
    /// Judged by modification date: the file is sealed by its sender, so there is no manifest
    /// to read a date from.
    ///
    /// Leaves `inbound/` itself, even when empty (`forensic-trace-avoidance.md` U6).
    static func sweepInbound(in container: URL) {
        let fm = FileManager.default

        guard let files = try? fm.contentsOfDirectory(
            at: container.appendingPathComponent("inbound"),
            includingPropertiesForKeys: [.contentModificationDateKey]
        ) else { return }

        let cutoff = Date.now.addingTimeInterval(-Self.staleAfter)

        for file in files where file.pathExtension == "occ" {
            let modified = try? file.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
            if let modified, modified < cutoff {
                try? fm.removeItem(at: file)
            }
        }
    }

    /// Delete `ShareIndex.sqlite` and its companions, left behind by builds before the picker
    /// moved into the app.
    ///
    /// Not merely tidiness. The rows are AES-GCM sealed, but the file's existence, its row
    /// count, its sizes, and its mtime are relationship metadata sitting in the App Group with
    /// no reader — precisely the kind of residue `forensic-trace-avoidance.md` exists to
    /// prevent. The SE key stays: staged files and manifests are still sealed with it.
    ///
    /// Runs on every foreground rather than behind a one-shot flag. It is three `removeItem`
    /// calls against paths that are absent after the first pass, and a migration marker would
    /// itself be a new artifact recording when this build was first run.
    static func removeLegacyContactIndex(in container: URL) {
        for name in ["ShareIndex.sqlite", "ShareIndex.sqlite-wal", "ShareIndex.sqlite-shm"] {
            try? FileManager.default.removeItem(at: container.appendingPathComponent(name))
        }
    }

    /// Delete everything the share extension has left in the App Group. Erase All Data calls
    /// this before it deletes the share-staging key.
    ///
    /// - `pending/` — staged sessions, including fresh ones `sweep` would keep
    /// - `inbound/` — `.occ` handoffs, including fresh ones `sweepInbound` would keep
    /// - the legacy contact index
    ///
    /// Removes the two directories themselves, not just what is in them. The extension
    /// creates each one on first use, so its creation date records the first share into
    /// Occulta just as the key's does.
    static func removeAll(in container: URL) {
        for name in ["pending", "inbound"] {
            try? FileManager.default.removeItem(at: container.appendingPathComponent(name))
        }
        self.removeLegacyContactIndex(in: container)
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

        // `kCFNull` imports as `CFNull!`. Dropping it straight into an `Any` slot stores
        // `Optional<CFNull>` rather than the sentinel itself — the compiler warns, and
        // ImageIO would not recognise the wrapped value as a removal instruction. Bind it
        // once with an explicit type so the unwrap happens in one place.
        let remove: CFNull = kCFNull

        var overrides: [CFString: Any] = [
            kCGImagePropertyExifDictionary:       remove,
            kCGImagePropertyExifAuxDictionary:    remove,
            kCGImagePropertyGPSDictionary:        remove,
            kCGImagePropertyIPTCDictionary:       remove,
            kCGImagePropertyTIFFDictionary:       remove,
            kCGImagePropertyMakerAppleDictionary: remove
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
