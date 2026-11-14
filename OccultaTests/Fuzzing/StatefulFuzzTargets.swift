//
//  StatefulFuzzTargets.swift
//  OccultaTests
//
//  The entry points that do more than decode: they read a file, keep a session, or touch the store. For these
//  the question is the same as for a decoder (does it trap, hang or balloon) and one more: **does a malformed
//  input leave anything behind?** The app must not leave a trace that something hostile was received, so each
//  target also checks what a refused input left.
//
//  - `ShareSessionTarget`: the share extension's staged files and manifest, read back by the app. A failed read
//    must delete the session, since the files in it are plaintext.
//  - `ExchangeSessionTarget`: a nearby phone's messages through `ExchangeManager.handleReceivedData`, which its
//    `MCSessionDelegate` calls. A refused message must not move the exchange.
//  - `StreamedReceiveTarget`: a streamed `.occ` file through the real receive path, as far as a stranger with no
//    key can take it. A refused file must not touch the sender's record or spend a prekey.
//
//  All run on the main actor (`Fuzzer.runOnMainActor`): everything they call is isolated to it.
//

import Foundation
import CryptoKit
import SwiftData
import ImageIO
import UniformTypeIdentifiers
import MultipeerConnectivity
@testable import Occulta
@testable import OccultaFormats

// MARK: - Share extension staging

/// `ShareSession.staged`, on files and manifests the extension would stage, and on ones it never would.
///
/// The extension seals whatever the user shares, so the file's bytes are the sharing app's, not ours. An image goes
/// to ImageIO to strip its EXIF, which makes the staged file an attack surface on the system's image decoders.
///
/// The input is a selector byte (which file type to stage it as) and the file's bytes.
@MainActor
struct ShareSessionTarget: MainActorFuzzTarget {
    let name = "ShareSession.staged (shared file content)"

    private static let types: [(uti: String, ext: String)] = [
        ("public.jpeg", "jpg"), ("public.png", "png"), ("com.compuserve.gif", "gif"), ("public.tiff", "tiff"),
        ("com.adobe.pdf", "pdf"), ("public.plain-text", "txt"), ("public.data", "bin"),
    ]

    var corpus: [FuzzSeedInput] {
        var seeds: [FuzzSeedInput] = []
        for (index, format) in [UTType.jpeg, .png, .gif, .tiff].enumerated() {
            if let image = Self.image(as: format) { seeds.append(FuzzSeedInput("\(format.identifier) with metadata", Data([UInt8(index)]) + image)) }
        }
        seeds.append(FuzzSeedInput("pdf", Data([4]) + Data("%PDF-1.1\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF".utf8)))
        seeds.append(FuzzSeedInput("text", Data([5]) + Data("hello".utf8)))
        return seeds
    }

    func run(_ input: Data) throws {
        let container = FileManager.default.temporaryDirectory.appendingPathComponent("fuzz-share-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: container) }

        let selector = Int(input.first ?? 0) % Self.types.count
        let type = Self.types[selector]
        let id = try FuzzShareStaging.stage(content: Data(input.dropFirst()), uti: type.uti, ext: type.ext, in: container)

        do {
            let staged = try ShareSession.staged(id: id, in: container, keyManager: FuzzShareStaging.key)
            guard staged.files.count == 1 else { throw FuzzViolation("staged one file and got \(staged.files.count)") }
        } catch let error as FuzzViolation {
            throw error
        } catch {
            // A refusal. The files in the session are plaintext, so a refusal must have removed them.
            guard !FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: container).path) else {
                throw FuzzViolation("a refused session was left on disk")
            }
            throw error
        }
    }

    /// A 2x2 image carrying EXIF and GPS, in `format`.
    static func image(as format: UTType) -> Data? {
        var pixels = [UInt8](repeating: 0x7F, count: 2 * 2 * 4)
        guard let context = CGContext(
            data: &pixels, width: 2, height: 2, bitsPerComponent: 8, bytesPerRow: 8,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ), let image = context.makeImage() else { return nil }
        let out = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(out, format.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(destination, image, [
            kCGImagePropertyOrientation: 6,
            kCGImagePropertyGPSDictionary: [kCGImagePropertyGPSLatitude: 51.5, kCGImagePropertyGPSLatitudeRef: "N"] as CFDictionary,
        ] as CFDictionary)
        return CGImageDestinationFinalize(destination) ? out as Data : nil
    }
}

/// The manifest side: `manifest.enc` is JSON the extension sealed, read by `staged`, `introductionCard` and `sweep`.
@MainActor
struct ShareManifestSessionTarget: MainActorFuzzTarget {
    let name = "ShareSession (manifest)"

    var corpus: [FuzzSeedInput] {
        let encoder = JSONEncoder()
        let manifest = ShareManifest(files: [ShareManifest.FileEntry(filename: "0.tmp", uti: "public.plain-text", fileExtension: "txt")], createdAt: .now)
        return [FuzzSeedInput("manifest", try! encoder.encode(manifest), isText: true)]
    }

    func run(_ input: Data) throws {
        let container = FileManager.default.temporaryDirectory.appendingPathComponent("fuzz-share-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: container) }

        let id = try FuzzShareStaging.stage(content: Data("hello".utf8), uti: "public.plain-text", ext: "txt", in: container, manifest: input)
        let directory = ShareSession.directory(for: id, in: container)

        // Neither of these throws or deletes: they answer "is this a card" and "should this session go".
        _ = ShareSession.introductionCard(id: id, in: container, keyManager: FuzzShareStaging.key)
        guard FileManager.default.fileExists(atPath: directory.path) else { throw FuzzViolation("introductionCard deleted the session") }

        do {
            _ = try ShareSession.staged(id: id, in: container, keyManager: FuzzShareStaging.key)
        } catch {
            guard !FileManager.default.fileExists(atPath: directory.path) else { throw FuzzViolation("a refused session was left on disk") }
            throw error
        }

        // The sweep's verdict on a manifest it can't read is delete, at once: nothing unreadable stays.
        let again = try FuzzShareStaging.stage(content: Data("hello".utf8), uti: "public.plain-text", ext: "txt", in: container, manifest: input)
        ShareSession.sweep(in: container, keyManager: FuzzShareStaging.key)
        if (try? BoundedJSON.decode(ShareManifest.self, from: input)) == nil,
           FileManager.default.fileExists(atPath: ShareSession.directory(for: again, in: container).path) {
            throw FuzzViolation("sweep kept a session whose manifest does not decode")
        }
    }
}

/// A staged session built the way the extension builds one.
@MainActor
enum FuzzShareStaging {

    struct Key: ShareSessionDecrypting {
        fileprivate static let symmetric = SymmetricKey(size: .bits256)

        func encrypt(data: Data) throws -> Data {
            try AES.GCM.seal(data, using: Self.symmetric, nonce: AES.GCM.Nonce()).combined!
        }
        func decrypt(data: Data) throws -> Data {
            try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: Self.symmetric)
        }
        func stagingKeys() -> [SymmetricKey] { [Self.symmetric] }
    }

    static let key = Key()

    /// Writes one staged file and a sealed manifest. `manifest` replaces the manifest's plaintext.
    static func stage(content: Data, uti: String, ext: String, in container: URL, manifest: Data? = nil) throws -> String {
        let id = UUID().uuidString
        let directory = ShareSession.directory(for: id, in: container)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Self.key.encrypt(data: content).write(to: directory.appendingPathComponent("0.tmp"))

        let plaintext = try manifest ?? JSONEncoder().encode(ShareManifest(
            files: [ShareManifest.FileEntry(filename: "0.tmp", uti: uti, fileExtension: ext)], createdAt: .now
        ))
        try Self.key.encrypt(data: plaintext).write(to: directory.appendingPathComponent("manifest.enc"))
        return id
    }
}

// MARK: - A nearby phone's messages

/// Messages from the peer an exchange is pinned to, handed to `ExchangeManager.handleReceivedData`: the method the
/// `MCSessionDelegate`'s `session(_:didReceive:fromPeer:)` calls from the main queue.
///
/// The manager is built without `start()`, so nothing advertises. It has no exchange in progress, so an identity
/// message is buffered and a ciphertext is ignored: what is under test is the path from bytes to those decisions. The
/// peer is pinned through the real delegate once, by `pin()`, which the caller awaits before the cases run.
@MainActor
final class ExchangeSessionTarget: MainActorFuzzTarget {
    let name = "ExchangeManager.handleReceivedData"

    private let manager = ExchangeManager()
    private let peer = MCPeerID(displayName: "fuzz-peer")
    private var pinnedPhase: ExchangeManager.ExchangePhase?

    var corpus: [FuzzSeedInput] { AppFuzzTargets.exchangeSeeds() }

    init() {
        self.manager.multipeerSession = MCSession(peer: MCPeerID(displayName: "fuzz-self-\(UUID().uuidString)"))
    }

    /// Connects the peer through the delegate, which hands the event to the main queue. Awaiting is what lets the main
    /// queue run: a block queued from inside a main-queue block waits for that block to end.
    func pin() async {
        guard let session = self.manager.multipeerSession else { return }
        self.manager.session(session, peer: self.peer, didChange: .connected)
        await withCheckedContinuation { continuation in DispatchQueue.main.async { continuation.resume() } }
        self.pinnedPhase = self.manager.phase
    }

    func run(_ input: Data) throws {
        guard self.manager.connectedPeerID == self.peer, let pinned = self.pinnedPhase else { throw FuzzViolation("the peer is not pinned: call pin() first") }

        self.manager.handleReceivedData(input, from: self.peer)

        guard self.manager.connectedPeerID == self.peer else { throw FuzzViolation("a message moved the pinned peer") }
        guard self.manager.phase == pinned else { throw FuzzViolation("a message moved the exchange to \(self.manager.phase)") }
        if let proof = self.manager.peerCardProof, proof.count != 64 { throw FuzzViolation("a card proof of \(proof.count) bytes was kept") }
    }
}

// MARK: - A streamed file through the receive path

/// A streamed `.occ` as a stranger can send it: the header, the group envelope, a chunk stream. Read from a file the
/// way the app reads one (`NoCacheFile`, `StreamedBody`), then through sender identification and slot opening.
///
/// The stranger holds no key, so a mutated file almost never opens; the question is what each refusal costs.
/// Run it under `.ambientTestKeyManager`, which stands in for the device's keys.
@MainActor
final class StreamedReceiveTarget: MainActorFuzzTarget {
    let name = "Streamed .occ receive (identify and open)"

    private let contactManager: ContactManager
    private let seedBytes: [(name: String, bytes: Data)]

    init() throws {
        let alice = TestKeyManager()
        let contactManager = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "alice", publicKey: try alice.retrieveIdentity(), in: contactManager)
        self.contactManager = contactManager

        let device = GroupRecipient(
            publicKey: try Manager.Ambient.keyManager.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil
        )
        let directory = try streamedScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        var seeds: [(String, Data)] = []
        for (label, files) in [
            ("text only", [inlineTextEntry("hello")]),
            ("text and a streamed file", [inlineTextEntry("hello"), streamedEntry("clip", streamedPattern(300))]),
        ] {
            let url = directory.appendingPathComponent("\(label).occ")
            _ = try writeStreamedBundle(to: url, from: alice, recipients: [device], files: files)
            seeds.append((label, try Data(contentsOf: url)))
        }
        self.seedBytes = seeds
    }

    var corpus: [FuzzSeedInput] {
        self.seedBytes.map { FuzzSeedInput($0.name, $0.bytes, lengthFields: FuzzLayout.envelope($0.bytes)) }
            // Inline bundles from a sender this phone doesn't know: they go as far as `redeemCard` and no further.
            + FuzzVectors.entries(ofKind: "groupEnvelope", "envelope").map {
                FuzzSeedInput($0.name, $0.bytes, lengthFields: FuzzLayout.envelope($0.bytes), isValid: false)
            }
    }

    func run(_ input: Data) throws {
        let directory = try streamedScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("m.occ")
        try input.write(to: url)

        let before = try self.snapshot()
        do {
            // What `handleOpenURL` and `processInboundFile` do with a file, up to the first key.
            switch try InboundFile.open(url) {
            case .streamed(let reader):
                let body = try StreamedBody(reader: reader)
                _ = try body.digest()
                let ownerID = try self.contactManager.identifyOwner(of: body.bundle, body: .streamed(body))
                _ = try self.contactManager.openGroup(bundle: body.bundle, body: .streamed(body), ownerID: ownerID)

            case .mapped(let data):
                // A card first, then a bundle, as `processInboundFile` and `buildOwnedBasket` do.
                if IntroductionCard.recognize(data) != nil { return }
                try MemoryGuard.system.checkReceive(bundleLength: data.count)
                let bundle = try OccultaBundle.decoded(from: data)
                let ownerID = try self.contactManager.identifyOwner(of: bundle)
                if bundle.group != nil {
                    _ = try self.contactManager.openGroup(bundle: bundle, body: .inline(bundle), ownerID: ownerID)
                } else {
                    _ = try self.contactManager.decryptSealed(bundle: bundle)
                }
            }
        } catch {
            // Refused. The record of the one contact this phone has must be exactly as it was: no prekey
            // spent, no capability tier moved, nothing re-sealed.
            guard try self.snapshot() == before else { throw FuzzViolation("a refused file changed the sender's record (\(error))") }
            guard !self.contactManager.modelContext.hasChanges else { throw FuzzViolation("a refused file left unsaved changes in the store (\(error))") }
            throw error
        }
    }

    private func snapshot() throws -> [Data?] {
        guard let sender = try self.contactManager.fetchContact(by: "alice") else { throw FuzzViolation("the sender is gone") }
        return [sender.prekeyRecordEncrypted, sender.maxBundleVersion, sender.introductionCardEncrypted]
    }
}
