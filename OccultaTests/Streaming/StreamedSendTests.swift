//
//  StreamedSendTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §3, §8.3 and §10: which layout a send uses, and that what it writes opens on the other side.
//  We are the ambient identity; `bob` and `carol` are other phones, which open what we send with their own keys.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

private let C = BodyStream.chunkSize

private func ourPublicKey() throws -> Data { try Manager.Ambient.keyManager.retrieveIdentity() }

/// A staged `.eatt`, sealed as compose seals one.
private func stageFile(_ plaintext: Data, in dir: URL, using manager: AttachmentManager, ext: String = "mp4") throws -> OccultaFormats.File {
    let url = dir.appendingPathComponent("\(UUID().uuidString).eatt")
    let encryptor = try manager.streamingEncryptor(to: url)
    var offset = 0
    while offset < plaintext.count {
        let end = min(offset + 65_536, plaintext.count)
        try encryptor.append(plaintext[offset..<end])
        offset = end
    }
    try encryptor.finalize()
    return OccultaFormats.File(url: url, format: .file(.init(name: "clip", extension: ext)), date: Date(timeIntervalSinceReferenceDate: 10))
}

private final class Collector: StreamSink {
    var files: [Int: Data] = [:]
    private var current = -1
    func begin(fileIndex: Int) throws { self.current = fileIndex; self.files[fileIndex] = Data() }
    func write(_ data: Data) throws { self.files[self.current, default: Data()].append(data) }
    func end() throws {}
}

/// What a phone does with a bundle in a file: its slot, its manifest and its streamed files, whichever the layout.
private struct Received {
    let layout: BundleLayout
    let sealed: OccultaBundle.SealedPayload
    let basket: Basket?
    /// Each streamed file's bytes by index in the basket, empty for the inline layout.
    let streamed: [Int: Data]
    let versionByte: UInt8
}

@MainActor
private func open(_ url: URL, on phone: TestKeyManager) throws -> Received {
    let bytes = try NoCacheFile.reader(url)
    let head = try bytes.read(at: 0, count: WireHandle.headerLength)
    let versionByte = head[4]
    let crypto = Manager.Crypto(keyManager: phone)

    if versionByte == WireHandle.streamedVersionByte {
        let body = try StreamedBody(reader: bytes)
        let (slot, _, _) = try crypto.findAndOpenRecipientSlot(
            in: body.bundle, blind: try #require(body.bundle.group).blind, senderContactID: "us",
            senderPublicKey: try ourPublicKey(), quantumMaterial: nil, prekeys: Manager.PrekeySecretsManager(),
            body: .streamed(body)
        )
        let opened = try BundleBody.streamed(body).openManifest(sessionKey: SymmetricKey(data: slot.sessionKey))
        let cursor = try #require(opened.cursor)
        guard !opened.payload.message.isEmpty, let decoded = try? WireHandle.decode(streamedBasket: opened.payload.message) else {
            return Received(layout: .streamed, sealed: opened.payload, basket: nil, streamed: [:], versionByte: versionByte)
        }
        try cursor.validate(streamedLengths: decoded.streamedLengths)
        let sink = Collector()
        try body.streamFiles(cursor: cursor, streamedLengths: decoded.streamedLengths, sink: sink)
        return Received(layout: .streamed, sealed: opened.payload, basket: decoded.basket, streamed: sink.files, versionByte: versionByte)
    }

    let bundle = try OccultaBundle.decoded(from: try Data(contentsOf: url))
    let (slot, _, _) = try crypto.findAndOpenRecipientSlot(
        in: bundle, blind: try #require(bundle.group).blind, senderContactID: "us",
        senderPublicKey: try ourPublicKey(), quantumMaterial: nil, prekeys: Manager.PrekeySecretsManager()
    )
    let sealed = try WireHandle.decode(payload: try crypto.openGroupCiphertext(bundle, using: SymmetricKey(data: slot.sessionKey)))
    return Received(
        layout: .inline, sealed: sealed, basket: sealed.identityChallenge != nil || sealed.message.isEmpty ? nil : try WireHandle.decode(basket: sealed.message),
        streamed: [:], versionByte: versionByte
    )
}

private func outputURL(_ dir: URL) -> URL { dir.appendingPathComponent("\(UUID().uuidString).occ") }

// MARK: - Tier

@Suite("The streamed tier")
struct StreamedTierTests {

    @Test("2.0.0 resolves to it, and it is at least the digest tier")
    func tierStartsAt2() {
        #expect(OccultaBundle.Version.max(forAppVersion: "2.0.0") == .streamedBodyCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "2.3.1") == .streamedBodyCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.11.1") == .prefixedSenderSignatureCapable)
        #expect(OccultaBundle.Version.streamedBodyCapable.isAtLeast(.bodyDigestCapable))
        #expect(!OccultaBundle.Version.bodyDigestCapable.isAtLeast(.streamedBodyCapable))
        #expect(OccultaBundle.Version.mostCapable == .streamedBodyCapable)
        #expect(OccultaBundle.Version.highestKnownWireByte == 0x0A)
        #expect(OccultaBundle.Version.streamedBodyCapable.minimumAppVersion == "2.0.0")
    }

    @Test("every tier's marker byte maps back to it, the streamed one included")
    func everyTierRoundTrips() {
        let tiers: [OccultaBundle.Version] = [
            .streamedBodyCapable, .bodyDigestCapable, .prefixedSenderSignatureCapable, .senderSignatureCapable,
            .groupShardCapable, .groupCapable, .v4
        ]
        for tier in tiers {
            #expect(tier.wireByte.flatMap(WireHandle.byteToVersion) == tier, "\(tier)")
        }
    }

    @Test("a contact recorded at 0x0A reads as the streamed tier, never as the floor", .ambientTestKeyManager)
    @MainActor func recordedAtTheTier() throws {
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try TestKeyManager().retrieveIdentity(), marker: .streamedBodyCapable, in: cm)
        let bob = try #require(try cm.fetchContact(by: "bob"))

        let tier = ContactManager.resolveTargetVersion(for: bob, using: Manager.Crypto())

        #expect(tier == .streamedBodyCapable)
        #expect(tier.isAtLeast(.bodyDigestCapable) && tier.isAtLeast(.streamedBodyCapable))
    }

    @Test("a byte above 0x0A is read as a newer build, and sent the streamed layout", .ambientTestKeyManager)
    @MainActor func newerThanUs() throws {
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try TestKeyManager().retrieveIdentity(), in: cm)
        let bob = try #require(try cm.fetchContact(by: "bob"))
        bob.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([0x0B]))

        #expect(ContactManager.resolveTargetVersion(for: bob, using: Manager.Crypto()) == .streamedBodyCapable)
    }
}

// MARK: - One recipient

@Suite("Streamed send — one contact")
@MainActor struct StreamedSendContactTests {

    let bob = TestKeyManager()

    private func fixture(marker: OccultaBundle.Version?, in dir: URL) throws -> ContactManager {
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try self.bob.retrieveIdentity(), marker: marker, in: cm)
        return cm
    }

    private func send(
        _ basket: Basket, to cm: ContactManager, attachments: AttachmentManager?, dir: URL,
        memoryGuard: MemoryGuard = .system
    ) throws -> (layout: BundleLayout, url: URL) {
        let url = outputURL(dir)
        let layout = try cm.encryptBundle(
            basket: basket, for: "bob", output: .file(destination: url, attachments: attachments, memoryGuard: memoryGuard)
        )
        return (layout, url)
    }

    @Test("a recipient at the tier gets the streamed layout, which opens, with the files they were sent", .ambientTestKeyManager)
    func streamedToCapableRecipient() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let video = streamedPattern(3 * C + 17, seed: 2)
        let photo = streamedPattern(900, seed: 3)
        let basket = Basket(files: [
            inlineTextEntry("lunch at one").file,
            try stageFile(video, in: dir, using: manager),
            try stageFile(photo, in: dir, using: manager, ext: "txt"),
        ])
        let cm = try self.fixture(marker: .streamedBodyCapable, in: dir)

        let (layout, url) = try self.send(basket, to: cm, attachments: manager, dir: dir)

        #expect(layout == .streamed)
        let received = try open(url, on: self.bob)
        #expect(received.layout == .streamed && received.versionByte == 0x0A)
        #expect(received.sealed.appVersion == Bundle.main.appVersion)
        let files = try #require(received.basket?.files)
        #expect(files.count == 3)
        #expect(received.streamed[1] == video && received.streamed[2] == photo)
        #expect(String(data: try #require(files[0].content), encoding: .utf8) == "lunch at one")
    }

    @Test("the file on disk is ciphertext, and holds no run of the plaintext", .ambientTestKeyManager)
    func fileIsCiphertext() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let marker = Data("SENT-MARKER-\(UUID().uuidString)".utf8)
        var plaintext = Data()
        while plaintext.count < 2 * C { plaintext.append(marker) }
        let cm = try self.fixture(marker: .streamedBodyCapable, in: dir)

        let (_, url) = try self.send(Basket(files: [try stageFile(plaintext, in: dir, using: manager)]), to: cm, attachments: manager, dir: dir)

        #expect(try Data(contentsOf: url).range(of: marker) == nil)
        #expect(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test("a recipient below the tier gets the inline layout, with the staged file read into it", .ambientTestKeyManager,
          arguments: [OccultaBundle.Version.bodyDigestCapable, .prefixedSenderSignatureCapable, .groupCapable])
    func inlineToOlderRecipient(marker: OccultaBundle.Version) throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let video = streamedPattern(C + 40, seed: 5)
        let cm = try self.fixture(marker: marker, in: dir)

        let (layout, url) = try self.send(Basket(files: [try stageFile(video, in: dir, using: manager)]), to: cm, attachments: manager, dir: dir)

        #expect(layout == .inline)
        let received = try open(url, on: self.bob)
        #expect(received.layout == .inline && received.versionByte == 0x04)
        #expect(received.basket?.files.first?.content == video)
    }

    @Test("a recipient with no tier recorded, or a stranded one, gets the inline layout", .ambientTestKeyManager)
    func inlineWhenUnknown() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let file = try stageFile(streamedPattern(500), in: dir, using: manager)

        let unrecorded = try self.fixture(marker: nil, in: dir)
        #expect(try self.send(Basket(files: [file]), to: unrecorded, attachments: manager, dir: dir).layout == .inline)

        let stranded = try self.fixture(marker: nil, in: dir)
        try #require(try stranded.fetchContact(by: "bob")).maxBundleVersion = Data((0..<60).map { _ in .random(in: .min ... .max) })
        #expect(try self.send(Basket(files: [file]), to: stranded, attachments: manager, dir: dir).layout == .inline)
    }

    @Test("a text-only message takes the same layout as one with a file", .ambientTestKeyManager)
    func layoutSaysNothingAboutContent() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let cm = try self.fixture(marker: .streamedBodyCapable, in: dir)

        let (layout, url) = try self.send(Basket(files: [inlineTextEntry("hi").file]), to: cm, attachments: nil, dir: dir)

        #expect(layout == .streamed)
        #expect(try open(url, on: self.bob).basket?.files.count == 1)
    }

    @Test("an identity challenge takes the layout of a message to the same contact, with only a manifest", .ambientTestKeyManager)
    func challengeFollowsTheLayout() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let challenge = IdentityChallengeEnvelope.challenge(payload: Data(count: 72), contextNote: "Was this you?")

        for (marker, expected) in [(OccultaBundle.Version.streamedBodyCapable, BundleLayout.streamed), (.bodyDigestCapable, .inline)] {
            let cm = try self.fixture(marker: marker, in: dir)
            let url = outputURL(dir)
            let layout = try cm.encryptBundle(
                for: "bob", identityChallenge: challenge, output: .file(destination: url, attachments: nil, memoryGuard: .system)
            )
            #expect(layout == expected)
            let received = try open(url, on: self.bob)
            #expect(received.sealed.identityChallenge?.kind == .challenge)
            #expect(received.sealed.identityChallenge?.contextNote == "Was this you?")
        }
    }

    @Test("a file in memory is streamed from there, for a send that has no staged file", .ambientTestKeyManager)
    func streamsFromMemory() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let content = streamedPattern(2 * C + 3, seed: 7)
        let cm = try self.fixture(marker: .streamedBodyCapable, in: dir)
        let file = OccultaFormats.File(content: content, format: .file(.init(name: "a", extension: "bin")), date: Date())

        let (layout, url) = try self.send(Basket(files: [file]), to: cm, attachments: nil, dir: dir)

        #expect(layout == .streamed)
        #expect(try open(url, on: self.bob).streamed[0] == content)
    }

    @Test("sending to memory still returns the inline layout, as callers without files rely on", .ambientTestKeyManager)
    func memoryOutputIsInline() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let cm = try self.fixture(marker: .streamedBodyCapable, in: dir)

        let data = try cm.encryptBundle(basket: Basket(files: [inlineTextEntry("hi").file]), for: "bob")

        #expect(data[4] == 0x04)
    }

    // MARK: The memory guard binds only the inline layout

    @Test("the guard refuses an inline send before any prekey is taken or file written, and is not asked of a streamed one",
          .ambientTestKeyManager)
    func guardOnlyBindsInline() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let file = try stageFile(streamedPattern(2 * C), in: dir, using: manager)
        let tiny = MemoryGuard { 10 * 1024 * 1024 }

        // Inline: refused, and nothing changed.
        let inline = try self.fixture(marker: .bodyDigestCapable, in: dir)
        let before = try #require(try inline.fetchContact(by: "bob")).prekeyRecordEncrypted
        let refused = outputURL(dir)
        #expect(throws: MemoryGuard.SendRefusal.tooLargeToSend) {
            try inline.encryptBundle(basket: Basket(files: [file]), for: "bob",
                                     output: .file(destination: refused, attachments: manager, memoryGuard: tiny))
        }
        #expect(!FileManager.default.fileExists(atPath: refused.path))
        #expect(try #require(try inline.fetchContact(by: "bob")).prekeyRecordEncrypted == before)

        // Streamed: the same tiny guard, and it goes through.
        let streamed = try self.fixture(marker: .streamedBodyCapable, in: dir)
        let (layout, _) = try self.send(Basket(files: [file]), to: streamed, attachments: manager, dir: dir, memoryGuard: tiny)
        #expect(layout == .streamed)
    }

    // MARK: A source that disagrees with its length

    @Test("a streamed source that delivers other than its length fails the send and leaves no file", .ambientTestKeyManager,
          arguments: [-1, 1])
    func sourceLengthMismatch(delta: Int) throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = outputURL(dir)
        let content = streamedPattern(1000)
        let source = StreamedFileSource(length: UInt64(1000 + delta)) { emit in try emit(content) }
        let recipient = GroupRecipient(publicKey: try self.bob.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)

        #expect(throws: BodyStream.StreamError.self) {
            try Manager.Crypto().sealStreamed(
                sealedPayload: OccultaBundle.SealedPayload(message: Data("m".utf8)), groupID: UUID(),
                recipients: [recipient], files: StreamedFiles(destination: url, sources: [source])
            )
        }
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }
}

// MARK: - A named group

@Suite("Streamed send — a group")
@MainActor struct StreamedSendGroupTests {

    let bob = TestKeyManager()
    let carol = TestKeyManager()

    private func group(_ markers: [(String, TestKeyManager, OccultaBundle.Version?)]) throws -> (ContactManager, UUID) {
        let cm = try TestSupport.makeContactManager()
        for (id, phone, marker) in markers {
            try insertStreamedSender(identifier: id, publicKey: try phone.retrieveIdentity(), marker: marker, in: cm)
        }
        let group = try cm.createGroup(name: "G")
        for (id, _, _) in markers { try group.addMember(id, atDepth: 0) }
        return (cm, try #require(group.readID()))
    }

    @Test("every member at the tier: streamed, and each opens it", .ambientTestKeyManager)
    func allCapable() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let video = streamedPattern(C + 9, seed: 8)
        let (cm, id) = try self.group([("bob", self.bob, .streamedBodyCapable), ("carol", self.carol, .streamedBodyCapable)])
        let url = outputURL(dir)

        let layout = try cm.encryptGroupBundle(
            basket: Basket(files: [try stageFile(video, in: dir, using: manager)]), groupID: id,
            output: .file(destination: url, attachments: manager, memoryGuard: .system)
        )

        #expect(layout == .streamed)
        for phone in [self.bob, self.carol] { #expect(try open(url, on: phone).streamed[0] == video) }
    }

    @Test("one member below the tier makes the whole send inline, which both still open", .ambientTestKeyManager)
    func mixedGroupIsInline() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let video = streamedPattern(C + 9, seed: 8)
        let (cm, id) = try self.group([("bob", self.bob, .streamedBodyCapable), ("carol", self.carol, .bodyDigestCapable)])
        let url = outputURL(dir)

        let layout = try cm.encryptGroupBundle(
            basket: Basket(files: [try stageFile(video, in: dir, using: manager)]), groupID: id,
            output: .file(destination: url, attachments: manager, memoryGuard: .system)
        )

        #expect(layout == .inline)
        for phone in [self.bob, self.carol] {
            let received = try open(url, on: phone)
            #expect(received.layout == .inline && received.basket?.files.first?.content == video)
        }
    }

    @Test("a member with no tier recorded makes it inline", .ambientTestKeyManager)
    func unrecordedMemberIsInline() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (cm, id) = try self.group([("bob", self.bob, .streamedBodyCapable), ("carol", self.carol, nil)])

        let layout = try cm.encryptGroupBundle(
            basket: Basket(files: [inlineTextEntry("hi").file]), groupID: id,
            output: .file(destination: outputURL(dir), attachments: nil, memoryGuard: .system)
        )

        #expect(layout == .inline)
    }

    @Test("a refused inline group send takes no member's prekey and writes nothing", .ambientTestKeyManager)
    func refusedGroupSendChangesNothing() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let (cm, id) = try self.group([("bob", self.bob, .streamedBodyCapable), ("carol", self.carol, .bodyDigestCapable)])
        let records = try ["bob", "carol"].map { try #require(try cm.fetchContact(by: $0)).prekeyRecordEncrypted }
        let url = outputURL(dir)

        #expect(throws: MemoryGuard.SendRefusal.tooLargeToSend) {
            try cm.encryptGroupBundle(
                basket: Basket(files: [try stageFile(streamedPattern(2 * C), in: dir, using: manager)]), groupID: id,
                output: .file(destination: url, attachments: manager, memoryGuard: MemoryGuard { 1024 })
            )
        }

        #expect(!FileManager.default.fileExists(atPath: url.path))
        #expect(try ["bob", "carol"].map { try #require(try cm.fetchContact(by: $0)).prekeyRecordEncrypted } == records)
    }
}

// MARK: - Compose

@Suite("Streamed send — through compose")
@MainActor struct ComposeStreamedSendTests {

    private struct FixedKey: ComposeStagingKeyProviding {
        let key = SymmetricKey(size: .bits256)
        func deriveComposeStagingKey() throws -> SymmetricKey { self.key }
    }

    let bob = TestKeyManager()

    private func vm(for marker: OccultaBundle.Version?, memoryGuard: MemoryGuard = .system) throws -> (ComposeViewModel, ContactManager) {
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try self.bob.retrieveIdentity(), marker: marker, in: cm)
        let group = try cm.createGroup(name: "G")
        try group.addMember("bob", atDepth: 0)
        let vm = ComposeViewModel(
            recipient: .group(try #require(group.readID())), stagingKeyProvider: FixedKey(), memoryGuard: memoryGuard
        )
        vm.setup(contactManager: cm)
        return (vm, cm)
    }

    @Test("a send to a group at the tier is streamed, opens, and leaves the staged file for the sheet to clean up", .ambientTestKeyManager)
    func composeStreams() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (vm, cm) = try self.vm(for: .streamedBodyCapable)
        let clip = streamedPattern(2 * C + 5, seed: 12)
        let staged = try stageFile(clip, in: dir, using: try #require(vm.attachmentManager))
        vm.messages = [staged]
        vm.draftText = "see this"

        await vm.encrypt(contactManager: cm)

        let url = try #require(vm.encryptedURL, "encrypt failed: \(vm.errorMessage)")
        defer { try? FileManager.default.removeItem(at: url) }
        let received = try open(url, on: self.bob)
        #expect(received.layout == .streamed)
        #expect(received.streamed.values.contains(clip))
        #expect(received.basket?.files.contains { $0.content.flatMap { String(data: $0, encoding: .utf8) } == "see this" } == true)
        #expect(FileManager.default.fileExists(atPath: try #require(staged.url).path), "the draft's file is the sheet's to remove")
        #expect(vm.isEncrypting == false && !vm.isShowingError)
    }

    @Test("a send to a group below the tier is inline, under the guard, and opens", .ambientTestKeyManager)
    func composeInline() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (vm, cm) = try self.vm(for: .bodyDigestCapable)
        let clip = streamedPattern(C + 5, seed: 13)
        vm.messages = [try stageFile(clip, in: dir, using: try #require(vm.attachmentManager))]

        await vm.encrypt(contactManager: cm)

        let url = try #require(vm.encryptedURL, "encrypt failed: \(vm.errorMessage)")
        defer { try? FileManager.default.removeItem(at: url) }
        let received = try open(url, on: self.bob)
        #expect(received.layout == .inline && received.basket?.files.first?.content == clip)
    }

    @Test("the guard refuses an inline compose send and a streamed one never meets it", .ambientTestKeyManager)
    func composeGuard() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let tiny = MemoryGuard { 8 * 1024 * 1024 }

        let (inlineVM, inlineCM) = try self.vm(for: .bodyDigestCapable, memoryGuard: tiny)
        inlineVM.messages = [try stageFile(streamedPattern(2 * C), in: dir, using: try #require(inlineVM.attachmentManager))]
        await inlineVM.encrypt(contactManager: inlineCM)
        #expect(inlineVM.encryptedURL == nil && inlineVM.isShowingError)
        #expect(inlineVM.errorMessage == MemoryGuard.SendRefusal.tooLargeToSend.localizedDescription)

        let (streamedVM, streamedCM) = try self.vm(for: .streamedBodyCapable, memoryGuard: tiny)
        streamedVM.messages = [try stageFile(streamedPattern(2 * C), in: dir, using: try #require(streamedVM.attachmentManager))]
        await streamedVM.encrypt(contactManager: streamedCM)
        let url = try #require(streamedVM.encryptedURL, "encrypt failed: \(streamedVM.errorMessage)")
        try? FileManager.default.removeItem(at: url)
    }
}
