//
//  StreamedReceive.swift
//  Occulta
//
//  Pass 2 of receiving a streamed bundle: the attachments, decrypted from the open inbound file into sealed
//  `.eatt` files in `tmp/` while the message is already on screen. STREAMING_SPEC §5.2 steps 7 and 8, §5.3.
//

import Foundation
import CryptoKit
import Observation
import OccultaFormats

/// A received message whose attachments are still arriving.
///
/// `files` is what the sheet shows: the inline files, and each streamed file as a placeholder until its last
/// byte is written, when the placeholder is replaced by the sealed file. Behaviour is the same at every depth:
/// nothing here reads the depth.
@MainActor @Observable
final class StreamedReceive {

    /// The message with placeholders, as first shown.
    let basket: Basket
    let owner: String

    /// The files as they stand: inline ones, and streamed ones either as placeholders or finished.
    private(set) var files: [OccultaFormats.File]
    /// Ids of streamed files not yet finished.
    private(set) var incoming: Set<UUID>
    /// A chunk failed to open, the stream was the wrong length, or a write failed. The attachments are gone.
    private(set) var failed = false
    /// Pass 2 is over, however it ended: every file finished, a failure, or a cancel.
    private(set) var isFinished = false

    @ObservationIgnored private var inlineFiles: [OccultaFormats.File]
    @ObservationIgnored private let streamedLengths: [UInt64?]
    @ObservationIgnored private var body: StreamedBody?
    @ObservationIgnored private var cursor: StreamCursor?
    @ObservationIgnored private let sink: ReceiveSink?
    @ObservationIgnored private var task: Task<Void, Never>?
    /// Pass 2 is over, or was never to run. `finished(id:at:)` is not gated by it: the last file's
    /// completion can reach the main actor after the stream's.
    @ObservationIgnored private var ended = false
    /// Stopped or failed: results still in flight are dropped.
    @ObservationIgnored private var discarded = false

    /// Steps 6 and 7 for a message that passed `routeGroupOpening`: decode the basket, check that the lengths
    /// the manifest gave are exactly what the stream holds (before any file is written), and plan the files.
    static func prepare(
        message: Data, opened: ContactManager.GroupOpening, body: StreamedBody, key: SymmetricKey?,
        in directory: URL = FileManager.default.temporaryDirectory
    ) throws -> StreamedReceive {
        guard let cursor = opened.cursor else { throw OccultaBundle.BundleError.malformedBundle }
        let (basket, streamedLengths) = try WireHandle.decode(streamedBasket: message)
        try cursor.validate(streamedLengths: streamedLengths)
        return try StreamedReceive(
            owner: opened.ownerID, basket: basket, streamedLengths: streamedLengths, body: body, cursor: cursor, key: key,
            directory: directory
        )
    }

    /// Plans the destination of every streamed file. Throws `ImportError.stagingKeyUnavailable` when there is
    /// a streamed file and no key to seal it under: nothing is written unsealed (Bug 184).
    init(
        owner: String, basket: Basket, streamedLengths: [UInt64?],
        body: StreamedBody, cursor: StreamCursor, key: SymmetricKey?, directory: URL
    ) throws {
        self.owner           = owner
        self.streamedLengths = streamedLengths
        self.body            = body
        self.cursor          = cursor

        var inline: [OccultaFormats.File] = []
        var placeholders: [OccultaFormats.File] = []
        var plan: [Int: URL] = [:]
        for (index, file) in basket.files.enumerated() {
            guard streamedLengths[index] != nil, case .file(let metadata) = file.format else {
                inline.append(file)
                continue
            }
            // The name is dropped for a fresh UUID and the extension is validated, as for any received file:
            // both come from the sender and neither is trusted for a path.
            plan[index] = directory
                .appendingPathComponent(UUID().uuidString)
                .appendingPathExtension(OccultaFormats.File.Metadata.sanitizedFilesystemExtension(metadata.extension))
            placeholders.append(OccultaFormats.File(id: file.id, format: file.format, date: file.date))
        }

        if plan.isEmpty {
            self.sink = nil
        } else {
            guard let key else { throw ImportError.stagingKeyUnavailable }
            self.sink = ReceiveSink(manager: AttachmentManager(contactKey: key), plan: plan, files: basket.files)
        }

        let shown = (inline + placeholders).sorted { ($0.date ?? .now) < ($1.date ?? .now) }
        self.inlineFiles = inline
        self.incoming    = Set(placeholders.map(\.id))
        self.files       = shown
        self.basket      = Basket(id: basket.id, files: shown, date: basket.date, owner: basket.owner)

        self.sink?.onFinished = { [weak self] id, url in
            Task { @MainActor in self?.finished(id: id, at: url) }
        }
    }

    /// Begins pass 2. Called once the message is on screen, so a refused presentation never decrypts anything.
    func start() {
        guard self.task == nil, !self.ended else { return }
        guard let body = self.body, let cursor = self.cursor, let sink = self.sink else {
            self.release()
            return
        }
        let lengths = self.streamedLengths
        self.task = Task.detached(priority: .userInitiated) { [weak self] in
            do {
                try body.streamFiles(cursor: cursor, streamedLengths: lengths, sink: sink)
                await self?.completed()
            } catch {
                sink.abandonAll()
                await self?.didFail()
            }
        }
    }

    /// Returns once pass 2's task has ended, however it ended.
    func settle() async {
        await self.task?.value
    }

    /// The sheet closed, the session ended, or the app was locked: stop, and delete every file of the message.
    /// The prekey stays spent (§5.3).
    func cancel() {
        guard !self.discarded else { return }
        self.discarded = true
        self.task?.cancel()
        self.sink?.abandonAll()
        self.deleteFiles()
        self.release()
    }

    /// Deletes the sealed files of a message whose sheet has closed. The same cleanup as `cancel`, for a finished one.
    func deleteFiles() {
        for file in self.files { if let url = file.url { try? FileManager.default.removeItem(at: url) } }
        self.sink?.removeAll()
    }

    // MARK: Pass 2 results

    private func finished(id: UUID, at url: URL) {
        guard !self.discarded, let index = self.files.firstIndex(where: { $0.id == id }) else { return }
        let old = self.files[index]
        self.files[index] = OccultaFormats.File(id: id, url: url, format: old.format, date: old.date)
        self.incoming.remove(id)
    }

    private func completed() {
        self.release()
    }

    /// A failure after the message is shown: every temporary file of it goes, completed ones too, and the
    /// placeholders become one error (§5.3). The same for every cause, so it says nothing about which.
    private func didFail() {
        guard !self.discarded else { return }
        self.discarded = true
        self.sink?.removeAll()
        self.files   = self.inlineFiles
        self.incoming = []
        self.failed  = true
        self.release()
    }

    private func release() {
        self.isFinished = true
        self.ended  = true
        self.body   = nil
        self.cursor = nil
    }
}

// MARK: - ReceiveSink

/// Writes each streamed file through a `StreamingEncryptor`, sealed under the received-attachment key.
nonisolated final class ReceiveSink: StreamSink, @unchecked Sendable {
    private let manager: AttachmentManager
    private let plan: [Int: URL]
    private let ids: [Int: UUID]
    private let lock = NSLock()
    private var encryptor: StreamingEncryptor?
    private var current: Int?
    private var created: [URL] = []

    /// Called, off the main actor, when a file's last byte is written and the file is sealed.
    var onFinished: (@Sendable (UUID, URL) -> Void)?

    init(manager: AttachmentManager, plan: [Int: URL], files: [OccultaFormats.File]) {
        self.manager = manager
        self.plan    = plan
        self.ids     = Dictionary(uniqueKeysWithValues: plan.keys.map { ($0, files[$0].id) })
    }

    func begin(fileIndex: Int) throws {
        guard let url = self.plan[fileIndex] else { throw BodyStream.StreamError.lengthMismatch }
        self.lock.lock(); defer { self.lock.unlock() }
        let encryptor = try self.manager.streamingEncryptor(to: url)
        self.created.append(url)
        self.encryptor = encryptor
        self.current = fileIndex
    }

    func write(_ data: Data) throws {
        self.lock.lock(); let encryptor = self.encryptor; self.lock.unlock()
        try encryptor?.append(data)
    }

    func end() throws {
        self.lock.lock()
        let encryptor = self.encryptor, index = self.current
        self.encryptor = nil; self.current = nil
        self.lock.unlock()

        try encryptor?.finalize()
        if let index, let url = self.plan[index], let id = self.ids[index] { self.onFinished?(id, url) }
    }

    /// Stops the file being written and removes it, and every one finished before it.
    func abandonAll() {
        self.lock.lock(); let encryptor = self.encryptor; self.encryptor = nil; self.lock.unlock()
        encryptor?.abandon()
        self.removeAll()
    }

    /// Removes every file this sink created.
    func removeAll() {
        self.lock.lock(); let urls = self.created; self.created = []; self.lock.unlock()
        for url in urls { try? FileManager.default.removeItem(at: url) }
    }
}
