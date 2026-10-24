import Foundation
import SwiftUI
import PhotosUI
import Photos
import AVFoundation
import UniformTypeIdentifiers
import OccultaFormats
import CryptoKit

// MARK: - ComposeStagingKeyProviding

/// The device-bound key that seals attachments staged for a recipient with no per-contact key:
/// every group, and a contact we hold no public key for. Production passes
/// `ShareStagingKeyManager`; tests pass an in-memory key and run without a Secure Enclave.
protocol ComposeStagingKeyProviding {
    func deriveComposeStagingKey() throws -> SymmetricKey
}

extension ShareStagingKeyManager: ComposeStagingKeyProviding {}

// MARK: - PendingImport

struct PendingImport: Identifiable {
    let id       = UUID()
    let filename: String
    let ext:      String
    var progress:  Double = 0
    var isLoading: Bool   = true

    init(filename: String, ext: String, progress: Double = 0, isLoading: Bool = true) {
        self.filename  = filename
        self.ext       = ext.lowercased()
        self.progress  = progress
        self.isLoading = isLoading
    }
}

// MARK: - ComposeViewModel

@Observable
final class ComposeViewModel {
    enum Recipient {
        case contact(String)
        case group(UUID)
    }

    let recipient: Recipient

    var messages:       [OccultaFormats.File]  = []
    var draftText:      String          = ""
    var pendingImports: [PendingImport] = []
    var thumbnails:     [URL: UIImage]  = [:]
    var encryptedURL:   URL?            = nil
    var isShowingError  = false
    var errorMessage    = ""
    var isEncrypting    = false

    private(set) var attachmentManager: AttachmentManager? = nil

    private let stagingKeyProvider: any ComposeStagingKeyProviding
    private let memoryGuard: MemoryGuard

    init(
        recipient: Recipient,
        stagingKeyProvider: any ComposeStagingKeyProviding = ShareStagingKeyManager(),
        memoryGuard: MemoryGuard = .system
    ) {
        self.recipient = recipient
        self.stagingKeyProvider = stagingKeyProvider
        self.memoryGuard = memoryGuard
    }

    // MARK: Setup

    /// A contact we hold a key for seals staged files under their per-contact key. A group, or a
    /// contact with no key yet, seals them under the device staging key. If neither key can be
    /// derived the manager stays nil and every import refuses — there is no plaintext fallback.
    func setup(contactManager: ContactManager) {
        if case .contact(let identifier) = self.recipient,
           let key = try? contactManager.fileEncryptionKey(for: identifier) {
            self.attachmentManager = AttachmentManager(contactKey: key)
        } else if let key = try? self.stagingKeyProvider.deriveComposeStagingKey() {
            self.attachmentManager = AttachmentManager(contactKey: key)
        }
    }

    /// Adopts a restored draft's attachments. Any file an earlier build staged as plaintext
    /// (group and key-less drafts) is sealed in place first, so nothing is lost and nothing is
    /// left readable. A file that can't be sealed is dropped from the draft and deleted.
    func adopt(draftMessages: [OccultaFormats.File]) async {
        guard let manager = self.attachmentManager else {
            self.messages = draftMessages
            return
        }
        var adopted: [OccultaFormats.File] = []
        for file in draftMessages {
            guard let url = file.url else { adopted.append(file); continue }
            let sealed = await Task.detached(priority: .userInitiated) {
                (try? manager.sealInPlace(at: url)) != nil
            }.value
            if sealed {
                adopted.append(file)
            } else {
                try? FileManager.default.removeItem(at: url)
            }
        }
        self.messages = adopted
    }

    var recipientIDString: String {
        switch self.recipient {
        case .contact(let identifier): return identifier
        case .group(let groupID):      return groupID.uuidString
        }
    }

    /// Group-level sensitivity gating for drafts is not yet designed — see
    /// Docs/Features/Message Persistence/FINDINGS.md. Groups are never treated
    /// as sensitive here; their drafts always persist.
    func isSensitive(contactManager: ContactManager) -> Bool {
        switch self.recipient {
        case .contact(let identifier): return contactManager.isSensitive(identifier)
        case .group:                   return false
        }
    }

    // MARK: Text

    func addText() {
        let trimmed = self.draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        self.messages.append(OccultaFormats.File(content: trimmed.data(using: .utf8), format: .text, date: Date()))
        self.draftText = ""
    }

    // MARK: Media import

    func handleMedia(_ result: PHPickerResult) async {
        let provider = result.itemProvider
        let typeID   = provider.registeredTypeIdentifiers.first { id in
            guard let type = UTType(id) else { return false }
            return type.conforms(to: .image) || type.conforms(to: .movie)
        } ?? provider.registeredTypeIdentifiers.first ?? UTType.data.identifier
        let ext      = UTType(typeID)?.preferredFilenameExtension ?? "bin"
        let filename = "media_\(UUID().uuidString.prefix(8))"
        let url      = FileManager.default.temporaryDirectory.appendingPathComponent("\(filename).\(ext)")
        let isVideo  = FileExtensions.Video(rawValue: ext) != nil

        guard let manager = self.attachmentManager else {
            await MainActor.run { self.showError("Secure storage not ready.") }
            return
        }

        if isVideo {
            let pending = PendingImport(filename: filename, ext: ext)
            await MainActor.run { self.pendingImports.append(pending) }

            let thumbTypeID = "com.apple.private.photos.thumbnail.standard"
            let thumbTask = Task<UIImage?, Never> {
                guard provider.hasItemConformingToTypeIdentifier(thumbTypeID),
                      let data = try? await loadItemData(from: provider, typeID: thumbTypeID) else { return nil }
                return UIImage(data: data)
            }

            do {
                try await self.streamVideo(assetID: result.assetIdentifier,
                                           provider: provider, typeID: typeID,
                                           pendingID: pending.id, url: url, manager: manager)
            } catch {
                thumbTask.cancel()
                await MainActor.run {
                    self.pendingImports.removeAll { $0.id == pending.id }
                    self.showError(error.localizedDescription)
                }
                return
            }

            let thumb = await thumbTask.value
            await MainActor.run {
                withTransaction(Transaction(animation: nil)) {
                    self.pendingImports.removeAll { $0.id == pending.id }
                    if let img = thumb { self.thumbnails[url] = img }
                    var file = OccultaFormats.File(url: url, format: .file(.init(name: filename, extension: ext)), date: Date())
                    file.id = pending.id
                    self.messages.append(file)
                }
            }
        } else {
            let pending = PendingImport(filename: filename, ext: ext)
            await MainActor.run { self.pendingImports.append(pending) }

            do {
                let data = try await loadItemData(from: provider, typeID: typeID)
                try await Task.detached(priority: .userInitiated) {
                    try manager.encrypt(data, to: url)
                }.value
                await MainActor.run {
                    self.pendingImports.removeAll { $0.id == pending.id }
                    var file = OccultaFormats.File(url: url, format: .file(.init(name: filename, extension: ext)), date: Date())
                    file.id = pending.id
                    self.messages.append(file)
                }
            } catch {
                await MainActor.run {
                    self.pendingImports.removeAll { $0.id == pending.id }
                    self.showError(error.localizedDescription)
                }
            }
        }
    }

    func handleFile(_ result: Result<[URL], Error>) {
        Task {
            var pendingImport: PendingImport?
            do {
                guard let srcURL = try result.get().first,
                      srcURL.startAccessingSecurityScopedResource() else { return }
                defer { srcURL.stopAccessingSecurityScopedResource() }

                let filename = srcURL.deletingPathExtension().lastPathComponent
                let ext      = srcURL.pathExtension.lowercased()
                let tmp      = FileManager.default.temporaryDirectory.appendingPathComponent("\(filename).\(ext)")
                guard let manager = self.attachmentManager else {
                    await MainActor.run { self.showError("Secure storage not ready.") }
                    return
                }

                let pending = PendingImport(filename: filename, ext: ext)
                pendingImport = pending
                await MainActor.run { self.pendingImports.append(pending) }

                try await Task.detached(priority: .userInitiated) {
                    try await Self.seal(contentsOf: srcURL, to: tmp, using: manager)
                }.value

                await MainActor.run {
                    self.pendingImports.removeAll { $0.id == pending.id }
                    var file = OccultaFormats.File(url: tmp, format: .file(.init(name: filename, extension: ext)), date: Date())
                    file.id = pending.id
                    self.messages.append(file)
                }
            } catch {
                await MainActor.run {
                    if let pendingImport {
                        self.pendingImports.removeAll { $0.id == pendingImport.id }
                    }
                    self.showError(error.localizedDescription)
                }
            }
        }
    }

    /// Streams `srcURL` into a sealed file at `tmp`, 64 KB at a time. Never writes plaintext.
    nonisolated static func seal(contentsOf srcURL: URL, to tmp: URL, using manager: AttachmentManager) async throws {
        let source = try NoCacheFile.reader(srcURL)
        let encryptor = try manager.streamingEncryptor(to: tmp)

        try source.forEachChunk(range: 0..<source.size, size: 65_536) { try encryptor.append($0) }

        try encryptor.finalize()
    }

    // MARK: Bundle encryption

    func encrypt(
        contactManager:      ContactManager,
        shardCustodyManager: ShardCustodyManager? = nil
    ) async {
        await MainActor.run { self.isEncrypting = true }
        switch self.recipient {
        case .contact(let identifier):
            await self.encrypt(
                for:                 identifier,
                contactManager:      contactManager,
                shardCustodyManager: shardCustodyManager
            )
        case .group(let groupID):
            await self.encrypt(
                groupID:             groupID,
                contactManager:      contactManager,
                shardCustodyManager: shardCustodyManager
            )
        }
    }

    private func encrypt(
        for identifier:      String,
        contactManager:      ContactManager,
        shardCustodyManager: ShardCustodyManager?
    ) async {
        do {
            let basket     = self.outgoingBasket()
            let contactPub = try? contactManager.currentPublicKey(forIdentifier: identifier)

            let isCard     = try contactManager.isCardContact(identifier: identifier)
            let shardOps   = try shardCustodyManager?.buildShardOperations(for: identifier, currentContactPublicKey: contactPub, isCardContact: isCard) ?? []
            let manifest   = try? shardCustodyManager?.buildCustodyManifest(for: identifier, isCardContact: isCard)

            // The staged files are not read here. The layout is chosen from the recipient's tier, and only the
            // inline one reads them into memory, behind the guard (STREAMING_SPEC §3, §7).
            let output = self.bundleOutput()

            do {
                try contactManager.encryptBundle(
                    basket:          basket,
                    for:             identifier,
                    shardOperations: shardOps.isEmpty ? nil : shardOps,
                    custodyManifest: manifest,
                    output:          output
                )
            } catch ContactManager.Errors.trusteeLacksQuantumMaterial {
                try contactManager.encryptBundle(basket: basket, for: identifier, output: output)
            }

            await MainActor.run {
                self.isEncrypting = false
                self.encryptedURL = output.destination
            }
        } catch {
            await MainActor.run {
                self.isEncrypting = false
                self.showError(error.localizedDescription)
            }
        }
    }

    private func encrypt(
        groupID: UUID,
        contactManager: ContactManager,
        shardCustodyManager: ShardCustodyManager? = nil
    ) async {
        do {
            let output = self.bundleOutput()
            try contactManager.encryptGroupBundle(
                basket: self.outgoingBasket(), groupID: groupID,
                shardCustodyManager: shardCustodyManager, output: output
            )

            await MainActor.run {
                self.isEncrypting = false
                self.encryptedURL = output.destination
            }
        } catch {
            await MainActor.run {
                self.isEncrypting = false
                self.showError(error.localizedDescription)
            }
        }
    }

    /// What is sent: the staged files, each still a sealed `.eatt` on disk, and the typed text, in date order.
    private func outgoingBasket() -> Basket {
        var allFiles = self.messages
        let text = self.draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !text.isEmpty {
            allFiles.append(OccultaFormats.File(content: text.data(using: .utf8), format: .text, date: Date()))
        }
        return Basket(files: allFiles.sorted { ($0.date ?? .distantPast) < ($1.date ?? .distantPast) })
    }

    /// A fresh `.occ` in `tmp/`, written as ciphertext with complete protection and deleted when the share sheet closes.
    private func bundleOutput() -> BundleOutput {
        let name = UUID().uuidString.components(separatedBy: "-").last ?? "msg"
        return .file(
            destination: FileManager.default.temporaryDirectory.appendingPathComponent("\(name).occ"),
            attachments: self.attachmentManager,
            memoryGuard: self.memoryGuard
        )
    }

    // MARK: Lifecycle

    func deleteMessage(_ file: OccultaFormats.File) {
        if let url = file.url { try? FileManager.default.removeItem(at: url) }
        self.messages.removeAll { $0.id == file.id }
    }

    func clearAfterEncrypt() {
        for file in self.messages {
            if let url = file.url { try? FileManager.default.removeItem(at: url) }
        }
        self.messages = []
        self.draftText = ""
    }

    func cleanup() {
        for file in self.messages {
            if let url = file.url { try? FileManager.default.removeItem(at: url) }
        }
    }

    // MARK: Private

    private func streamVideo(
        assetID:   String?,
        provider:  NSItemProvider,
        typeID:    String,
        pendingID: UUID,
        url:       URL,
        manager:   AttachmentManager
    ) async throws {
        if let assetID {
            try await self.streamVideoPOSIX(assetID: assetID, pendingID: pendingID, url: url, manager: manager)
        } else {
            try await self.streamVideoProvider(provider: provider, typeID: typeID,
                                               pendingID: pendingID, url: url, manager: manager)
        }
    }

    // POSIX path: F_NOCACHE + F_RDAHEAD=0 on the source fd keeps the kernel buffer
    // cache from accumulating pages behind the read cursor, bounding RSS to one chunk.
    private func streamVideoPOSIX(
        assetID:   String,
        pendingID: UUID,
        url:       URL,
        manager:   AttachmentManager
    ) async throws {
        let status = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
        guard status == .authorized || status == .limited else {
            throw ImportError.photosAccessDenied
        }

        let fetchResult = PHAsset.fetchAssets(withLocalIdentifiers: [assetID], options: nil)
        guard let asset = fetchResult.firstObject else { throw ImportError.assetNotFound }

        let opts = PHVideoRequestOptions()
        opts.isNetworkAccessAllowed = true
        opts.deliveryMode = .automatic

        let videoURL: URL = try await withCheckedThrowingContinuation { cont in
            var resumed = false
            PHImageManager.default().requestAVAsset(forVideo: asset, options: opts) { avAsset, _, info in
                guard !resumed else { return }
                resumed = true
                if let err = info?[PHImageErrorKey] as? Error { cont.resume(throwing: err) }
                else if let ua = avAsset as? AVURLAsset       { cont.resume(returning: ua.url) }
                else                                           { cont.resume(throwing: ImportError.noVideoResource) }
            }
        }

        await MainActor.run {
            if let idx = self.pendingImports.firstIndex(where: { $0.id == pendingID }) {
                self.pendingImports[idx].isLoading = false
            }
        }

        let encryptor = try manager.streamingEncryptor(to: url)

        // Blocking I/O — run on a detached task, not the cooperative pool. `NoCacheFile` turns the page cache
        // off and read-ahead off on the source, which keeps resident memory to one chunk.
        try await Task.detached(priority: .userInitiated) {
            let source = try NoCacheFile.reader(videoURL)
            try source.forEachChunk(range: 0..<source.size, size: 65_536) { try encryptor.append($0) }
            try encryptor.finalize()
        }.value
    }

    // NSItemProvider fallback — no Photos authorization needed, picker grant is sufficient.
    private func streamVideoProvider(
        provider:  NSItemProvider,
        typeID:    String,
        pendingID: UUID,
        url:       URL,
        manager:   AttachmentManager
    ) async throws {
        await MainActor.run {
            if let idx = self.pendingImports.firstIndex(where: { $0.id == pendingID }) {
                self.pendingImports[idx].isLoading = false
            }
        }

        let encryptor = try manager.streamingEncryptor(to: url)

        // Read directly from the system-provided URL inside the callback — no plaintext copy written.
        // The callback runs on a background thread so blocking I/O is fine.
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            provider.loadFileRepresentation(forTypeIdentifier: typeID) { fileURL, error in
                do {
                    if let err = error { throw err }
                    guard let fileURL else { throw ImportError.noVideoResource }
                    
                    let source = try NoCacheFile.reader(fileURL)

                    try source.forEachChunk(range: 0..<source.size, size: 65_536) { try encryptor.append($0) }
                    try encryptor.finalize()
                    
                    cont.resume()
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }

    private func showError(_ message: String) {
        self.errorMessage = message
        self.isShowingError = true
    }
}

// MARK: - Supporting types

struct FileExtensions {
    enum Video: String { case mov, mp4, m4v }
    enum Image: String { case jpg, jpeg, png, heic }
}

enum ImportError: LocalizedError {
    case photosAccessDenied
    case assetNotFound
    case noVideoResource
    case stagingKeyUnavailable

    var errorDescription: String? {
        switch self {
        case .photosAccessDenied: return "Photos access is required to import videos."
        case .assetNotFound:      return "Could not find the selected video."
        case .noVideoResource:    return "The selected item has no video resource."
        case .stagingKeyUnavailable: return "Secure storage not ready."
        }
    }
}

private func loadItemData(from provider: NSItemProvider, typeID: String) async throws -> Data {
    try await withCheckedThrowingContinuation { cont in
        provider.loadDataRepresentation(forTypeIdentifier: typeID) { data, error in
            if let data { cont.resume(returning: data) }
            else { cont.resume(throwing: error ?? ImportError.assetNotFound) }
        }
    }
}
