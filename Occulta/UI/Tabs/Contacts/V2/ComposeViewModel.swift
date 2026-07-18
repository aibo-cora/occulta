import Foundation
import SwiftUI
import PhotosUI
import Photos
import AVFoundation
import UniformTypeIdentifiers

// MARK: - PendingImport

struct PendingImport: Identifiable {
    let id       = UUID()
    let filename: String
    let ext:      String
    var progress:  Double = 0
    var isLoading: Bool   = true
}

// MARK: - ComposeViewModel

@Observable
final class ComposeViewModel {
    enum Recipient {
        case contact(String)
        case group(UUID)
    }

    let recipient: Recipient

    var messages:       [Occulta.File]  = []
    var draftText:      String          = ""
    var pendingImports: [PendingImport] = []
    var thumbnails:     [URL: UIImage]  = [:]
    var encryptedURL:   URL?            = nil
    var isShowingError  = false
    var errorMessage    = ""
    var isEncrypting    = false

    private(set) var attachmentManager: AttachmentManager? = nil

    init(recipient: Recipient) {
        self.recipient = recipient
    }

    // MARK: Setup

    func setup(contactManager: ContactManager) {
        guard
            case .contact(let identifier) = self.recipient,
            let key = try? contactManager.fileEncryptionKey(for: identifier)
        else { return }
        self.attachmentManager = AttachmentManager(contactKey: key)
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
        self.messages.append(Occulta.File(content: trimmed.data(using: .utf8), format: .text, date: Date()))
        self.draftText = ""
    }

    // MARK: Media import

    func handleMedia(_ result: PHPickerResult) async {
        let provider = result.itemProvider
        let typeID   = provider.registeredTypeIdentifiers.first ?? UTType.data.identifier
        let ext      = UTType(typeID)?.preferredFilenameExtension ?? "bin"
        let filename = "media_\(UUID().uuidString.prefix(8))"
        let url      = FileManager.default.temporaryDirectory.appendingPathComponent("\(filename).\(ext)")
        let isVideo  = FileExtensions.Video(rawValue: ext) != nil
        let manager  = self.attachmentManager

        if isVideo {
            guard let manager else {
                await MainActor.run { self.showError("Secure storage not ready.") }
                return
            }
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
                    var file = Occulta.File(url: url, format: .file(.init(name: filename, extension: ext)), date: Date())
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
                    if let manager {
                        try manager.encrypt(data, to: url)
                    } else {
                        try data.writeProtected(to: url)
                    }
                }.value
                await MainActor.run {
                    self.pendingImports.removeAll { $0.id == pending.id }
                    var file = Occulta.File(url: url, format: .file(.init(name: filename, extension: ext)), date: Date())
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
                let ext      = srcURL.pathExtension
                let tmp      = FileManager.default.temporaryDirectory.appendingPathComponent("\(filename).\(ext)")
                let manager  = self.attachmentManager

                let pending = PendingImport(filename: filename, ext: ext)
                pendingImport = pending
                await MainActor.run { self.pendingImports.append(pending) }

                try await Task.detached(priority: .userInitiated) {
                    if let manager {
                        let source = try FileHandle(forReadingFrom: srcURL)

                        defer { try? source.close() }
                        let encryptor = try await manager.streamingEncryptor(to: tmp)


                        while let chunk = try source.read(upToCount: 65_536), !chunk.isEmpty {
                            try await encryptor.append(chunk)
                        }

                        try await encryptor.finalize()
                    } else {
                        let data = try Data(contentsOf: srcURL, options: .mappedIfSafe)
                        try data.writeProtected(to: tmp)
                    }
                }.value

                await MainActor.run {
                    self.pendingImports.removeAll { $0.id == pending.id }
                    var file = Occulta.File(url: tmp, format: .file(.init(name: filename, extension: ext)), date: Date())
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

    // MARK: Bundle encryption

    func encrypt(
        contactManager:      ContactManager,
        shardCustodyManager: ShardCustodyManager? = nil,
        vaultManager:        VaultManager?        = nil
    ) async {
        await MainActor.run { self.isEncrypting = true }
        switch self.recipient {
        case .contact(let identifier):
            await self.encrypt(
                for:                 identifier,
                contactManager:      contactManager,
                shardCustodyManager: shardCustodyManager,
                vaultManager:        vaultManager
            )
        case .group(let groupID):
            await self.encrypt(
                groupID:             groupID,
                contactManager:      contactManager,
                shardCustodyManager: shardCustodyManager,
                vaultManager:        vaultManager
            )
        }
    }

    private func encrypt(
        for identifier:      String,
        contactManager:      ContactManager,
        shardCustodyManager: ShardCustodyManager?,
        vaultManager:        VaultManager?
    ) async {
        do {
            var allFiles = self.messages
            let text = self.draftText.trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.isEmpty {
                allFiles.append(Occulta.File(content: text.data(using: .utf8), format: .text, date: Date()))
            }

            let manager = self.attachmentManager
            let processed: [Occulta.File] = try await withThrowingTaskGroup(of: Occulta.File.self) { group in
                for file in allFiles {
                    if let fileURL = file.url {
                        group.addTask {
                            let data: Data
                            if let manager {
                                data = try await manager.data(at: fileURL)
                            } else {
                                (data, _) = try await URLSession.shared.data(from: fileURL)
                            }
                            return Occulta.File(content: data, format: file.format, date: file.date)
                        }
                    } else {
                        let captured = file
                        group.addTask { captured }
                    }
                }
                var results: [Occulta.File] = []
                for try await file in group { results.append(file) }
                return results.sorted { ($0.date ?? .distantPast) < ($1.date ?? .distantPast) }
            }

            let basket     = Basket(files: processed)
            let contactPub = try? contactManager.currentPublicKey(forIdentifier: identifier)

            let shardOps   = try await shardCustodyManager?.buildShardOperations(for: identifier, currentContactPublicKey: contactPub) ?? []
            let manifest   = try? await shardCustodyManager?.buildCustodyManifest(for: identifier)
            let expected: [UUID]?

            if let custody = shardCustodyManager, let vm = vaultManager {
                expected = try? await custody.buildExpectedShards(for: identifier, vaultManager: vm)
            } else {
                expected = nil
            }

            let encrypted: Data

            do {
                encrypted = try contactManager.encryptBundle(
                    basket:          basket,
                    for:             identifier,
                    shardOperations: shardOps.isEmpty ? nil : shardOps,
                    custodyManifest: manifest,
                    expectedShards:  expected
                )
            } catch ContactManager.Errors.trusteeLacksQuantumMaterial {
                encrypted = try contactManager.encryptBundle(basket: basket, for: identifier)
            }

            guard !encrypted.isEmpty else {
                await MainActor.run {
                    self.isEncrypting = false
                    self.showError("Encryption failed. Try again.")
                }
                return
            }

            let name = UUID().uuidString.components(separatedBy: "-").last ?? "msg"
            let outURL = FileManager.default.temporaryDirectory.appendingPathComponent("\(name).occ")
            try encrypted.writeProtected(to: outURL)
            await MainActor.run {
                self.isEncrypting = false
                self.encryptedURL = outURL
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
        shardCustodyManager: ShardCustodyManager? = nil,
        vaultManager: VaultManager? = nil
    ) async {
        do {
            var allFiles = self.messages
            
            let text = self.draftText.trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.isEmpty {
                allFiles.append(Occulta.File(content: text.data(using: .utf8), format: .text, date: Date()))
            }

            let processed: [Occulta.File] = try await withThrowingTaskGroup(of: Occulta.File.self) { group in
                for file in allFiles {
                    if let fileURL = file.url {
                        group.addTask {
                            let (data, _) = try await URLSession.shared.data(from: fileURL)
                            return Occulta.File(content: data, format: file.format, date: file.date)
                        }
                    } else {
                        let captured = file
                        group.addTask { captured }
                    }
                }
                var results: [Occulta.File] = []
                for try await file in group { results.append(file) }
                return results.sorted { ($0.date ?? .distantPast) < ($1.date ?? .distantPast) }
            }

            let basket    = Basket(files: processed)
            let encrypted = try contactManager.encryptGroupBundle(
                basket: basket, groupID: groupID,
                shardCustodyManager: shardCustodyManager, vaultManager: vaultManager
            )
            
            guard !encrypted.isEmpty else {
                await MainActor.run {
                    self.isEncrypting = false
                    self.showError("Encryption failed. Try again.")
                }
                return
            }

            let name   = UUID().uuidString.components(separatedBy: "-").last ?? "msg"
            let outURL = FileManager.default.temporaryDirectory.appendingPathComponent("\(name).occ")

            try encrypted.writeProtected(to: outURL)

            await MainActor.run {
                self.isEncrypting = false
                self.encryptedURL = outURL
            }
        } catch {
            await MainActor.run {
                self.isEncrypting = false
                self.showError(error.localizedDescription)
            }
        }
    }

    // MARK: Lifecycle

    func deleteMessage(_ file: Occulta.File) {
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

        // Blocking I/O — run on a detached task, not the cooperative pool.
        try await Task.detached(priority: .userInitiated) {
            let fd = open(videoURL.path(percentEncoded: false), O_RDONLY)
            guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            defer { close(fd) }

            _ = fcntl(fd, F_NOCACHE, 1)  // bypass unified buffer cache
            _ = fcntl(fd, F_RDAHEAD, 0)  // disable kernel readahead (int 0, not a pointer)

            let chunkSize = 65_536
            var rawBuf: UnsafeMutableRawPointer? = nil
            
            guard posix_memalign(&rawBuf, Int(sysconf(_SC_PAGESIZE)), chunkSize) == 0,
                  let buf = rawBuf else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            defer { free(buf) }

            while true {
                let n = read(fd, buf, chunkSize)
                if n == 0 { break }
                if n < 0  { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
                // bytesNoCopy with .none deallocator: buf is reused each iteration;
                // append() copies into its internal buffer before returning.
                try await encryptor.append(Data(bytesNoCopy: buf, count: n, deallocator: .none))
            }
            try await encryptor.finalize()
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
                    
                    let source = try FileHandle(forReadingFrom: fileURL)
                    
                    defer { try? source.close() }
                    
                    while let chunk = try source.read(upToCount: 65_536), !chunk.isEmpty {
                        try encryptor.append(chunk)
                    }
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

    var errorDescription: String? {
        switch self {
        case .photosAccessDenied: return "Photos access is required to import videos."
        case .assetNotFound:      return "Could not find the selected video."
        case .noVideoResource:    return "The selected item has no video resource."
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
