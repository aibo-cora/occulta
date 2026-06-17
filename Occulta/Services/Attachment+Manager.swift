//
//  Attachment+Manager.swift
//  Occulta
//

import Foundation
import CryptoKit
import AVFoundation
import ImageIO
import UniformTypeIdentifiers
import UIKit

// MARK: - AttachmentManager

/// Encrypts and decrypts file attachments stored on disk.
///
/// Initialized once per contact session with that contact's long-term shared
/// secret. All per-file keys are derived internally via HKDF — callers never
/// see key material.
final class AttachmentManager: Sendable {
    private let contactKey: SymmetricKey

    init(contactKey: SymmetricKey) {
        self.contactKey = contactKey
    }

    // MARK: Write

    nonisolated func encrypt(_ data: Data, to url: URL) throws {
        try Encryptor.write(data, contactKey: self.contactKey, to: url)
    }

    func streamingEncryptor(to url: URL) throws -> StreamingEncryptor {
        try StreamingEncryptor(url: url, contactKey: self.contactKey)
    }

    nonisolated func encryptWithProgress(_ data: Data, to url: URL) -> AsyncThrowingStream<Double, Error> {
        let key = self.contactKey
        
        return AsyncThrowingStream { continuation in
            Task.detached(priority: .userInitiated) {
                do {
                    try Encryptor.write(data, contactKey: key, to: url) { @Sendable p in
                        continuation.yield(p)
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }

    // Extracts a thumbnail from raw (plaintext) video data. Writes to a protected
    // temp file, grabs frame 0, then immediately deletes the temp file.
    static func videoThumbnail(from data: Data, fileExtension ext: String) async -> UIImage? {
        try? await withCheckedThrowingContinuation { continuation in
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString)
                .appendingPathExtension(ext)
            
            defer { try? FileManager.default.removeItem(at: tmp) }
            
            guard (try? data.writeProtected(to: tmp)) != nil else {
                continuation.resume(throwing: AttachmentError.invalidImageData)
                
                return
            }
            
            let asset = AVURLAsset(url: tmp)
            let gen   = AVAssetImageGenerator(asset: asset)
            
            gen.appliesPreferredTrackTransform = true
            gen.maximumSize                    = CGSize(width: 600, height: 600)
            gen.generateCGImageAsynchronously(for: .zero) { cgImage, _, error in
                if let cgImage {
                    continuation.resume(returning: UIImage(cgImage: cgImage))
                } else if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(throwing: AttachmentError.invalidImageData)
                }
            }
        }
    }

    // MARK: Read

    func data(at url: URL) async throws -> Data {
        let key = self.contactKey
        
        return try await Task.detached(priority: .userInitiated) {
            try Decryptor.all(at: url, contactKey: key)
        }.value
    }

    // MARK: Image

    func image(at url: URL) async throws -> UIImage {
        let key = self.contactKey

        return try await Task.detached(priority: .userInitiated) {
            let data   = try Decryptor.all(at: url, contactKey: key)
            let source = CGImageSourceCreateWithData(data as CFData, nil)

            let options: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceThumbnailMaxPixelSize:          960,
                kCGImageSourceCreateThumbnailWithTransform:   true
            ]
            guard let source,
                  let cgImage = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary)
            else { throw AttachmentError.invalidImageData }
            
            return UIImage(cgImage: cgImage)
        }.value
    }

    // MARK: Video

    /// Returns an `AVPlayer` whose I/O is served by an encrypted resource loader.
    /// The player decrypts only the chunks AVFoundation requests — no plaintext
    /// file is ever written.
    func player(for url: URL) -> AVPlayer {
        guard let loader = ResourceLoader(fileURL: url, contactKey: self.contactKey) else {
            return AVPlayer()
        }
        let asset  = AVURLAsset(url: Self.occattURL(for: url))
        asset.resourceLoader.setDelegate(loader, queue: .global(qos: .userInitiated))
        let item = AVPlayerItem(asset: asset)
        // Limit pre-buffering — content is local so stalling is not a concern.
        item.preferredForwardBufferDuration = 2
        let player = AVPlayer(playerItem: item)
        player.automaticallyWaitsToMinimizeStalling = false
        // AVFoundation holds a weak reference to the delegate — retain it on the player.
        objc_setAssociatedObject(player, &AssociatedKeys.loader, loader, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        return player
    }

    // MARK: Share / export

    /// Returns a `UIActivityItemProvider` that decrypts the file on a background
    /// thread and hands the plaintext `Data` to the share sheet.
    func shareProvider(at url: URL, filename: String, contentType: UTType) -> UIActivityItemProvider {
        ShareProvider(fileURL: url, filename: filename, contentType: contentType, contactKey: self.contactKey)
    }

    // MARK: Private

    private static func occattURL(for fileURL: URL) -> URL {
        URL(string: "occatt://\(fileURL.lastPathComponent)")!
    }
}

// MARK: - Header (101 bytes)
//
//  Offset  Size  Field
//   0       4    magic "OATT"
//   4       1    version 0x01
//   5       4    chunk_size  (UInt32 big-endian)
//   9       8    chunk_count (UInt64 big-endian)
//  17       8    plaintext_size (UInt64 big-endian)
//  25      12    base_nonce (random)
//  37      32    key_salt   (random, per-file HKDF input)
//  69      32    header_mac (HMAC-SHA256 of bytes 0..<69)

private struct Header {
    nonisolated static let magic:     [UInt8] = Array("OATT".utf8)
    nonisolated static let version:   UInt8   = 0x01
    nonisolated static let byteCount: Int     = 101

    let chunkSize:     Int
    let chunkCount:    Int
    let plaintextSize: Int
    let baseNonce:     AES.GCM.Nonce
    let keySalt:       Data
}

// MARK: - Encryptor

private enum Encryptor {
    nonisolated static let chunkSize = 262_144 // 256 KB

    nonisolated static func write(
        _ plaintext: Data,
        contactKey: SymmetricKey,
        to url: URL,
        onProgress: (@Sendable (Double) -> Void)? = nil
    ) throws {
        let baseNonce = AES.GCM.Nonce()
        let keySalt   = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let fileKey   = derivedFileKey(contactKey: contactKey, salt: keySalt)
        let total     = plaintext.count
        let chunks    = max(1, (total + chunkSize - 1) / chunkSize)

        var header = Data()
        header.append(contentsOf: Header.magic)
        header.append(Header.version)
        header.append(contentsOf: UInt32(chunkSize).bigEndianData)
        header.append(contentsOf: UInt64(chunks).bigEndianData)
        header.append(contentsOf: UInt64(total).bigEndianData)
        header.append(contentsOf: baseNonce.dataRepresentation)
        header.append(contentsOf: keySalt)
        header.append(contentsOf: HMAC<SHA256>.authenticationCode(for: header, using: fileKey))

        var output = header
        for i in 0..<chunks {
            let start = i * chunkSize
            let end   = min(start + chunkSize, total)
            let box   = try AES.GCM.seal(
                total > 0 ? plaintext[start..<end] : Data(),
                using: fileKey,
                nonce: derivedNonce(base: baseNonce, index: i)
            )
            output.append(contentsOf: box.ciphertext)
            output.append(contentsOf: box.tag)
            onProgress?(Double(i + 1) / Double(chunks))
        }

        try output.writeProtected(to: url)
    }
}

// MARK: - Decryptor

private enum Decryptor {
    nonisolated static func all(at url: URL, contactKey: SymmetricKey) throws -> Data {
        let h = try header(at: url, contactKey: contactKey)
        guard h.plaintextSize > 0 else { return Data() }
        return try range(at: url, offset: 0, length: h.plaintextSize, contactKey: contactKey)
    }

    nonisolated static func range(at url: URL, offset: Int, length: Int, contactKey: SymmetricKey) throws -> Data {
        guard length > 0 else { return Data() }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        guard let headerBytes = try handle.read(upToCount: Header.byteCount),
              headerBytes.count == Header.byteCount
        else { throw AttachmentError.invalidHeader }

        let h             = try parseHeader(headerBytes, contactKey: contactKey)
        let fileKey       = derivedFileKey(contactKey: contactKey, salt: h.keySalt)
        let clampedLength = min(length, h.plaintextSize - offset)

        let first = offset / h.chunkSize
        let last  = min((offset + clampedLength - 1) / h.chunkSize, h.chunkCount - 1)

        var plaintext = Data()
        for i in first...last {
            let isLast         = i == h.chunkCount - 1
            let ciphertextSize = isLast ? h.plaintextSize - i * h.chunkSize : h.chunkSize
            try handle.seek(toOffset: UInt64(Header.byteCount + i * (h.chunkSize + 16)))
            guard let raw = try handle.read(upToCount: ciphertextSize + 16),
                  raw.count == ciphertextSize + 16
            else { throw AttachmentError.truncated }

            let box = try AES.GCM.SealedBox(
                nonce:      derivedNonce(base: h.baseNonce, index: i),
                ciphertext: raw.prefix(ciphertextSize),
                tag:        raw.suffix(16)
            )
            plaintext.append(contentsOf: try AES.GCM.open(box, using: fileKey))
        }

        let trimStart = offset - first * h.chunkSize
        return Data(plaintext[trimStart..<(trimStart + clampedLength)])
    }

    nonisolated static func header(at url: URL, contactKey: SymmetricKey) throws -> Header {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard let bytes = try handle.read(upToCount: Header.byteCount),
              bytes.count == Header.byteCount
        else { throw AttachmentError.invalidHeader }
        return try parseHeader(bytes, contactKey: contactKey)
    }

    private nonisolated static func parseHeader(_ bytes: Data, contactKey: SymmetricKey) throws -> Header {
        guard bytes.prefix(4).elementsEqual(Header.magic) else { throw AttachmentError.invalidHeader }
        guard bytes[4] == Header.version                  else { throw AttachmentError.unsupportedVersion }

        let chunkSize     = Int(UInt32(bigEndianBytes: bytes[5..<9]))
        let chunkCount    = Int(UInt64(bigEndianBytes: bytes[9..<17]))
        let plaintextSize = Int(UInt64(bigEndianBytes: bytes[17..<25]))
        let nonceData     = bytes[25..<37]
        let keySalt       = Data(bytes[37..<69])
        let storedMac     = Data(bytes[69..<101])

        let fileKey     = derivedFileKey(contactKey: contactKey, salt: keySalt)
        let computedMac = Data(HMAC<SHA256>.authenticationCode(for: bytes[..<69], using: fileKey))
        guard computedMac == storedMac else { throw AttachmentError.headerMACFailed }

        return Header(
            chunkSize:     chunkSize,
            chunkCount:    chunkCount,
            plaintextSize: plaintextSize,
            baseNonce:     try AES.GCM.Nonce(data: nonceData),
            keySalt:       keySalt
        )
    }
}

// MARK: - StreamingEncryptor

final class StreamingEncryptor: @unchecked Sendable {
    private let handle:    FileHandle
    private let fileKey:   SymmetricKey
    private let baseNonce: AES.GCM.Nonce
    private let keySalt:   Data
    private let chunkSize: Int
    private var index:     Int  = 0
    private var buffer:    Data = Data()

    private(set) var totalBytes: Int = 0

    init(url: URL, contactKey: SymmetricKey) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        
        self.handle    = try FileHandle(forWritingTo: url)
        // Bypass the page cache for all writes — prevents 2GB of dirty pages
        // accumulating in RAM during large video encryption.
        let result = fcntl(self.handle.fileDescriptor, F_NOCACHE, 1)
        
        #if DEBUG
        debugPrint("No cache setting result was \(result)")
        #endif
        
        self.chunkSize = Encryptor.chunkSize
        self.keySalt   = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        self.baseNonce = AES.GCM.Nonce()
        self.fileKey   = derivedFileKey(contactKey: contactKey, salt: self.keySalt)
        // Reserve space for header — finalize() overwrites it
        try self.handle.write(contentsOf: Data(count: Header.byteCount))
    }

    func append(_ incoming: Data) throws {
        self.totalBytes += incoming.count
        var offset = 0
        while offset < incoming.count {
            let take = min(self.chunkSize - self.buffer.count, incoming.count - offset)
            self.buffer.append(contentsOf: incoming[offset..<(offset + take)])
            offset += take
            if self.buffer.count == self.chunkSize {
                try self.flush(self.buffer)
                self.buffer.removeAll(keepingCapacity: true)
            }
        }
    }

    func finalize() throws {
        // Only flush remaining bytes; skip if input was an exact multiple of chunkSize
        if !self.buffer.isEmpty || self.index == 0 {
            try self.flush(self.buffer)
        }
        self.buffer.removeAll()
        try self.handle.synchronize()

        var hdr = Data()
        hdr.append(contentsOf: Header.magic)
        hdr.append(Header.version)
        hdr.append(contentsOf: UInt32(self.chunkSize).bigEndianData)
        hdr.append(contentsOf: UInt64(self.index).bigEndianData)
        hdr.append(contentsOf: UInt64(self.totalBytes).bigEndianData)
        hdr.append(contentsOf: self.baseNonce.dataRepresentation)
        hdr.append(contentsOf: self.keySalt)
        hdr.append(contentsOf: HMAC<SHA256>.authenticationCode(for: hdr, using: self.fileKey))

        try self.handle.seek(toOffset: 0)
        try self.handle.write(contentsOf: hdr)
        try self.handle.close()
    }

    private func flush(_ plaintext: Data) throws {
        let box = try AES.GCM.seal(
            plaintext,
            using: self.fileKey,
            nonce: derivedNonce(base: self.baseNonce, index: self.index)
        )
        try self.handle.write(contentsOf: box.ciphertext)
        try self.handle.write(contentsOf: box.tag)
        self.index += 1
    }
}

// MARK: - Helpers

nonisolated private func derivedFileKey(contactKey: SymmetricKey, salt: some DataProtocol) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(
        inputKeyMaterial: contactKey,
        salt:             salt,
        info:             SaltInfo.kFileKeyInfo,
        outputByteCount:  32
    )
}

nonisolated private func derivedNonce(base: AES.GCM.Nonce, index: Int) throws -> AES.GCM.Nonce {
    var bytes = base.withUnsafeBytes { Array($0) }
    let idx   = withUnsafeBytes(of: UInt64(index).bigEndian) { Array($0) }
    for j in 0..<8 { bytes[4 + j] ^= idx[j] }
    return try AES.GCM.Nonce(data: Data(bytes))
}

// MARK: - Resource Loader (in-app video playback)

private final class ResourceLoader: NSObject, AVAssetResourceLoaderDelegate {
    private let fileURL: URL
    private let header:  Header
    private let fileKey: SymmetricKey

    // Parses and HMAC-validates the header once at init. Returns nil if the
    // file is unreadable or the key is wrong — AVFoundation will show a blank player.
    init?(fileURL: URL, contactKey: SymmetricKey) {
        guard let h = try? Decryptor.header(at: fileURL, contactKey: contactKey) else { return nil }
        self.fileURL = fileURL
        self.header  = h
        self.fileKey = derivedFileKey(contactKey: contactKey, salt: h.keySalt)
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource request: AVAssetResourceLoadingRequest
    ) -> Bool {
        if let info = request.contentInformationRequest {
            let uti = UTType(filenameExtension: self.fileURL.pathExtension)?.identifier
                   ?? UTType.movie.identifier
            info.contentType                = uti
            info.contentLength              = Int64(self.header.plaintextSize)
            info.isByteRangeAccessSupported = true
            if request.dataRequest == nil {
                request.finishLoading()
                return true
            }
        }
        if let dataReq = request.dataRequest {
            var cursor = Int(dataReq.currentOffset)
            let end    = Int(dataReq.requestedOffset) + dataReq.requestedLength
            do {
                // One FileHandle per AVFoundation request, shared across all chunks in
                // that request — avoids a file open/close per 256KB chunk.
                let handle = try FileHandle(forReadingFrom: self.fileURL)
                defer { try? handle.close() }
                while cursor < end {
                    let length = min(self.header.chunkSize, end - cursor)
                    let chunk  = try self.decryptChunk(at: cursor, length: length, using: handle)
                    dataReq.respond(with: chunk)
                    cursor += chunk.count
                    if chunk.count < length { break }
                }
                request.finishLoading()
            } catch {
                request.finishLoading(with: error)
            }
        }
        return true
    }

    private func decryptChunk(at offset: Int, length: Int, using handle: FileHandle) throws -> Data {
        let h             = self.header
        let clampedLength = min(length, h.plaintextSize - offset)
        guard clampedLength > 0 else { return Data() }

        let first = offset / h.chunkSize
        let last  = min((offset + clampedLength - 1) / h.chunkSize, h.chunkCount - 1)

        var plaintext = Data()
        for i in first...last {
            let isLast         = i == h.chunkCount - 1
            let ciphertextSize = isLast ? h.plaintextSize - i * h.chunkSize : h.chunkSize
            try handle.seek(toOffset: UInt64(Header.byteCount + i * (h.chunkSize + 16)))
            guard let raw = try handle.read(upToCount: ciphertextSize + 16),
                  raw.count == ciphertextSize + 16
            else { throw AttachmentError.truncated }
            let box = try AES.GCM.SealedBox(
                nonce:      derivedNonce(base: h.baseNonce, index: i),
                ciphertext: raw.prefix(ciphertextSize),
                tag:        raw.suffix(16)
            )
            plaintext.append(contentsOf: try AES.GCM.open(box, using: self.fileKey))
        }

        let trimStart = offset - first * h.chunkSize
        return Data(plaintext[trimStart..<(trimStart + clampedLength)])
    }
}

// MARK: - Share Provider

// UIActivityItemProvider is @MainActor in UIKit. Stored properties are nonisolated
// so that item and activityViewController can run on UIKit's background thread.
private final class ShareProvider: UIActivityItemProvider, @unchecked Sendable {
    nonisolated let fileURL:     URL
    nonisolated let filename:    String
    nonisolated let contentType: UTType
    nonisolated let contactKey:  SymmetricKey

    nonisolated init(fileURL: URL, filename: String, contentType: UTType, contactKey: SymmetricKey) {
        self.fileURL     = fileURL
        self.filename    = filename
        self.contentType = contentType
        self.contactKey  = contactKey
        super.init(placeholderItem: Data())
    }

    nonisolated override init(placeholderItem item: Any) {
        self.fileURL     = URL(fileURLWithPath: "")
        self.filename    = ""
        self.contentType = .data
        self.contactKey  = SymmetricKey(size: .bits256)
        super.init(placeholderItem: item)
    }

    // Called on a background thread by UIActivityViewController.
    nonisolated override var item: Any {
        (try? Decryptor.all(at: self.fileURL, contactKey: self.contactKey)) ?? Data()
    }

    nonisolated override func activityViewController(
        _ ac: UIActivityViewController,
        subjectForActivityType type: UIActivity.ActivityType?
    ) -> String { self.filename }

    nonisolated override func activityViewController(
        _ ac: UIActivityViewController,
        dataTypeIdentifierForActivityType type: UIActivity.ActivityType?
    ) -> String { self.contentType.identifier }
}

// MARK: - Errors

enum AttachmentError: Error {
    case invalidHeader
    case unsupportedVersion
    case headerMACFailed
    case truncated
    case invalidImageData
}

// MARK: - Associated object key

private enum AssociatedKeys {
    static var loader: UInt8 = 0
}

// MARK: - Encoding helpers

private extension UInt32 {
    nonisolated var bigEndianData: Data { withUnsafeBytes(of: self.bigEndian) { Data($0) } }
    nonisolated init(bigEndianBytes bytes: some DataProtocol) {
        var v: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &v) { ptr in bytes.copyBytes(to: ptr) }
        self = UInt32(bigEndian: v)
    }
}

private extension UInt64 {
    nonisolated var bigEndianData: Data { withUnsafeBytes(of: self.bigEndian) { Data($0) } }
    nonisolated init(bigEndianBytes bytes: some DataProtocol) {
        var v: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &v) { ptr in bytes.copyBytes(to: ptr) }
        self = UInt64(bigEndian: v)
    }
}

private extension AES.GCM.Nonce {
    nonisolated var dataRepresentation: Data { self.withUnsafeBytes { Data($0) } }
}
