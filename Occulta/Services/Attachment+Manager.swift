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
        let loader = ResourceLoader(fileURL: url, contactKey: self.contactKey)
        let asset  = AVURLAsset(url: Self.occattURL(for: url))
        asset.resourceLoader.setDelegate(loader, queue: .global(qos: .userInitiated))
        let player = AVPlayer(playerItem: AVPlayerItem(asset: asset))
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

    nonisolated static func write(_ plaintext: Data, contactKey: SymmetricKey, to url: URL) throws {
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
    private let fileURL:    URL
    private let contactKey: SymmetricKey

    init(fileURL: URL, contactKey: SymmetricKey) {
        self.fileURL    = fileURL
        self.contactKey = contactKey
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource request: AVAssetResourceLoadingRequest
    ) -> Bool {
        if let info = request.contentInformationRequest {
            guard let h = try? Decryptor.header(at: self.fileURL, contactKey: self.contactKey) else {
                request.finishLoading(with: AttachmentError.invalidHeader)
                return true
            }
            let uti = UTType(filenameExtension: self.fileURL.pathExtension)?.identifier
                   ?? UTType.movie.identifier
            info.contentType                = uti
            info.contentLength              = Int64(h.plaintextSize)
            info.isByteRangeAccessSupported = true
            if request.dataRequest == nil {
                request.finishLoading()
                return true
            }
        }
        if let data = request.dataRequest {
            let offset = Int(data.requestedOffset)
            let length = data.requestedLength
            do {
                let plain = try Decryptor.range(at: self.fileURL, offset: offset, length: length, contactKey: self.contactKey)
                data.respond(with: plain)
                request.finishLoading()
            } catch {
                request.finishLoading(with: error)
            }
        }
        return true
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
