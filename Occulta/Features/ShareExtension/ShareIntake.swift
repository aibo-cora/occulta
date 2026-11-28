//
//  ShareIntake.swift
//  Occulta
//
//  What the share extension does with a file it is handed, apart from the view controller that asks for it: the size
//  limits, the choice of type, sealing a file into the session directory, and writing the manifest. Linked by both the
//  main app and the share extension. The extension can't be driven from the test host, so this is the part of its
//  logic a test can reach (register D5); `ShareViewController` only asks the system for the file and calls these.
//
//  Moved out of `ShareViewController` as it was, without a change in what any of it does. The inbound `.occ` handoff
//  stays in the view controller (Bug 188).
//

import Foundation
import CryptoKit
import UniformTypeIdentifiers

nonisolated enum ShareIntake {

    /// Per-file ceiling for a file the provider hands over by URL. Staging streams, so memory no longer grows with it;
    /// the cap stays until the extension's peak memory has been measured on a device (STREAMING_SPEC §8.4).
    static let maxFileBytes = 100_000_000

    /// Ceiling for the fallback that loads a provider's data into memory, which can't be streamed.
    static let maxDataBytes = 10_000_000

    /// The chunk the source is read and sealed in.
    static let chunkBytes = 65_536

    enum Refusal: Error {
        case fileTooLarge
    }

    /// The type identifier to ask a provider for, and the extension to record for it: the first one the provider
    /// registers, or plain data when it registers none, and that type's preferred extension, or `bin`.
    static func requestedType(registered identifiers: [String]) -> (uti: String, fileExtension: String) {
        let uti = identifiers.first ?? UTType.data.identifier
        let type = UTType(uti) ?? .data
        return (uti, type.preferredFilenameExtension ?? "bin")
    }

    /// Seals the file at `source` as a `.eatt` at `destination`, 64 KB at a time. The source is never read whole.
    ///
    /// Refuses a source over `maxFileBytes` before reading a byte, so the user gets a clean cancel. `key` is asked for
    /// after that and after the source is open, as it always was: deriving it is a Secure Enclave operation. The
    /// destination has complete protection, stays out of the page cache, and is removed if the sealing fails.
    ///
    /// - Throws: `Refusal.fileTooLarge`, or whatever opening, reading or sealing throws.
    static func seal(
        fileAt source: URL, to destination: URL, key: () throws -> SymmetricKey, afterChunk: () -> Void = {}
    ) throws {
        let size = try source.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= Self.maxFileBytes else { throw Refusal.fileTooLarge }

        let reader = try NoCacheFile.reader(source)
        let encryptor = try StreamingEncryptor(url: destination, contactKey: try key())
        try reader.forEachChunk(range: 0..<reader.size, size: Self.chunkBytes) {
            try encryptor.append($0)
            afterChunk()
        }
        try encryptor.finalize()
    }

    /// Seals `data` as a `.eatt` at `destination`: the fallback for a provider that has no file to give. Refuses more than
    /// `maxDataBytes`, which is all that is held in memory.
    static func seal(_ data: Data, to destination: URL, key: () throws -> SymmetricKey) throws {
        guard data.count <= Self.maxDataBytes else { throw Refusal.fileTooLarge }

        let encryptor = try StreamingEncryptor(url: destination, contactKey: try key())
        try encryptor.append(data)
        try encryptor.finalize()
    }

    /// Encodes `manifest`, seals it with `encrypting`, zeroes the plaintext, and writes `manifest.enc` into `directory` with
    /// complete protection applied by the write itself, so there is no window at the default class.
    static func writeManifest(_ manifest: ShareManifest, in directory: URL, encrypting: (Data) throws -> Data) throws {
        var manifestData = try JSONEncoder().encode(manifest)
        let encryptedManifest = try encrypting(manifestData)

        // Zero plaintext manifest. It no longer carries a recipient, but it still lists
        // original file extensions, and it stays encrypted for that reason.
        _ = manifestData.withUnsafeMutableBytes { buffer in
            memset(buffer.baseAddress!, 0, buffer.count)
        }
        manifestData = Data()

        try encryptedManifest.write(to: directory.appendingPathComponent("manifest.enc"), options: .completeFileProtection)
    }
}
