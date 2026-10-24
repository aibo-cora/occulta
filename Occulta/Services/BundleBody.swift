//
//  BundleBody.swift
//  Occulta
//
//  The body of a group bundle, whichever layout it came in. Four places open one — `openRecipientSlot`,
//  `openGroup`, `openCardSlot` and the card first-message recognition — and each asks the same four questions
//  of it, so the checks are written once and work on both layouts. STREAMING_SPEC §5.4.
//

import Foundation
import CryptoKit
import OccultaFormats

// MARK: - BundleBody

nonisolated enum BundleBody {

    /// The inline layout: the body is `bundle.ciphertext`, one AES-GCM seal, held in memory.
    case inline(OccultaBundle)

    /// The streamed layout: the body is a chunk stream, read from the file as it is wanted.
    case streamed(StreamedBody)

    /// SHA-256 over the *T* bytes of the body, which a slot's `bodyDigest` must equal (Bug 165).
    /// For the streamed layout this is pass 1: the stream is hashed from disk, and not twice.
    func digest() throws -> Data {
        switch self {
        case .inline(let bundle): return Data(SHA256.hash(data: bundle.ciphertext))
        case .streamed(let body): return try body.digest()
        }
    }

    /// The outer header is authenticated only by opening the body under the slot's key (Bug 181): the
    /// whole of it for the inline layout, chunk 0 for the streamed one. The result is discarded.
    func authenticateHeader(sessionKey: SymmetricKey) throws {
        switch self {
        case .inline(let bundle): _ = try Self.openInline(bundle, using: sessionKey)
        case .streamed(let body): try body.authenticateHeader(sessionKey: sessionKey)
        }
    }

    /// The bundle's `SealedPayload`: everything but the streamed files' bytes.
    func openManifest(sessionKey: SymmetricKey) throws -> OpenedManifest {
        switch self {
        case .inline(let bundle):
            let plaintext = try Self.openInline(bundle, using: sessionKey)
            return OpenedManifest(payload: try WireHandle.decode(payload: plaintext), cursor: nil)
        case .streamed(let body):
            return try body.openManifest(sessionKey: sessionKey)
        }
    }

    /// AAD = `computeAdditionalAuthentication(version:secrecy:) ‖ group.blind`. One implementation, which
    /// `Manager.Crypto.openGroupCiphertext` uses too.
    static func openInline(_ bundle: OccultaBundle, using sessionKey: SymmetricKey) throws -> Data {
        guard let group = bundle.group else { throw GroupDecryptError.noGroupEnvelope }
        var aad = try OccultaBundle.computeAdditionalAuthentication(version: bundle.version, secrecy: bundle.secrecy)
        aad.append(group.blind)
        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        return try AES.GCM.open(box, using: sessionKey, authenticating: aad)
    }
}

/// What opening a body's manifest gives: the payload, and for the streamed layout where pass 2 resumes.
nonisolated struct OpenedManifest {
    let payload: OccultaBundle.SealedPayload
    /// Nil for the inline layout, whose files are already in `payload`.
    let cursor: StreamCursor?
}

// MARK: - StreamedBody

/// A streamed bundle's body, read from an open file. Nothing here holds more than a chunk or two.
nonisolated final class StreamedBody: @unchecked Sendable {

    /// Sections of a streamed bundle are the group envelope; no honest one is anywhere near this (§5.2).
    static let maxSectionsLength: UInt64 = 8 * 1024 * 1024

    /// The envelope: the header and the group sections, with an empty `ciphertext`.
    let bundle: OccultaBundle
    let layout: BodyStream.Layout

    private let reader: NoCacheFile.Reader
    private let headerAAD: Data
    private let lock = NSLock()
    private var memoisedDigest: Data?

    private var streamStart: UInt64 { UInt64(WireHandle.headerLength) }

    /// Parses the header and sections of the streamed bundle in `reader` (§5.2 step 1) and checks that the
    /// file is exactly as long as they say. Throws `malformedBundle` otherwise.
    init(reader: NoCacheFile.Reader) throws {
        let malformed = OccultaBundle.BundleError.malformedBundle
        guard reader.size >= UInt64(WireHandle.headerLength) else { throw malformed }

        let header = try WireHandle.parseHeader(try reader.read(at: 0, count: WireHandle.headerLength))
        guard header.version == WireHandle.streamedVersionByte else { throw OccultaBundle.BundleError.unsupportedVersion }

        let layout: BodyStream.Layout
        do { layout = try BodyStream.Layout(streamLength: header.ciphertextLength) } catch { throw malformed }

        let (streamEnd, overflow) = UInt64(WireHandle.headerLength).addingReportingOverflow(layout.streamLength)
        guard !overflow, streamEnd <= reader.size, reader.size - streamEnd <= Self.maxSectionsLength else { throw malformed }

        let sections = try WireHandle.parseSections(try reader.read(at: streamEnd, count: Int(reader.size - streamEnd)))
        let bundle = try OccultaBundle(header: header, sections: sections)

        guard let group = bundle.group else { throw malformed }
        self.bundle    = bundle
        self.layout    = layout
        self.reader    = reader
        self.headerAAD = try BodyStream.headerAAD(secrecy: bundle.secrecy, blind: group.blind)
    }

    // MARK: Pass 1

    /// SHA-256 of the chunk stream, hashed from disk once and remembered.
    func digest() throws -> Data {
        self.lock.lock(); defer { self.lock.unlock() }
        if let memoised = self.memoisedDigest { return memoised }

        var hasher = SHA256()
        try self.reader.forEachChunk(
            range: self.streamStart..<(self.streamStart + self.layout.streamLength), size: BodyStream.wireChunkSize
        ) { hasher.update(data: $0) }

        let digest = Data(hasher.finalize())
        self.memoisedDigest = digest
        return digest
    }

    // MARK: Header check and manifest

    func authenticateHeader(sessionKey: SymmetricKey) throws {
        var opener = BodyStream.Opener(sessionKey: sessionKey, header: self.headerAAD, layout: self.layout)
        _ = try opener.open(try self.chunk(0), index: 0)
    }

    /// Opens chunks in order until the manifest is whole (§5.2 step 6), and keeps the plaintext after it.
    func openManifest(sessionKey: SymmetricKey) throws -> OpenedManifest {
        var opener = BodyStream.Opener(sessionKey: sessionKey, header: self.headerAAD, layout: self.layout)
        var plaintext = Data()
        var manifestLength: Int?

        while true {
            if manifestLength == nil, plaintext.count >= BodyStream.Manifest.prefixLength {
                manifestLength = try BodyStream.Manifest.length(prefix: plaintext)
            }
            if let manifestLength, plaintext.count >= BodyStream.Manifest.prefixLength + manifestLength { break }
            guard !opener.isFinished else { throw OccultaBundle.BundleError.malformedBundle }

            let index = opener.nextIndex
            plaintext.append(try opener.open(try self.chunk(index), index: index))
        }

        let manifestEnd = BodyStream.Manifest.prefixLength + manifestLength!
        let payload = try BodyStream.Manifest.decode(plaintext.subdata(in: BodyStream.Manifest.prefixLength..<manifestEnd))
        let cursor = StreamCursor(
            opener: opener, carry: plaintext.subdata(in: manifestEnd..<plaintext.count),
            manifestLength: manifestLength!, layout: self.layout
        )
        return OpenedManifest(payload: payload, cursor: cursor)
    }

    // MARK: Pass 2

    /// Opens the rest of the stream and routes it, in manifest order, to `sink` (§5.2 step 8). Checks for
    /// cancellation at every chunk. Throws if the stream's bytes are not exactly what the manifest says.
    func streamFiles(cursor: StreamCursor, streamedLengths: [UInt64?], sink: StreamSink) throws {
        var router = StreamRouter(lengths: streamedLengths)
        try router.consume(cursor.carry, into: sink)
        cursor.carry = Data()

        while !cursor.opener.isFinished {
            try Task.checkCancellation()
            let index = cursor.opener.nextIndex
            let plaintext = try cursor.opener.open(try self.chunk(index), index: index)
            try router.consume(plaintext, into: sink)
        }
        try router.finish(into: sink)
    }

    private func chunk(_ index: UInt64) throws -> Data {
        let wire = self.layout.wireLength(ofChunk: index)
        let data = try self.reader.read(at: self.streamStart + self.layout.wireOffset(ofChunk: index), count: wire)
        guard data.count == wire else { throw OccultaBundle.BundleError.malformedBundle }
        return data
    }
}

/// Where pass 2 resumes: the opener part-way through the stream, and the plaintext already opened past the
/// manifest.
nonisolated final class StreamCursor: @unchecked Sendable {
    fileprivate var opener: BodyStream.Opener
    fileprivate var carry: Data
    let manifestLength: Int
    let layout: BodyStream.Layout

    fileprivate init(opener: BodyStream.Opener, carry: Data, manifestLength: Int, layout: BodyStream.Layout) {
        self.opener = opener
        self.carry = carry
        self.manifestLength = manifestLength
        self.layout = layout
    }

    /// What the manifest says follows it must be exactly what the stream holds (§5.3). Checked the moment
    /// the basket is decoded, so a bundle whose lengths disagree is refused before any file is written.
    func validate(streamedLengths: [UInt64?]) throws {
        try BodyStream.Manifest.validate(manifestLength: self.manifestLength, streamedLengths: streamedLengths, against: self.layout)
    }
}

// MARK: - Routing

/// Receives the streamed files' bytes, one file after another, in manifest order.
nonisolated protocol StreamSink: AnyObject {
    /// The file at this index of the basket begins. Called for a zero-length file too.
    func begin(fileIndex: Int) throws
    func write(_ data: Data) throws
    /// The file's last byte has been written.
    func end() throws
}

/// Splits the plaintext after the manifest into the streamed files, by the lengths the manifest gave.
///
/// Pure: it sees only byte counts. A file is ended the moment its last byte is routed, so its placeholder can
/// be replaced then and not at the end of the stream. Bytes beyond the last file, or a stream that ends with a
/// file still short, are `lengthMismatch`.
nonisolated struct StreamRouter {
    private var queue: [(fileIndex: Int, length: UInt64)]
    private var position = 0
    private var remaining: UInt64 = 0
    private var isOpen = false

    /// `lengths` runs parallel to the basket's files; a nil entry is not streamed.
    init(lengths: [UInt64?]) {
        self.queue = lengths.enumerated().compactMap { index, length in length.map { (index, $0) } }
        self.remaining = self.queue.first?.length ?? 0
    }

    mutating func consume(_ data: Data, into sink: StreamSink) throws {
        var rest = data[...]
        while !rest.isEmpty {
            try self.skipEmptyFiles(into: sink)
            guard self.position < self.queue.count else { throw BodyStream.StreamError.lengthMismatch }
            try self.openIfNeeded(into: sink)

            let take = Int(min(self.remaining, UInt64(rest.count)))
            try sink.write(Data(rest.prefix(take)))
            rest = rest.dropFirst(take)
            self.remaining -= UInt64(take)
            if self.remaining == 0 { try self.close(into: sink) }
        }
    }

    /// The stream is over: every file must be complete and nothing may be left to route.
    mutating func finish(into sink: StreamSink) throws {
        try self.skipEmptyFiles(into: sink)
        guard self.position == self.queue.count, !self.isOpen else { throw BodyStream.StreamError.lengthMismatch }
    }

    private mutating func skipEmptyFiles(into sink: StreamSink) throws {
        while self.position < self.queue.count, !self.isOpen, self.remaining == 0 {
            try self.openIfNeeded(into: sink)
            try self.close(into: sink)
        }
    }

    private mutating func openIfNeeded(into sink: StreamSink) throws {
        guard !self.isOpen else { return }
        try sink.begin(fileIndex: self.queue[self.position].fileIndex)
        self.isOpen = true
    }

    private mutating func close(into sink: StreamSink) throws {
        try sink.end()
        self.isOpen = false
        self.position += 1
        self.remaining = self.position < self.queue.count ? self.queue[self.position].length : 0
    }
}
