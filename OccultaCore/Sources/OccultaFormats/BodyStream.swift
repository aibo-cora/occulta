//
//  BodyStream.swift
//  OccultaFormats
//
//  The streamed bundle body: a chunked STREAM construction over AES-256-GCM, so neither side holds a
//  whole attachment in memory. Pure: no I/O, no keys beyond the ones handed in.
//  See Docs/Features/Bundle/STREAMING_SPEC.md §4 and §8.1.
//

import CryptoKit
import Foundation

// MARK: - BodyStream

/// The chunk stream that sits where the AES-GCM combined ciphertext sits in the inline layout.
///
/// Send builds a `Layout` from the plaintext length *P* and feeds a `Sealer`; receive builds one from the
/// header's `ciphertext_length` *T* and feeds an `Opener`. Nonce and AAD derivation exist once, in `seal`
/// and `open` below.
public enum BodyStream {

    // MARK: Constants

    /// Plaintext bytes per chunk. The same value as `Encryptor.chunkSize` for the at-rest `.eatt` format.
    public static let chunkSize = 262_144

    /// AES-GCM tag, appended to every chunk. Nonces are not transmitted.
    public static let tagSize = 16

    /// A chunk on the wire: `ciphertext ‖ tag`.
    public static let wireChunkSize = chunkSize + tagSize

    /// `manifest_length` is at most this (§4.4).
    public static let maxManifestLength = 16 * 1024 * 1024

    /// Domain separator for `streamKey`.
    static let keyInfo = Data("occulta-body-stream-v1".utf8)

    /// The smallest plaintext: the 4-byte `manifest_length` and a manifest of at least one byte.
    static let minimumPlaintextLength: UInt64 = 5

    /// A bound that keeps every length computation clear of overflow. A terabyte is already unreachable.
    static let maximumPlaintextLength: UInt64 = 1 << 50

    /// The longest stream a valid layout can have: that plaintext and a tag on every chunk.
    static let maximumStreamLength: UInt64 =
        maximumPlaintextLength + UInt64(tagSize) * (maximumPlaintextLength / UInt64(chunkSize) + 1)

    // MARK: Errors

    public enum StreamError: Error, Equatable {
        /// *P* or *T* does not describe a valid chunk stream.
        case invalidLayout
        /// A chunk arrived for an index other than the next one.
        case chunkOutOfOrder
        /// A chunk arrived after the final one had been opened.
        case chunkAfterFinal
        /// The chunk is not the size the layout gives for its index.
        case chunkWrongSize
        /// The tag did not verify: a wrong key, header, index or final flag, or an altered chunk.
        case chunkNotAuthentic
        /// More plaintext was fed to the `Sealer` than the layout holds.
        case tooMuchInput
        /// `finish()` was called before the layout's plaintext had all been fed.
        case inputShort
        /// The `Sealer` has already finished.
        case alreadyFinished
        /// `manifest_length` is zero or over 16 MiB.
        case manifestLengthOutOfRange
        /// The manifest's streamed lengths do not add up to the stream's plaintext length.
        case lengthMismatch
    }

    // MARK: Key, nonce, AAD

    /// One key per bundle, derived from the group session key (§4.3). `HKDF-SHA256` with an *empty* salt.
    public static func streamKey(sessionKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: sessionKey, salt: Data(), info: Self.keyInfo, outputByteCount: 32)
    }

    /// Chunk *i*'s nonce: `0x00000000 ‖ u64(i)`.
    ///
    /// Deterministic nonces are safe because `streamKey` is fresh for every bundle and each index is sealed once.
    public static func nonce(index: UInt64) -> AES.GCM.Nonce {
        var bytes = Data(count: 4)
        bytes.append(Self.bigEndian(index))
        return try! AES.GCM.Nonce(data: bytes)  // always 12 bytes
    }

    /// The outer header's authenticated data, as every chunk carries it:
    /// `computeAdditionalAuthentication(version: .streamedBodyCapable, secrecy:) ‖ blind`.
    public static func headerAAD(secrecy: OccultaBundle.SecrecyContext, blind: Data) throws -> Data {
        var aad = try OccultaBundle.computeAdditionalAuthentication(version: .streamedBodyCapable, secrecy: secrecy)
        aad.append(blind)
        return aad
    }

    /// Chunk *i*'s authenticated data: `headerAAD ‖ u64(i) ‖ u8(final)`.
    ///
    /// The header binds every chunk to the bundle's envelope, the index binds its place, and the final flag
    /// makes a stream cut short end on a chunk sealed as not-final.
    public static func aad(header: Data, index: UInt64, final: Bool) -> Data {
        var aad = header
        aad.append(Self.bigEndian(index))
        aad.append(final ? 0x01 : 0x00)
        return aad
    }

    // MARK: Layout

    /// How *P* plaintext bytes lie in chunks, and *T* wire bytes with them.
    ///
    /// *n* = ⌈*P* / *C*⌉. Every chunk but the last carries *C* plaintext bytes; the last carries between 1 and
    /// *C*. A *P* that is a multiple of *C* ends on a full chunk, never an empty trailer. *T* = *P* + 16*n*.
    public struct Layout: Equatable, Sendable {
        /// *P*.
        public let plaintextLength: UInt64
        /// *T*, the `ciphertext_length` of the outer header.
        public let streamLength: UInt64
        /// *n*.
        public let chunkCount: UInt64
        /// Plaintext bytes in the final chunk: 1 through `chunkSize`.
        public let lastChunkPlaintextLength: Int

        /// The layout of a stream of *P* plaintext bytes. Send side.
        public init(plaintextLength p: UInt64) throws {
            guard p >= BodyStream.minimumPlaintextLength, p <= BodyStream.maximumPlaintextLength else {
                throw StreamError.invalidLayout
            }
            let c = UInt64(BodyStream.chunkSize)
            let n = (p + c - 1) / c
            self.plaintextLength = p
            self.chunkCount = n
            self.lastChunkPlaintextLength = Int(p - (n - 1) * c)
            self.streamLength = p + UInt64(BodyStream.tagSize) * n
        }

        /// The layout of a stream *T* bytes long. Receive side.
        ///
        /// Rejects a *T* whose last chunk would be shorter than 17 bytes: a tag and not one plaintext byte.
        public init(streamLength t: UInt64) throws {
            let w = UInt64(BodyStream.wireChunkSize)
            guard t > 0, t <= BodyStream.maximumStreamLength else { throw StreamError.invalidLayout }
            let n = (t + w - 1) / w
            let lastWire = t - (n - 1) * w
            guard lastWire > UInt64(BodyStream.tagSize) else { throw StreamError.invalidLayout }
            let p = t - UInt64(BodyStream.tagSize) * n
            guard p >= BodyStream.minimumPlaintextLength else { throw StreamError.invalidLayout }
            self.plaintextLength = p
            self.chunkCount = n
            self.lastChunkPlaintextLength = Int(lastWire) - BodyStream.tagSize
            self.streamLength = t
        }

        /// Plaintext bytes in chunk `index`.
        public func plaintextLength(ofChunk index: UInt64) -> Int {
            index + 1 == self.chunkCount ? self.lastChunkPlaintextLength : BodyStream.chunkSize
        }

        /// Wire bytes in chunk `index`: its plaintext and the tag.
        public func wireLength(ofChunk index: UInt64) -> Int {
            self.plaintextLength(ofChunk: index) + BodyStream.tagSize
        }

        /// Where chunk `index` begins in the stream.
        public func wireOffset(ofChunk index: UInt64) -> UInt64 {
            index * UInt64(BodyStream.wireChunkSize)
        }

        public func isFinal(_ index: UInt64) -> Bool { index + 1 == self.chunkCount }
    }

    // MARK: ChunkBuffer

    /// Fixed-size accumulation: hands out each complete chunk in order and keeps the rest.
    ///
    /// The logic `StreamingEncryptor.append` had, in one place for it and the `Sealer`.
    public struct ChunkBuffer: Sendable {
        public let chunkSize: Int
        private var buffer = Data()

        public init(chunkSize: Int) {
            precondition(chunkSize > 0)
            self.chunkSize = chunkSize
            self.buffer.reserveCapacity(chunkSize)
        }

        /// Bytes held, fewer than `chunkSize` between calls.
        public var count: Int { self.buffer.count }

        /// Adds `data`, passing every chunk it completes to `emit`. The chunk is only valid for the call.
        public mutating func append(_ data: Data, emit: (Data) throws -> Void) rethrows {
            var offset = data.startIndex
            while offset < data.endIndex {
                let take = min(self.chunkSize - self.buffer.count, data.endIndex - offset)
                self.buffer.append(data[offset..<(offset + take)])
                offset += take
                if self.buffer.count == self.chunkSize {
                    try emit(self.buffer)
                    self.buffer.removeAll(keepingCapacity: true)
                }
            }
        }

        /// The bytes held back, and empties the buffer. Fewer than `chunkSize`.
        public mutating func drain() -> Data {
            defer { self.buffer.removeAll(keepingCapacity: true) }
            return self.buffer
        }
    }

    // MARK: Sealer

    /// Send side. Feed it the plaintext in any piece sizes; it emits sealed chunks and hashes what it emits.
    ///
    /// The `Layout` fixes the length up front, which the header's `ciphertext_length` needs anyway, so the
    /// sealer knows which chunk is the last without holding one back.
    public struct Sealer {
        private let key: SymmetricKey
        private let header: Data
        public let layout: Layout
        private var buffer = ChunkBuffer(chunkSize: BodyStream.chunkSize)
        private var hasher = SHA256()
        private var index: UInt64 = 0
        private var fed: UInt64 = 0
        private var finished = false

        public init(sessionKey: SymmetricKey, header: Data, layout: Layout) {
            self.key = BodyStream.streamKey(sessionKey: sessionKey)
            self.header = header
            self.layout = layout
        }

        /// Adds plaintext. Each chunk it completes goes to `emit` as `ciphertext ‖ tag`, and into the digest.
        public mutating func append(_ plaintext: Data, emit: (Data) throws -> Void) throws {
            guard !self.finished else { throw StreamError.alreadyFinished }
            guard UInt64(plaintext.count) <= self.layout.plaintextLength - self.fed else { throw StreamError.tooMuchInput }
            self.fed += UInt64(plaintext.count)

            let key = self.key, header = self.header, layout = self.layout
            var index = self.index
            var hasher = self.hasher
            try self.buffer.append(plaintext) { chunk in
                let sealed = try BodyStream.seal(chunk: chunk, index: index, final: layout.isFinal(index), key: key, header: header)
                hasher.update(data: sealed)
                try emit(sealed)
                index += 1
            }
            self.index = index
            self.hasher = hasher
        }

        /// Seals the final chunk if it is still held, and returns the SHA-256 of the whole stream: the
        /// `bodyDigest` for every recipient slot (§4.5).
        public mutating func finish(emit: (Data) throws -> Void) throws -> Data {
            guard !self.finished else { throw StreamError.alreadyFinished }
            guard self.fed == self.layout.plaintextLength else { throw StreamError.inputShort }

            let rest = self.buffer.drain()
            if !rest.isEmpty {
                let sealed = try BodyStream.seal(chunk: rest, index: self.index, final: true, key: self.key, header: self.header)
                self.hasher.update(data: sealed)
                try emit(sealed)
                self.index += 1
            }
            self.finished = true
            return Data(self.hasher.finalize())
        }
    }

    // MARK: Opener

    /// Receive side. Opens one wire chunk at a time, in order, against the layout.
    public struct Opener {
        private let key: SymmetricKey
        private let header: Data
        public let layout: Layout
        /// The index the next chunk must carry. Equals `layout.chunkCount` once the final chunk has opened.
        public private(set) var nextIndex: UInt64 = 0

        public init(sessionKey: SymmetricKey, header: Data, layout: Layout) {
            self.key = BodyStream.streamKey(sessionKey: sessionKey)
            self.header = header
            self.layout = layout
        }

        public var isFinished: Bool { self.nextIndex == self.layout.chunkCount }

        /// Opens chunk `index`, which must be the next one and exactly the size the layout gives it.
        public mutating func open(_ chunk: Data, index: UInt64) throws -> Data {
            guard !self.isFinished else { throw StreamError.chunkAfterFinal }
            guard index == self.nextIndex else { throw StreamError.chunkOutOfOrder }
            guard chunk.count == self.layout.wireLength(ofChunk: index) else { throw StreamError.chunkWrongSize }

            let plaintext = try BodyStream.open(
                chunk: chunk, index: index, final: self.layout.isFinal(index), key: self.key, header: self.header
            )
            self.nextIndex += 1
            return plaintext
        }
    }

    // MARK: One seal, one open

    /// The only place a chunk is sealed.
    static func seal(chunk: Data, index: UInt64, final: Bool, key: SymmetricKey, header: Data) throws -> Data {
        let box = try AES.GCM.seal(
            chunk, using: key, nonce: Self.nonce(index: index),
            authenticating: Self.aad(header: header, index: index, final: final)
        )
        var wire = Data(capacity: chunk.count + Self.tagSize)
        wire.append(box.ciphertext)
        wire.append(box.tag)
        return wire
    }

    /// The only place a chunk is opened. Every authentication failure is one error.
    static func open(chunk: Data, index: UInt64, final: Bool, key: SymmetricKey, header: Data) throws -> Data {
        guard chunk.count > Self.tagSize else { throw StreamError.chunkWrongSize }
        let split = chunk.endIndex - Self.tagSize
        do {
            let box = try AES.GCM.SealedBox(
                nonce: Self.nonce(index: index), ciphertext: chunk[chunk.startIndex..<split], tag: chunk[split...]
            )
            return try AES.GCM.open(box, using: key, authenticating: Self.aad(header: header, index: index, final: final))
        } catch {
            throw StreamError.chunkNotAuthentic
        }
    }

    // MARK: Manifest

    /// The stream's opening (§4.2): `manifest_length: u32` then the manifest, which is
    /// `WireHandle.encode(payload:)` of the bundle's `SealedPayload`. The streamed files' bytes follow it.
    public enum Manifest {

        /// Bytes of `manifest_length`.
        public static let prefixLength = 4

        /// `u32(M) ‖ manifest`. Throws if the manifest is empty or over 16 MiB: a sender refuses the send.
        public static func frame(payload: OccultaBundle.SealedPayload) throws -> Data {
            let manifest = try WireHandle.encode(payload: payload)
            guard (1...BodyStream.maxManifestLength).contains(manifest.count) else {
                throw StreamError.manifestLengthOutOfRange
            }
            var framed = BodyStream.bigEndian32(UInt32(manifest.count))
            framed.append(manifest)
            return framed
        }

        /// *M*, from the first four bytes of the plaintext. Rejects 0 and anything over 16 MiB, before a
        /// receiver decrypts past it.
        public static func length(prefix: Data) throws -> Int {
            guard prefix.count >= Self.prefixLength else { throw StreamError.manifestLengthOutOfRange }
            let start = prefix.startIndex
            let m = prefix[start..<(start + Self.prefixLength)].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            guard (1...UInt32(BodyStream.maxManifestLength)).contains(m) else { throw StreamError.manifestLengthOutOfRange }
            return Int(m)
        }

        /// The sealed payload in `manifest`, the `M` bytes after the prefix.
        public static func decode(_ manifest: Data) throws -> OccultaBundle.SealedPayload {
            try WireHandle.decode(payload: manifest)
        }

        /// *P*: the prefix, the manifest and every streamed file. Throws if it overflows.
        public static func plaintextLength(manifestLength: Int, streamedLengths: [UInt64?]) throws -> UInt64 {
            var total = UInt64(Self.prefixLength) + UInt64(manifestLength)
            for length in streamedLengths.compactMap({ $0 }) {
                let (sum, overflow) = total.addingReportingOverflow(length)
                guard !overflow, sum <= BodyStream.maximumPlaintextLength else { throw StreamError.lengthMismatch }
                total = sum
            }
            return total
        }

        /// A receiver's check, as soon as the manifest is decoded: what it says follows the manifest must
        /// be exactly what the stream holds (§5.3). Bytes left over, or a file still short, are the same
        /// mismatch seen from either side.
        public static func validate(manifestLength: Int, streamedLengths: [UInt64?], against layout: Layout) throws {
            guard try Self.plaintextLength(manifestLength: manifestLength, streamedLengths: streamedLengths)
                    == layout.plaintextLength else { throw StreamError.lengthMismatch }
        }
    }

    // MARK: Integers

    static func bigEndian(_ value: UInt64) -> Data {
        Data((0..<8).map { UInt8(truncatingIfNeeded: value >> UInt64(56 - 8 * $0)) })
    }

    static func bigEndian32(_ value: UInt32) -> Data {
        Data((0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(24 - 8 * $0)) })
    }
}
