//
//  WireHandle.swift
//  Occulta
//

import CryptoKit
import Foundation

// MARK: - WireHandle

/// Binary codec for the v4 bundle wire format. Purely a serialisation layer —
/// the in-memory representation (`OccultaBundle`, `SealedPayload`, `Basket`)
/// is unchanged. See Docs/Features/Bundle/SPEC.md for the full wire layout.
///
/// Each method maps 1:1 to a future Rust FFI call in `occulta-protocol`.
public struct WireHandle {

    public static let magic: [UInt8] = [0x4F, 0x43, 0x43, 0x42]  // "OCCB"

    // MARK: - Outer Bundle

    /// Parsed outer envelope. Does not contain decrypted content.
    /// Use `fingerprintNonce` + `senderFingerprint` to identify the sender
    /// before calling `open`.
    public struct Bundle {
        public let version: UInt8
        public let minReaderVersion: UInt8
        public let mode: UInt8
        public let flags: UInt16
        public let prekeyID: Data?          // nil or 36-byte UTF-8 UUID
        public let ephemeralKey: Data       // 65-byte P-256 key, or empty Data on longTerm paths
        public let fingerprintNonce: Data   // 16 bytes
        public let senderFingerprint: Data  // 32 bytes
        public let ciphertext: Data         // AES-GCM combined: nonce(12) || ct || tag(16)
        public let groupEnvelope: Data?     // TLV section 0x01 — JSON(GroupEnvelope), nil for non-group bundles
    }

    // MARK: - Outer envelope: parse

    /// The 167-byte header (`SPEC.md` §4.1): everything before the ciphertext, and its length.
    public struct Header {
        public let version: UInt8
        public let minReaderVersion: UInt8
        public let mode: UInt8
        public let flags: UInt16
        public let prekeyID: Data?          // nil or 36-byte UTF-8 UUID
        public let ephemeralKey: Data       // 65-byte P-256 key, or empty Data on longTerm paths
        public let fingerprintNonce: Data   // 16 bytes
        public let senderFingerprint: Data  // 32 bytes
        public let ciphertextLength: UInt64
    }

    /// The TLV sections that follow the ciphertext (§4.4).
    public struct Sections {
        public let groupEnvelope: Data?     // TLV section 0x01 — JSON(GroupEnvelope), nil for non-group bundles
    }

    /// Bytes of the header, and so the offset of the ciphertext.
    public static let headerLength = 167

    /// Wire `version` of the streamed layout (`STREAMING_SPEC.md` §4.1).
    public static let streamedVersionByte: UInt8 = 0x0A

    /// Parse the binary outer envelope without decrypting.
    /// Throws `BundleError.unsupportedVersion` if the wire version is not one this build reads.
    public static func parse(_ data: Data) throws -> Bundle {
        let header = try Self.parseHeader(data)
        var r = Reader(data)
        _ = try r.read(Self.headerLength)
        let ciphertext = try r.read(length: header.ciphertextLength)
        let sections = try Self.parseSections(try r.read(r.remaining))

        if header.version == Self.streamedVersionByte {
            guard sections.groupEnvelope != nil else { throw OccultaBundle.BundleError.malformedBundle }
        }

        return Bundle(
            version:           header.version,
            minReaderVersion:  header.minReaderVersion,
            mode:              header.mode,
            flags:             header.flags,
            prekeyID:          header.prekeyID,
            ephemeralKey:      header.ephemeralKey,
            fingerprintNonce:  header.fingerprintNonce,
            senderFingerprint: header.senderFingerprint,
            ciphertext:        ciphertext,
            groupEnvelope:     sections.groupEnvelope
        )
    }

    /// Parse the 167-byte header at the start of `data`, which may be longer.
    ///
    /// Reader rules (`STREAMING_SPEC.md` §4.1): accept exactly `0x04` and `0x0A` as `version`, and require
    /// `min_reader_version` to equal it. `0x05`–`0x09` exist only as capability markers: `byteToVersion` maps
    /// them to tiers, and a reader that let them through would route them as bundles.
    public static func parseHeader(_ data: Data) throws -> Header {
        var r = Reader(data)

        let magic4 = try r.read(4)
        guard magic4.elementsEqual(magic) else { throw OccultaBundle.BundleError.unsupportedVersion }

        let version          = try r.uint8()
        let minReaderVersion = try r.uint8()
        let mode             = try r.uint8()
        let flags            = try r.uint16BE()
        let hasPrekeyID      = try r.uint8() == 0x01
        let prekeyIDBytes    = try r.read(36)
        let ephemeralKeyRaw  = try r.read(65)
        let fingerprintNonce = try r.read(16)
        let senderFP         = try r.read(32)
        let ctLen            = try r.uint64BE()

        guard version == Self.versionByte || version == Self.streamedVersionByte,
              minReaderVersion == version
        else { throw OccultaBundle.BundleError.unsupportedVersion }

        let prekeyID = hasPrekeyID ? prekeyIDBytes : nil
        // 65 zero bytes signals empty ephemeral key (longTerm paths).
        // A real P-256 key always begins with 0x04 — all-zero is not a valid key.
        let ephemeralKey = ephemeralKeyRaw.allSatisfy({ $0 == 0 }) ? Data() : ephemeralKeyRaw

        return Header(
            version:           version,
            minReaderVersion:  minReaderVersion,
            mode:              mode,
            flags:             flags,
            prekeyID:          prekeyID,
            ephemeralKey:      ephemeralKey,
            fingerprintNonce:  fingerprintNonce,
            senderFingerprint: senderFP,
            ciphertextLength:  ctLen
        )
    }

    /// Parse the TLV extension sections (§4.4): the bytes after the ciphertext, to the end. Unknown types
    /// are skipped.
    public static func parseSections(_ data: Data) throws -> Sections {
        var r = Reader(data)
        var groupEnvelope: Data? = nil
        while r.remaining >= 5 {
            let sectionType   = try r.uint8()
            let sectionLength = Int(try r.uint32BE())
            let sectionBytes  = try r.read(sectionLength)
            if sectionType == 0x01 {
                guard groupEnvelope == nil else { throw OccultaBundle.BundleError.malformedBundle }
                groupEnvelope = sectionBytes
            }
        }
        return Sections(groupEnvelope: groupEnvelope)
    }

    // MARK: - Outer envelope: open

    /// Compute AAD from the parsed bundle and AES-GCM decrypt.
    /// The plaintext is a binary `SealedPayload` — pass it to `decode(payload:)`.
    static func open(_ bundle: Bundle, using key: SymmetricKey) throws -> Data {
        guard let mode = Self.byteToMode(bundle.mode) else {
            throw OccultaBundle.BundleError.unsupportedMode
        }
        guard let version = Self.byteToVersion(bundle.version) else {
            throw OccultaBundle.BundleError.unsupportedVersion
        }

        let prekeyIDString: String?
        if let pid = bundle.prekeyID {
            guard let s = String(data: pid, encoding: .utf8) else {
                throw OccultaBundle.BundleError.unsupportedVersion
            }
            prekeyIDString = s
        } else {
            prekeyIDString = nil
        }

        let secrecy = OccultaBundle.SecrecyContext(
            mode:               mode,
            ephemeralPublicKey: bundle.ephemeralKey,
            prekeyID:           prekeyIDString
        )
        let aad = try OccultaBundle.computeAdditionalAuthentication(version: version, secrecy: secrecy)
        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }

    // MARK: - Outer envelope: encode

    /// Encode a fully constructed `OccultaBundle` as a binary outer envelope.
    /// The bundle's `ciphertext` must already be the AES-GCM combined output.
    public static func encode(_ bundle: OccultaBundle) throws -> Data {
        var out = try Self.encodeHeader(bundle, ciphertextLength: UInt64(bundle.ciphertext.count))
        out.append(bundle.ciphertext)
        out.append(try Self.encodeSections(bundle))
        return out
    }

    /// The 167-byte header of `bundle`, declaring a ciphertext of `ciphertextLength` bytes. The bundle's own
    /// `ciphertext` is not read: a streamed writer writes the chunk stream after this, and the sections after
    /// that.
    public static func encodeHeader(_ bundle: OccultaBundle, ciphertextLength: UInt64) throws -> Data {
        guard let vByte = Self._versionToByte[bundle.version] else {
            throw OccultaBundle.BundleError.unsupportedVersion
        }
        guard let mByte = Self._modeToByte[bundle.secrecy.mode] else {
            throw OccultaBundle.BundleError.unsupportedMode
        }

        var w = Writer()
        w.bytes(magic)
        w.uint8(vByte)              // version
        w.uint8(vByte)              // min_reader_version = same as version
        w.uint8(mByte)              // mode
        w.uint16BE(0x0000)          // flags (reserved)

        if let pid = bundle.secrecy.prekeyID,
           let pidData = pid.data(using: .utf8), pidData.count == 36 {
            w.uint8(0x01)
            w.data(pidData)
        } else {
            w.uint8(0x00)
            w.zeros(36)
        }

        let eph = bundle.secrecy.ephemeralPublicKey
        if eph.isEmpty { w.zeros(65) } else { w.data(eph) }

        w.data(bundle.fingerprintNonce)
        w.data(bundle.senderFingerprint)
        w.uint64BE(ciphertextLength)
        return w.result
    }

    /// The TLV sections of `bundle`, for the bytes after the ciphertext.
    public static func encodeSections(_ bundle: OccultaBundle) throws -> Data {
        var w = Writer()

        // TLV section 0x01 — group envelope (§4.4). Written only for group bundles.
        //
        // Sorted keys: this JSON travels in cleartext, and a default JSONEncoder orders keys by
        // a hash seeded per process, so the order changed with every app launch — a signal an
        // observer could use to group bundles by sender session, against what `blind` is for.
        // Nothing authenticates these bytes and every receiver parses any order, so this is
        // compatible in both directions.
        if let group = bundle.group {
            let groupJSON = try Self.sortedEncoder.encode(group)
            w.uint8(0x01)
            w.uint32BE(UInt32(groupJSON.count))
            w.data(groupJSON)
        }

        return w.result
    }

    // MARK: - Payload: encode

    /// Binary-encode a `SealedPayload`. This is the plaintext passed to AES.GCM.seal.
    /// The `message` field (already binary Basket bytes) is written as raw bytes.
    /// All other fields are written as a length-prefixed JSON block.
    public static func encode(payload: OccultaBundle.SealedPayload) throws -> Data {
        let meta = PayloadMeta(
            appVersion:        payload.appVersion,
            prekeyBatch:       payload.prekeyBatch,
            identityChallenge: payload.identityChallenge,
            shardOperations:   payload.shardOperations,
            custodyManifest:   payload.custodyManifest,
            senderProof:       payload.senderProof,
            groupID:           payload.groupID
        )
        let metaJSON = try Self.sortedEncoder.encode(meta)

        var w = Writer()
        w.uint32BE(UInt32(metaJSON.count))
        w.data(metaJSON)
        w.uint64BE(UInt64(payload.message.count))
        w.data(payload.message)
        return w.result
    }

    // MARK: - Payload: decode

    /// Decode binary `SealedPayload` bytes produced by `encode(payload:)`.
    public static func decode(payload data: Data) throws -> OccultaBundle.SealedPayload {
        var r = Reader(data)

        let metaLen  = Int(try r.uint32BE())
        let metaJSON = try r.read(metaLen)
        let msgLen   = try r.uint64BE()
        let message  = try r.read(length: msgLen)

        let meta = try BoundedJSON.decode(PayloadMeta.self, from: metaJSON)

        return OccultaBundle.SealedPayload(
            message:           message,
            prekeyBatch:       meta.prekeyBatch,
            identityChallenge: meta.identityChallenge,
            shardOperations:   meta.shardOperations,
            custodyManifest:   meta.custodyManifest,
            appVersion:        meta.appVersion,
            senderProof:       meta.senderProof,
            groupID:           meta.groupID
        )
    }

    // MARK: - Basket: encode

    /// Binary-encode a `Basket`. The result becomes `SealedPayload.message`.
    /// File content is written as raw bytes; all other metadata is JSON.
    public static func encode(basket: Basket) throws -> Data {
        try Self.encodeBasket(basket, streamedLengths: nil)
    }

    /// The streamed layout's basket (`STREAMING_SPEC.md` §4.4). `streamedLengths` runs parallel to
    /// `basket.files`: a non-nil entry marks that file as streamed. Its content is not written, so
    /// `content_length` is 0, and its `FileMeta` JSON gains `"streamedLength"`, the plaintext length of the
    /// content that follows the manifest in the stream.
    public static func encode(basket: Basket, streamedLengths: [UInt64?]) throws -> Data {
        guard streamedLengths.count == basket.files.count else { throw OccultaBundle.BundleError.malformedBundle }
        return try Self.encodeBasket(basket, streamedLengths: streamedLengths)
    }

    private static func encodeBasket(_ basket: Basket, streamedLengths: [UInt64?]?) throws -> Data {
        let meta = BasketMeta(id: basket.id, date: basket.date, owner: basket.owner)
        let metaJSON = try Self.sortedEncoder.encode(meta)

        var w = Writer()
        w.uint32BE(UInt32(metaJSON.count))
        w.data(metaJSON)
        w.uint32BE(UInt32(basket.files.count))

        for (index, file) in basket.files.enumerated() {
            let streamedLength = streamedLengths?[index]
            let fileMeta = FileMeta(id: file.id, format: file.format, date: file.date, streamedLength: streamedLength)
            let fileMetaJSON = try Self.sortedEncoder.encode(fileMeta)

            w.uint32BE(UInt32(fileMetaJSON.count))
            w.data(fileMetaJSON)

            // A streamed file's bytes travel in the stream, never here.
            let content = streamedLength == nil ? (file.content ?? Data()) : Data()
            w.uint64BE(UInt64(content.count))
            w.data(content)
        }

        return w.result
    }

    // MARK: - Basket: decode

    /// Decode binary Basket bytes produced by `encode(basket:)`.
    public static func decode(basket data: Data) throws -> Basket {
        try Self.decodeBasket(data).basket
    }

    /// Decode the streamed layout's basket. `streamedLengths` runs parallel to `basket.files`.
    ///
    /// Every `.file` must be streamed and nothing else may be, and a streamed file carries no inline
    /// content (§4.4); anything else is `malformedBundle`. Streamed files' `content` is nil: their bytes
    /// are in the stream.
    public static func decode(streamedBasket data: Data) throws -> (basket: Basket, streamedLengths: [UInt64?]) {
        let (basket, lengths, inlineContentLengths) = try Self.decodeBasket(data)
        for (file, (length, inline)) in zip(basket.files, zip(lengths, inlineContentLengths)) {
            var isFile = false
            if case .file = file.format { isFile = true }
            guard isFile == (length != nil), length == nil || inline == 0 else {
                throw OccultaBundle.BundleError.malformedBundle
            }
        }
        return (basket, lengths)
    }

    private static func decodeBasket(_ data: Data) throws -> (basket: Basket, streamedLengths: [UInt64?], inlineContentLengths: [UInt64]) {
        var r = Reader(data)

        let metaLen   = Int(try r.uint32BE())
        let metaJSON  = try r.read(metaLen)
        let fileCount = Int(try r.uint32BE())

        let meta = try BoundedJSON.decode(BasketMeta.self, from: metaJSON)

        var files: [File] = []
        var streamedLengths: [UInt64?] = []
        var inlineContentLengths: [UInt64] = []
        for _ in 0..<fileCount {
            let fMetaLen  = Int(try r.uint32BE())
            let fMetaJSON = try r.read(fMetaLen)
            let ctLen     = try r.uint64BE()
            let content   = ctLen > 0 ? try r.read(length: ctLen) : nil

            let fMeta = try BoundedJSON.decode(FileMeta.self, from: fMetaJSON)
            files.append(File(id: fMeta.id, content: content, format: fMeta.format, date: fMeta.date))
            streamedLengths.append(fMeta.streamedLength)
            inlineContentLengths.append(ctLen)
        }

        return (Basket(id: meta.id, files: files, date: meta.date, owner: meta.owner), streamedLengths, inlineContentLengths)
    }

    // MARK: - Version / mode byte tables

    public static let versionByte: UInt8 = 0x04

    public static func byteToVersion(_ b: UInt8) -> OccultaBundle.Version? { Self._byteToVersion[b] }
    public static func byteToMode(_ b: UInt8)    -> OccultaBundle.Mode?    { Self._byteToMode[b] }

    // groupCapable/groupShardCapable/senderSignatureCapable/prefixedSenderSignatureCapable/bodyDigestCapable
    // all encode to 0x04 on the wire (same binary layout as v4); 0x05–0x09 are only written
    // into Contact.Profile.maxBundleVersion as capability markers. `streamedBodyCapable` is the
    // exception: 0x0A is a marker and also the wire version of the streamed layout. `parseHeader`
    // accepts exactly 0x04 and 0x0A, whatever these tables map.
    //
    // ⚠️ These two tables and `Version.wireByte` are three statements of one fact and must be
    // updated together. Adding a tier to the enum alone leaves its marker byte unmappable on
    // read, and `bundleVersionState` then classifies it by comparison with
    // `highestKnownWireByte` — which the new `wireByte` just raised, so the byte lands on the
    // "not newer than us" side and resolves to `.v3fs`. A contact on the newest build would be
    // recorded as unable to sign, failing the `openGroup` signature gate open: exactly the
    // fail-open that comment at `ContactManager.bundleVersionState` exists to prevent.
    // `PrefixedSignatureTierTests.everyTierRoundTripsThroughItsMarkerByte` pins all three.
    private static let _versionToByte: [OccultaBundle.Version: UInt8] = [
        .v4:                     0x04,
        .groupCapable:           0x04,
        .groupShardCapable:      0x04,
        .senderSignatureCapable: 0x04,
        .prefixedSenderSignatureCapable: 0x04,
        .bodyDigestCapable:      0x04,
        .streamedBodyCapable:    0x0A,
    ]
    private static let _byteToVersion: [UInt8: OccultaBundle.Version] = [
        0x04: .v4,
        0x05: .groupCapable,
        0x06: .groupShardCapable,
        0x07: .senderSignatureCapable,
        0x08: .prefixedSenderSignatureCapable,
        0x09: .bodyDigestCapable,
        0x0A: .streamedBodyCapable,
    ]

    private static let _modeToByte: [OccultaBundle.Mode: UInt8] = [
        .forwardSecret:     0x01,
        .forwardSecretNoPQ: 0x02,
        .longTermFallback:  0x03,
        .longTermNoPQ:      0x04,
        .group:             0x05,
    ]
    private static let _byteToMode: [UInt8: OccultaBundle.Mode] = [
        0x01: .forwardSecret,
        0x02: .forwardSecretNoPQ,
        0x03: .longTermFallback,
        0x04: .longTermNoPQ,
        0x05: .group,
    ]

    private static let sortedEncoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = .sortedKeys
        return e
    }()
}

// MARK: - Private metadata Codable structs
// Nil fields are omitted (not encoded as null) per spec §4.2.1 and §4.3.1.

private struct PayloadMeta: Codable {
    var appVersion: String?
    var prekeyBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?
    var identityChallenge: IdentityChallengeEnvelope?
    var shardOperations: [OccultaBundle.ShardOperation]?
    var custodyManifest: [UUID]?
    var senderProof: Data?
    var groupID: UUID?

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(self.appVersion,        forKey: .appVersion)
        try c.encodeIfPresent(self.prekeyBatch,       forKey: .prekeyBatch)
        try c.encodeIfPresent(self.identityChallenge, forKey: .identityChallenge)
        try c.encodeIfPresent(self.shardOperations,   forKey: .shardOperations)
        try c.encodeIfPresent(self.custodyManifest,   forKey: .custodyManifest)
        try c.encodeIfPresent(self.senderProof,       forKey: .senderProof)
        try c.encodeIfPresent(self.groupID,           forKey: .groupID)
    }

    enum CodingKeys: String, CodingKey {
        case appVersion, prekeyBatch, identityChallenge, shardOperations, custodyManifest, senderProof, groupID
    }
}

private struct BasketMeta: Codable {
    var id: UUID
    var date: Date?
    var owner: Data?

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(self.id,              forKey: .id)
        try c.encodeIfPresent(self.date,   forKey: .date)
        try c.encodeIfPresent(self.owner,  forKey: .owner)
    }

    enum CodingKeys: String, CodingKey { case id, date, owner }
}

private struct FileMeta: Codable {
    var id: UUID
    var format: File.Format?
    var date: Date?
    /// Plaintext length of this file's content in the body stream. Present only on a streamed file of the
    /// streamed layout, so an inline basket encodes exactly as it always did.
    var streamedLength: UInt64?

    init(id: UUID, format: File.Format?, date: Date?, streamedLength: UInt64? = nil) {
        self.id             = id
        self.format         = format
        self.date           = date
        self.streamedLength = streamedLength
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(self.id,                      forKey: .id)
        try c.encodeIfPresent(self.format,         forKey: .format)
        try c.encodeIfPresent(self.date,           forKey: .date)
        try c.encodeIfPresent(self.streamedLength, forKey: .streamedLength)
    }

    enum CodingKeys: String, CodingKey { case id, format, date, streamedLength }
}

// MARK: - Reader (sequential big-endian byte reader)

private struct Reader {
    private let data: Data
    private var offset: Int

    init(_ data: Data) {
        self.data   = data
        self.offset = data.startIndex
    }

    var remaining: Int { data.endIndex - offset }

    mutating func read(_ count: Int) throws -> Data {
        guard count >= 0, count <= self.remaining else { throw OccultaBundle.BundleError.unsupportedVersion }
        let end = self.offset + count
        defer { self.offset = end }
        return self.data[self.offset..<end]
    }

    /// For a length taken straight off the wire. `Int(length)` traps from 2^63 up, and the
    /// check has to come first: a hostile value is rejected here as a short file would be.
    mutating func read(length: UInt64) throws -> Data {
        guard length <= UInt64(self.remaining) else { throw OccultaBundle.BundleError.unsupportedVersion }
        return try self.read(Int(length))
    }

    mutating func uint8() throws -> UInt8 {
        let b = try read(1)
        return b[b.startIndex]
    }

    mutating func uint16BE() throws -> UInt16 {
        let b = Array(try read(2))
        return UInt16(b[0]) << 8 | UInt16(b[1])
    }

    mutating func uint32BE() throws -> UInt32 {
        let b = Array(try read(4))
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }

    mutating func uint64BE() throws -> UInt64 {
        let b = Array(try read(8))
        var v: UInt64 = 0
        for byte in b { v = v << 8 | UInt64(byte) }
        return v
    }
}

// MARK: - Writer (sequential big-endian byte writer)

private struct Writer {
    private(set) var result = Data()

    mutating func bytes(_ v: [UInt8])  { result.append(contentsOf: v) }
    mutating func data(_ v: Data)      { result.append(v) }
    mutating func zeros(_ count: Int)  { result.append(contentsOf: [UInt8](repeating: 0, count: count)) }
    mutating func uint8(_ v: UInt8)    { result.append(v) }

    mutating func uint16BE(_ v: UInt16) {
        result.append(UInt8(v >> 8))
        result.append(UInt8(v & 0xFF))
    }

    mutating func uint32BE(_ v: UInt32) {
        result.append(UInt8((v >> 24) & 0xFF))
        result.append(UInt8((v >> 16) & 0xFF))
        result.append(UInt8((v >>  8) & 0xFF))
        result.append(UInt8( v        & 0xFF))
    }

    mutating func uint64BE(_ v: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            result.append(UInt8((v >> shift) & 0xFF))
        }
    }
}
