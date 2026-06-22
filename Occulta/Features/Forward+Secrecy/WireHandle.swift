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
struct WireHandle {

    static let magic: [UInt8] = [0x4F, 0x43, 0x43, 0x42]  // "OCCB"

    // MARK: - Outer Bundle

    /// Parsed outer envelope. Does not contain decrypted content.
    /// Use `fingerprintNonce` + `senderFingerprint` to identify the sender
    /// before calling `open`.
    struct Bundle {
        let version: UInt8
        let minReaderVersion: UInt8
        let mode: UInt8
        let flags: UInt16
        let prekeyID: Data?          // nil or 36-byte UTF-8 UUID
        let ephemeralKey: Data       // 65-byte P-256 key, or empty Data on longTerm paths
        let fingerprintNonce: Data   // 16 bytes
        let senderFingerprint: Data  // 32 bytes
        let ciphertext: Data         // AES-GCM combined: nonce(12) || ct || tag(16)
    }

    // MARK: - Outer envelope: parse

    /// Parse the binary outer envelope without decrypting.
    /// Throws `BundleError.unsupportedVersion` if `min_reader_version` exceeds this build.
    static func parse(_ data: Data) throws -> Bundle {
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
        let ciphertext       = try r.read(Int(ctLen))

        guard minReaderVersion <= Self.versionByte else {
            throw OccultaBundle.BundleError.unsupportedVersion
        }

        let prekeyID = hasPrekeyID ? prekeyIDBytes : nil
        // 65 zero bytes signals empty ephemeral key (longTerm paths).
        // A real P-256 key always begins with 0x04 — all-zero is not a valid key.
        let ephemeralKey = ephemeralKeyRaw.allSatisfy({ $0 == 0 }) ? Data() : ephemeralKeyRaw

        return Bundle(
            version:           version,
            minReaderVersion:  minReaderVersion,
            mode:              mode,
            flags:             flags,
            prekeyID:          prekeyID,
            ephemeralKey:      ephemeralKey,
            fingerprintNonce:  fingerprintNonce,
            senderFingerprint: senderFP,
            ciphertext:        ciphertext
        )
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
    static func encode(_ bundle: OccultaBundle) throws -> Data {
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
        w.uint64BE(UInt64(bundle.ciphertext.count))
        w.data(bundle.ciphertext)

        return w.result
    }

    // MARK: - Payload: encode

    /// Binary-encode a `SealedPayload`. This is the plaintext passed to AES.GCM.seal.
    /// The `message` field (already binary Basket bytes) is written as raw bytes.
    /// All other fields are written as a length-prefixed JSON block.
    static func encode(payload: OccultaBundle.SealedPayload) throws -> Data {
        let meta = PayloadMeta(
            appVersion:        payload.appVersion,
            prekeyBatch:       payload.prekeyBatch,
            identityChallenge: payload.identityChallenge,
            shardOperations:   payload.shardOperations,
            custodyManifest:   payload.custodyManifest,
            expectedShards:    payload.expectedShards
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
    static func decode(payload data: Data) throws -> OccultaBundle.SealedPayload {
        var r = Reader(data)

        let metaLen  = Int(try r.uint32BE())
        let metaJSON = try r.read(metaLen)
        let msgLen   = Int(try r.uint64BE())
        let message  = try r.read(msgLen)

        let meta = try JSONDecoder().decode(PayloadMeta.self, from: metaJSON)

        return OccultaBundle.SealedPayload(
            message:           message,
            prekeyBatch:       meta.prekeyBatch,
            identityChallenge: meta.identityChallenge,
            shardOperations:   meta.shardOperations,
            custodyManifest:   meta.custodyManifest,
            expectedShards:    meta.expectedShards,
            appVersion:        meta.appVersion
        )
    }

    // MARK: - Basket: encode

    /// Binary-encode a `Basket`. The result becomes `SealedPayload.message`.
    /// File content is written as raw bytes; all other metadata is JSON.
    static func encode(basket: Basket) throws -> Data {
        let meta = BasketMeta(id: basket.id, date: basket.date, owner: basket.owner)
        let metaJSON = try Self.sortedEncoder.encode(meta)

        var w = Writer()
        w.uint32BE(UInt32(metaJSON.count))
        w.data(metaJSON)
        w.uint32BE(UInt32(basket.files.count))

        for file in basket.files {
            let fileMeta = FileMeta(id: file.id, format: file.format, date: file.date)
            let fileMetaJSON = try Self.sortedEncoder.encode(fileMeta)

            w.uint32BE(UInt32(fileMetaJSON.count))
            w.data(fileMetaJSON)

            let content = file.content ?? Data()
            w.uint64BE(UInt64(content.count))
            w.data(content)
        }

        return w.result
    }

    // MARK: - Basket: decode

    /// Decode binary Basket bytes produced by `encode(basket:)`.
    static func decode(basket data: Data) throws -> Basket {
        var r = Reader(data)

        let metaLen   = Int(try r.uint32BE())
        let metaJSON  = try r.read(metaLen)
        let fileCount = Int(try r.uint32BE())

        let meta = try JSONDecoder().decode(BasketMeta.self, from: metaJSON)

        var files: [File] = []
        for _ in 0..<fileCount {
            let fMetaLen  = Int(try r.uint32BE())
            let fMetaJSON = try r.read(fMetaLen)
            let ctLen     = Int(try r.uint64BE())
            let content   = ctLen > 0 ? try r.read(ctLen) : nil

            let fMeta = try JSONDecoder().decode(FileMeta.self, from: fMetaJSON)
            files.append(File(id: fMeta.id, content: content, format: fMeta.format, date: fMeta.date))
        }

        return Basket(id: meta.id, files: files, date: meta.date, owner: meta.owner)
    }

    // MARK: - Version / mode byte tables

    static let versionByte: UInt8 = 0x04

    static func byteToVersion(_ b: UInt8) -> OccultaBundle.Version? { Self._byteToVersion[b] }
    static func byteToMode(_ b: UInt8)    -> OccultaBundle.Mode?    { Self._byteToMode[b] }

    // groupCapable encodes to 0x04 on the wire (same binary layout as v4);
    // 0x05 is only written into Contact.Profile.maxBundleVersion as a capability marker.
    private static let _versionToByte: [OccultaBundle.Version: UInt8] = [
        .v4:           0x04,
        .groupCapable: 0x04,
    ]
    private static let _byteToVersion: [UInt8: OccultaBundle.Version] = [
        0x04: .v4,
        0x05: .groupCapable,
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
    var expectedShards: [UUID]?

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(self.appVersion,        forKey: .appVersion)
        try c.encodeIfPresent(self.prekeyBatch,       forKey: .prekeyBatch)
        try c.encodeIfPresent(self.identityChallenge, forKey: .identityChallenge)
        try c.encodeIfPresent(self.shardOperations,   forKey: .shardOperations)
        try c.encodeIfPresent(self.custodyManifest,   forKey: .custodyManifest)
        try c.encodeIfPresent(self.expectedShards,    forKey: .expectedShards)
    }

    enum CodingKeys: String, CodingKey {
        case appVersion, prekeyBatch, identityChallenge, shardOperations, custodyManifest, expectedShards
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

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(self.id,              forKey: .id)
        try c.encodeIfPresent(self.format, forKey: .format)
        try c.encodeIfPresent(self.date,   forKey: .date)
    }

    enum CodingKeys: String, CodingKey { case id, format, date }
}

// MARK: - Reader (sequential big-endian byte reader)

private struct Reader {
    private let data: Data
    private var offset: Int

    init(_ data: Data) {
        self.data   = data
        self.offset = data.startIndex
    }

    mutating func read(_ count: Int) throws -> Data {
        let end = offset + count
        guard end <= data.endIndex else { throw OccultaBundle.BundleError.unsupportedVersion }
        defer { offset = end }
        return data[offset..<end]
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
