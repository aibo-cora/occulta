//
//  PrekeyRecordCodec.swift
//  Occulta
//

import Foundation
import OccultaCore

/// Turns a `PrekeyRecord` into the plaintext sealed into `Contact.Profile`, and back.
///
/// The plaintext is always exactly `capacity` bytes, so its sealed length says nothing about how many keys
/// either side holds (Bug 161):
/// ```
/// [ formatVersion: 1 byte | payload length: UInt32 big-endian | payload: binary plist | zeros to capacity ]
/// ```
/// The filler is inside the encryption, so zeros are as good as random.
///
/// Lossless: it never drops data. A record too large for `capacity` throws, which can only mean the
/// bookkeeper's limits were broken. Keeping a record within them is `PrekeyBookkeeper`'s job, eviction
/// included (stage 1 decision, 2026-10-09).
///
/// Also reads today's format, the JSON-encoded `ForwardSecrecy`, so existing records can be migrated.
nonisolated
struct PrekeyRecordCodec {

    static let capacity      = 16 * 1024
    static let formatVersion: UInt8 = 2
    static let headerSize    = 5

    enum CodecError: Error, Equatable {
        /// The encoded record doesn't fit `capacity`. A broken bookkeeper limit, never a normal state.
        case overCapacity
        /// Neither format, or a field that can't be read.
        case malformed
    }

    func encode(_ record: PrekeyRecord) throws -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let payload = try encoder.encode(record)
        guard Self.headerSize + payload.count <= Self.capacity else { throw CodecError.overCapacity }

        var plaintext = Data(capacity: Self.capacity)
        plaintext.append(Self.formatVersion)
        withUnsafeBytes(of: UInt32(payload.count).bigEndian) { plaintext.append(contentsOf: $0) }
        plaintext.append(payload)
        plaintext.append(Data(count: Self.capacity - plaintext.count))
        return plaintext
    }

    func decode(_ plaintext: Data) throws -> PrekeyRecord {
        switch plaintext.first {
        case Self.formatVersion: return try self.decodeCurrent(plaintext)
        case UInt8(ascii: "{"):  return try self.decodeLegacy(plaintext)
        default:                 throw CodecError.malformed
        }
    }

    // MARK: - Current format

    private func decodeCurrent(_ plaintext: Data) throws -> PrekeyRecord {
        guard plaintext.count == Self.capacity else { throw CodecError.malformed }
        let bytes  = [UInt8](plaintext)
        let length = bytes[1...4].reduce(0) { ($0 << 8) | Int($1) }
        guard length <= Self.capacity - Self.headerSize else { throw CodecError.malformed }

        let payload = Data(bytes[Self.headerSize ..< Self.headerSize + length])
        do {
            return try PropertyListDecoder().decode(PrekeyRecord.self, from: payload)
        } catch {
            throw CodecError.malformed
        }
    }

    // MARK: - Today's format

    /// The JSON-encoded `ForwardSecrecy` stored before stage 1.
    /// - `encodedPrekeys`, each a JSON-encoded `Prekey`, become one inbound batch without an ID. The
    ///   `contactID` each one repeated is dropped; it is the profile's own identifier.
    /// - `latestPrekeysGeneratedAt` keeps filtering inbound batches that carry no ID.
    /// - `pendingOutboundBatch` becomes a pending own batch without an ID, its keys without blobs. It must keep
    ///   travelling without an ID: a peer on a new build that accepted it under the date rule would accept it
    ///   again if it reappeared with one.
    ///
    /// Our other keychain prekeys aren't read here, and never enter the record: the keychain can't give up an
    /// Enclave key's wrapped blob. They stay in the keychain until `legacyKeys` lets them go.
    private func decodeLegacy(_ plaintext: Data) throws -> PrekeyRecord {
        let decoder = JSONDecoder()
        guard let legacy = try? decoder.decode(ForwardSecrecy.self, from: plaintext) else { throw CodecError.malformed }

        var record = PrekeyRecord.empty
        record.latestInboundGeneratedAt = legacy.latestPrekeysGeneratedAt
        // We may hold keychain prekeys for this contact; nothing here says whether we do.
        record.legacyKeys = .inUse

        let inbound = try (legacy.encodedPrekeys ?? []).map { blob -> PrekeyRecord.InboundKey in
            guard let prekey = try? decoder.decode(Prekey.self, from: blob) else { throw CodecError.malformed }
            return PrekeyRecord.InboundKey(id: prekey.id, publicKey: prekey.publicKey)
        }
        if !inbound.isEmpty {
            record.inboundBatches = [PrekeyRecord.InboundBatch(id: nil, keys: inbound)]
        }

        if let encoded = legacy.pendingOutboundBatch {
            guard let batch = try? decoder.decode(OccultaBundle.SealedPayload.PrekeySyncBatch.self, from: encoded) else {
                throw CodecError.malformed
            }
            let keys = try batch.prekeys.map { wire -> PrekeyRecord.OwnKey in
                guard let uuid = UUID(uuidString: wire.id) else { throw CodecError.malformed }
                return PrekeyRecord.OwnKey(id: withUnsafeBytes(of: uuid.uuid) { Data($0) }, blob: nil, publicKey: wire.publicKey)
            }
            record.ownBatches = [PrekeyRecord.OwnBatch(
                id: nil, createdAt: batch.generatedAt, retiredAt: nil, isPending: true, keys: keys
            )]
        }
        return record
    }
}
