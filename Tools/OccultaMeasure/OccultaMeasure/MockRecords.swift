//
//  MockRecords.swift
//  OccultaMeasure
//
//  Sealed rows of mock data. The contact table has one row size (decided 2026-11-15, §8 item 29; the size itself is
//  set later, so it is a parameter) for every small record: a contact, whose mock content is a P-256 identity and
//  agreement key (65 bytes each), an ML-KEM-1024 public key (1,568 bytes) and 23 prekey blobs of 143 bytes, and a
//  photo (24 KB of random bytes, as opaque as a re-encoded image), each padded to the row size. The record's type is
//  the first byte inside the seal. Vault entries are 4 KB of opaque bytes in a table of their own. A row is AES-GCM
//  sealed with its 16-byte ID as AAD; a noise row is random bytes of the same size, which fails its tag check.
//

import CryptoKit
import Foundation

struct Row {
    let id: Data
    let sealed: Data
}

enum RowSize {
    static let photo = 24_576
    static let vault = 4_096
}

/// The first byte of a record's plaintext.
enum RecordKind: UInt8 {
    case contact = 0
    case photo = 1
}

struct MockContactRecord: Codable {
    struct Labeled: Codable {
        var label: String
        var value: String
    }

    var givenName: String
    var familyName: String
    var organizationName: String
    var note: String
    var phoneNumbers: [Labeled]
    var emailAddresses: [Labeled]
    var postalAddress: String
    var identityKey: Data
    var agreementKey: Data
    var postQuantumKey: Data
    var prekeyBlobs: [Data]
    var photoRowIDs: [Data]

    static func make(_ index: Int, photoRowID: Data) -> MockContactRecord {
        MockContactRecord(
            givenName: "Given\(index)",
            familyName: "Family\(index)",
            organizationName: "Organization \(index)",
            note: String(repeating: "n", count: 200),
            phoneNumbers: [Labeled(label: "mobile", value: "+1 555 000 \(1_000 + index)"),
                           Labeled(label: "work", value: "+1 555 111 \(1_000 + index)")],
            emailAddresses: [Labeled(label: "home", value: "contact\(index)@example.com")],
            postalAddress: "\(index) Example Street, Springfield, 12345, US",
            identityKey: Random.bytes(65),
            agreementKey: Random.bytes(65),
            postQuantumKey: Random.bytes(1_568),
            prekeyBlobs: (0..<23).map { _ in Random.bytes(143) },
            photoRowIDs: [photoRowID]
        )
    }
}

enum Sealing {
    static func newID() -> Data {
        Random.bytes(16)
    }

    /// AES-GCM's nonce and tag, added to the plaintext by `seal`.
    static let overhead = 28

    /// The type byte, a 4-byte length, the payload, then zeros up to `rowSize`.
    static func padded(_ kind: RecordKind, payload: Data, rowSize: Int) throws -> Data {
        var plaintext = Data([kind.rawValue])
        plaintext.append(withUnsafeBytes(of: UInt32(payload.count).bigEndian) { Data($0) })
        plaintext.append(payload)
        guard plaintext.count <= rowSize else { throw MeasureError("a \(kind) record outgrew its \(rowSize)-byte row") }
        return plaintext + Data(count: rowSize - plaintext.count)
    }

    /// The type of an opened row. Unlock reads this first and drops a photo's plaintext right after.
    static func kind(of plaintext: Data) -> RecordKind? {
        plaintext.first.flatMap(RecordKind.init(rawValue:))
    }

    static func decodeContact(_ plaintext: Data) throws -> MockContactRecord {
        let length = plaintext.dropFirst().prefix(4).reduce(0) { $0 << 8 | Int($1) }
        return try JSONDecoder().decode(MockContactRecord.self, from: plaintext.dropFirst(5).prefix(length))
    }

    static func seal(_ plaintext: Data, id: Data, key: SymmetricKey) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key, authenticating: id).combined else {
            throw MeasureError("AES-GCM gave no combined box")
        }
        return combined
    }

    static func open(_ sealed: Data, id: Data, key: SymmetricKey) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key, authenticating: id)
    }

    /// The size of one mock contact's JSON, which is what decoding it parses whatever the row size is.
    static func contactPayloadSize() throws -> Int {
        try JSONEncoder().encode(MockContactRecord.make(0, photoRowID: Self.newID())).count
    }

    /// A contact row, and the row of its photo, as the table holds them.
    static func contactAndPhotoRows(index: Int, rowSize: Int, key: SymmetricKey) throws -> (contact: Row, photo: Row) {
        let photoID = Self.newID()
        let photo = Row(id: photoID, sealed: try Self.seal(
            try Self.padded(.photo, payload: Random.bytes(RowSize.photo), rowSize: rowSize), id: photoID, key: key))

        let contactID = Self.newID()
        let json = try JSONEncoder().encode(MockContactRecord.make(index, photoRowID: photoID))
        let contact = Row(id: contactID, sealed: try Self.seal(
            try Self.padded(.contact, payload: json, rowSize: rowSize), id: contactID, key: key))
        return (contact, photo)
    }

    static func opaqueRows(count: Int, plaintextSize: Int, key: SymmetricKey) throws -> [Row] {
        try (0..<count).map { _ in
            let id = Self.newID()
            return Row(id: id, sealed: try Self.seal(Random.bytes(plaintextSize), id: id, key: key))
        }
    }

    static func noiseRows(count: Int, sealedSize: Int) -> [Row] {
        (0..<count).map { _ in Row(id: Self.newID(), sealed: Random.bytes(sealedSize)) }
    }
}
