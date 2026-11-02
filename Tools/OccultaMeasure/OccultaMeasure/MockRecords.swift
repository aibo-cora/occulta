//
//  MockRecords.swift
//  OccultaMeasure
//
//  Sealed rows of mock data, sized as `ContactRecordCryptoMeasurementTests` sizes them: a P-256 identity and
//  agreement key (65 bytes each), an ML-KEM-1024 public key (1,568 bytes) and 23 prekey blobs of 143 bytes, padded
//  to 8 KB. Photos are 24 KB and vault entries 4 KB, as opaque bytes. A row is AES-GCM sealed with its 16-byte ID
//  as AAD; a noise row is random bytes of the same size, which fails its tag check.
//

import CryptoKit
import Foundation

struct Row {
    let id: Data
    let sealed: Data
}

enum RowSize {
    static let contact = 8_192
    static let photo = 24_576
    static let vault = 4_096
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

    static func make(_ index: Int) -> MockContactRecord {
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
            photoRowIDs: [Random.bytes(16)]
        )
    }
}

enum Sealing {
    static func newID() -> Data {
        Random.bytes(16)
    }

    /// A 4-byte length, the JSON, then zeros up to `RowSize.contact`.
    static func padded(_ record: MockContactRecord) throws -> Data {
        let json = try JSONEncoder().encode(record)
        var plaintext = withUnsafeBytes(of: UInt32(json.count).bigEndian) { Data($0) }
        plaintext.append(json)
        guard plaintext.count <= RowSize.contact else { throw MeasureError("the mock record outgrew its row") }
        return plaintext + Data(count: RowSize.contact - plaintext.count)
    }

    static func decode(_ plaintext: Data) throws -> MockContactRecord {
        let length = plaintext.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        return try JSONDecoder().decode(MockContactRecord.self, from: plaintext.dropFirst(4).prefix(length))
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

    static func contactRows(count: Int, key: SymmetricKey) throws -> [Row] {
        try (0..<count).map { index in
            let id = Self.newID()
            return Row(id: id, sealed: try Self.seal(try Self.padded(.make(index)), id: id, key: key))
        }
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
