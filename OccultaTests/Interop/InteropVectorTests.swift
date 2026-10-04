//
//  InteropVectorTests.swift
//  OccultaTests
//
//  Byte-exact checks of the wire and at-rest formats against `InteropVectors.json`.
//
//  Round-trip tests cannot catch a format change: rename a field and the encoder and decoder
//  change together, so the round trip still passes while every contact on the old version
//  stops reading your messages. These pin the bytes themselves. The fixture holds each
//  vector's inputs as well as its output, so a second implementation can run against the
//  same file.
//
//  Expected values were recorded from this implementation and are never edited. A failure
//  here means the format changed: either undo the change, or add a new vector for a new
//  version and leave the old ones passing. To record a new vector, leave its `expected`
//  empty and run with `TEST_RUNNER_RECORD_INTEROP_VECTORS=<absolute directory>`: each
//  vector's bytes are written there as `<name>.hex`, and nothing is compared. Copy only the
//  new vector's bytes into the fixture.
//

import Testing
import Foundation
@testable import Occulta

@MainActor
@Suite("Interop vectors — wire and at-rest formats")
struct InteropVectorTests {

    @Test("Every vector reproduces its recorded bytes", arguments: try loadVectors())
    func vectorMatches(_ vector: Vector) throws {
        let actual = try vector.compute().hex
        // Opt-in recording mode: write the bytes instead of comparing them. One file per
        // vector, so parameterized cases running in parallel never share a file. Recording
        // is not a separate test, because a test that skips in every normal run would break
        // the "exactly 6 skips" pass condition in CLAUDE.md.
        if let directory = recordingDirectory {
            try actual.write(toFile: directory + "/" + vector.name + ".hex", atomically: true, encoding: .utf8)
            return
        }
        #expect(!vector.expected.isEmpty, "\(vector.name) has no recorded bytes")
        #expect(actual == vector.expected, "\(vector.name) changed")
    }

    @Test("Vector names are unique")
    func namesAreUnique() throws {
        let names = try loadVectors().map(\.name)
        #expect(Set(names).count == names.count)
    }

    /// The slash vector exists to pin Foundation's `\/` escaping, which other JSON encoders
    /// don't do. It is only worth anything if its input really does produce a `/`.
    @Test("The slash vector's key base64-encodes with a slash")
    func slashVectorExercisesEscaping() throws {
        let vector = try #require(loadVectors().first { $0.name == "aad.v4.forwardSecretNoPQ.slashInBase64" })
        let key = try #require(Data(hex: vector.ephemeralPublicKey ?? ""))
        #expect(key.base64EncodedString().contains("/"))
        let aad = try #require(String(data: try vector.compute(), encoding: .utf8))
        #expect(aad.contains("\\/"))
    }
}

// MARK: - Fixture

private let recordingDirectory = ProcessInfo.processInfo.environment["RECORD_INTEROP_VECTORS"]

private final class BundleToken {}

private func loadVectors() throws -> [Vector] {
    let bundle = Bundle(for: BundleToken.self)
    let url = try #require(
        bundle.url(forResource: "InteropVectors", withExtension: "json")
            ?? bundle.url(forResource: "InteropVectors", withExtension: "json", subdirectory: "Interop")
    )
    struct Fixture: Decodable { let vectors: [Vector] }
    return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url)).vectors
}

/// One fixture entry. Every input is optional because each `kind` uses a different subset.
struct Vector: Decodable, Sendable, CustomTestStringConvertible {
    let name: String
    let kind: String
    let expected: String

    // aad, envelope
    let version: String?
    let mode: String?
    let ephemeralPublicKey: String?
    let prekeyID: String?

    // fingerprint
    let publicKey: String?
    let nonce: String?

    // envelope
    let ciphertext: String?
    let fingerprintNonce: String?
    let senderFingerprint: String?

    // payload
    let message: String?
    let appVersion: String?
    let custodyManifest: [String]?
    let senderProof: String?
    let groupID: String?
    let prekeyBatch: Batch?

    // basket
    let id: String?
    let date: Double?
    let owner: String?
    let files: [FileInput]?

    // depth
    let value: Int?

    struct Batch: Decodable, Sendable {
        let generatedAt: Double
        let prekeys: [WirePrekeyInput]
    }

    struct WirePrekeyInput: Decodable, Sendable {
        let id: String
        let publicKey: String
    }

    struct FileInput: Decodable, Sendable {
        let id: String
        let format: String
        let date: Double?
        let content: String?
        let fileName: String?
        let fileExtension: String?
        let fileNote: String?
    }

    var testDescription: String { self.name }

    /// The bytes this implementation produces for the vector's inputs.
    @MainActor
    func compute() throws -> Data {
        switch self.kind {
        case "aad":
            return try OccultaBundle.computeAdditionalAuthentication(
                version: try Self.version(self.version),
                secrecy: try self.secrecy()
            )

        case "fingerprint":
            return OccultaBundle.SecrecyContext.fingerprint(
                for: try Self.bytes(self.publicKey),
                nonce: try Self.bytes(self.nonce)
            )

        case "envelope":
            let bundle = OccultaBundle(
                version:           try Self.version(self.version),
                secrecy:           try self.secrecy(),
                ciphertext:        try Self.bytes(self.ciphertext),
                fingerprintNonce:  try Self.bytes(self.fingerprintNonce),
                senderFingerprint: try Self.bytes(self.senderFingerprint)
            )
            return try WireHandle.encode(bundle)

        case "payload":
            let batch = try self.prekeyBatch.map { batch in
                OccultaBundle.SealedPayload.PrekeySyncBatch(
                    generatedAt: Date(timeIntervalSinceReferenceDate: batch.generatedAt),
                    prekeys: try batch.prekeys.map {
                        OccultaBundle.WirePrekey(id: $0.id, publicKey: try Self.bytes($0.publicKey))
                    }
                )
            }
            let payload = OccultaBundle.SealedPayload(
                message:         try Self.bytes(self.message),
                prekeyBatch:     batch,
                custodyManifest: try self.custodyManifest?.map(Self.uuid),
                appVersion:      self.appVersion,
                senderProof:     try self.senderProof.map(Self.bytes),
                groupID:         try self.groupID.map(Self.uuid)
            )
            return try WireHandle.encode(payload: payload)

        case "basket":
            let basket = Basket(
                id:    try Self.uuid(self.id),
                files: try (self.files ?? []).map(Self.file),
                date:  self.date.map(Date.init(timeIntervalSinceReferenceDate:)),
                owner: try self.owner.map(Self.bytes)
            )
            return try WireHandle.encode(basket: basket)

        case "depth":
            return DepthCodec.encode(try #require(self.value))

        default:
            Issue.record("\(self.name): unknown kind \(self.kind)")
            return Data()
        }
    }

    private func secrecy() throws -> OccultaBundle.SecrecyContext {
        OccultaBundle.SecrecyContext(
            mode:               try #require(OccultaBundle.Mode(rawValue: self.mode ?? "")),
            ephemeralPublicKey: try Self.bytes(self.ephemeralPublicKey),
            prekeyID:           self.prekeyID
        )
    }

    private static func version(_ raw: String?) throws -> OccultaBundle.Version {
        try #require(OccultaBundle.Version(rawValue: raw ?? ""))
    }

    private static func bytes(_ hex: String?) throws -> Data {
        try #require(Data(hex: hex ?? ""))
    }

    private static func uuid(_ string: String?) throws -> UUID {
        try #require(UUID(uuidString: string ?? ""))
    }

    private static func file(_ input: FileInput) throws -> File {
        let format: File.Format
        switch input.format {
        case "text":     format = .text
        case "contacts": format = .contacts
        case "link":     format = .link
        case "file":
            format = .file(File.Metadata(name: input.fileName, extension: input.fileExtension, note: input.fileNote))
        default:
            throw VectorError.unknownFileFormat(input.format)
        }
        return File(
            id:      try Self.uuid(input.id),
            content: try input.content.map(Self.bytes),
            format:  format,
            date:    input.date.map(Date.init(timeIntervalSinceReferenceDate:))
        )
    }

    enum VectorError: Error { case unknownFileFormat(String) }
}

// MARK: - Hex

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    var hex: String { self.map { String(format: "%02x", $0) }.joined() }
}
