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
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

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

    /// The `fsKey` vectors pin the sender's side. Decryption runs the same two functions with
    /// the roles swapped — the recipient's prekey private key against the sender's ephemeral
    /// public key, and the ML-KEM secrets the other way round — and must land on the same bytes.
    @Test("The recipient derives the same forward-secret key as the sender",
          arguments: try loadVectors().filter { $0.kind == "fsKey" })
    func recipientDerivesSameKey(_ vector: Vector) throws {
        let prekey    = try Vector.privateKey(vector.recipientScalar)
        let ephemeral = try Vector.publicMaterial(vector.ephemeralScalar)
        let key: SymmetricKey?
        if let encapsulated = vector.encapsulatedSecret {
            key = Manager.Key().createHybridFSSharedSecret(
                ephemeralPrivateKey: prekey,
                recipientMaterial:   ephemeral,
                quantumMaterial: QuantumKeyMaterial(
                    encapsulatedSecret: try #require(Data(hex: vector.decapsulatedSecret ?? "")),
                    decapsulatedSecret: try #require(Data(hex: encapsulated)),
                    ourCiphertext: Data(), peerCiphertext: Data()
                )
            )
        } else {
            key = Manager.Key().createSharedSecret(ephemeralPrivateKey: prekey, recipientMaterial: ephemeral)
        }
        let recipientSide = try #require(key).withUnsafeBytes { Data($0) }
        #expect(recipientSide == (try vector.compute()), "\(vector.name): the two sides disagree")
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

    // payload (identity challenge, shard operations), recipientPayload
    let identityChallenge: ChallengeInput?
    let shardOperations: [ShardOperationInput]?

    // fsKey
    let ephemeralScalar: String?
    let recipientScalar: String?
    let encapsulatedSecret: String?
    let decapsulatedSecret: String?

    // gcm
    let key: String?
    let plaintext: String?

    // groupEnvelope
    let group: GroupInput?

    // recipientPayload
    let sessionKey: String?
    let custodyManifestCount: Int?
    let shardMetadataAttempted: Bool?
    let senderEphemeralSignature: String?

    // signingPayload
    let attribute: AttributeInput?

    struct ChallengeInput: Decodable, Sendable {
        let kind: String
        let payload: String
        let contextNote: String?
    }

    struct ShardOperationInput: Decodable, Sendable {
        let kind: String
        let attribute: AttributeInput?
        let attributeID: String?
    }

    struct AttributeInput: Decodable, Sendable {
        let id: String
        let label: String
        let value: String
        let category: String
        let signature: String
        let createdAt: Double
        let expiresAt: Double?
        let entryID: String?
    }

    struct GroupInput: Decodable, Sendable {
        let version: UInt8
        let blind: String
        let blindNonce: String
        let recipients: [RecipientInput]
    }

    struct RecipientInput: Decodable, Sendable {
        let mode: String
        let ephemeralPublicKey: String
        let prekeyID: String?
        let wrappedPayload: String
    }

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
            let payload = OccultaBundle.SealedPayload(
                message:           try Self.bytes(self.message),
                prekeyBatch:       try self.prekeyBatch.map(Self.batch),
                identityChallenge: try self.identityChallenge.map(Self.challenge),
                shardOperations:   try self.shardOperations?.map(Self.shardOperation),
                custodyManifest:   try self.custodyManifest?.map(Self.uuid),
                appVersion:        self.appVersion,
                senderProof:       try self.senderProof.map(Self.bytes),
                groupID:           try self.groupID.map(Self.uuid)
            )
            return try WireHandle.encode(payload: payload)

        case "fsKey":
            // The sender's side of the forward-secret derivation, in Manager.Key itself — both
            // functions take the ephemeral private key as a parameter and never touch the Enclave.
            let ephemeral = try Self.privateKey(self.ephemeralScalar)
            let recipient = try Self.publicMaterial(self.recipientScalar)
            let key: SymmetricKey?
            if let encapsulated = self.encapsulatedSecret {
                key = Manager.Key().createHybridFSSharedSecret(
                    ephemeralPrivateKey: ephemeral,
                    recipientMaterial:   recipient,
                    quantumMaterial:     try self.quantumMaterial(encapsulated)
                )
            } else {
                key = Manager.Key().createSharedSecret(ephemeralPrivateKey: ephemeral, recipientMaterial: recipient)
            }
            return try #require(key).withUnsafeBytes { Data($0) }

        case "gcm":
            // AES-GCM is standard, so CryptoKit seals with a fixed nonce; what the vector pins is
            // the combined layout and the AAD it binds. Production `open` must then accept it.
            let key       = SymmetricKey(data: try Self.bytes(self.key))
            let plaintext = try Self.bytes(self.plaintext)
            let version   = try Self.version(self.version)
            let secrecy   = try self.secrecy()
            let sealed = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: try AES.GCM.Nonce(data: try Self.bytes(self.nonce)),
                authenticating: try OccultaBundle.computeAdditionalAuthentication(version: version, secrecy: secrecy)
            )
            let combined = try #require(sealed.combined)
            let bundle = OccultaBundle(
                version: version, secrecy: secrecy, ciphertext: combined,
                fingerprintNonce: Data(count: 16), senderFingerprint: Data(count: 32)
            )
            #expect(try Manager.Crypto(keyManager: TestKeyManager()).open(bundle, using: key) == plaintext,
                    "\(self.name): production open rejected the sealed bytes")
            return combined

        case "legacyBundle":
            // The JSON bundle still sent to contacts below v4 (`encoded(version:)`'s default path).
            let bundle = OccultaBundle(
                version:           try Self.version(self.version),
                secrecy:           try self.secrecy(),
                ciphertext:        try Self.bytes(self.ciphertext),
                fingerprintNonce:  try Self.bytes(self.fingerprintNonce),
                senderFingerprint: try Self.bytes(self.senderFingerprint)
            )
            return try bundle.encoded(version: try Self.version(self.version))

        case "groupEnvelope":
            let group = try #require(self.group)
            let bundle = OccultaBundle(
                version:           try Self.version(self.version),
                secrecy:           try self.secrecy(),
                ciphertext:        try Self.bytes(self.ciphertext),
                fingerprintNonce:  try Self.bytes(self.fingerprintNonce),
                senderFingerprint: try Self.bytes(self.senderFingerprint),
                group: OccultaBundle.GroupEnvelope(
                    version:    group.version,
                    blind:      try Self.bytes(group.blind),
                    blindNonce: try Self.bytes(group.blindNonce),
                    recipients: try group.recipients.map {
                        OccultaBundle.Recipient(
                            secrecyContext: OccultaBundle.SecrecyContext(
                                mode:               try #require(OccultaBundle.Mode(rawValue: $0.mode)),
                                ephemeralPublicKey: try Self.bytes($0.ephemeralPublicKey),
                                prekeyID:           $0.prekeyID
                            ),
                            wrappedPayload: try Self.bytes($0.wrappedPayload)
                        )
                    }
                )
            )
            return try WireHandle.encode(bundle)

        case "recipientPayload":
            let payload = OccultaBundle.RecipientPayload(
                sessionKey:               try Self.bytes(self.sessionKey),
                prekeyBatch:              try self.prekeyBatch.map(Self.batch),
                shardOperations:          try (self.shardOperations ?? []).map(Self.shardOperation),
                custodyManifest:          try (self.custodyManifest ?? []).map(Self.uuid),
                custodyManifestCount:     self.custodyManifestCount ?? 0,
                shardMetadataAttempted:   self.shardMetadataAttempted ?? false,
                senderEphemeralSignature: try self.senderEphemeralSignature.map(Self.bytes)
            )
            // Mirrors `wrapRecipient` (Crypto+Manager+GroupEncrypt.swift), which encodes the
            // payload with a sorted-keys JSONEncoder before wrapping it. Keep the two in step.
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            return try encoder.encode(payload)

        case "signingPayload":
            return try Self.attribute(try #require(self.attribute)).signingPayload()

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

    private func quantumMaterial(_ encapsulated: String) throws -> QuantumKeyMaterial {
        QuantumKeyMaterial(
            encapsulatedSecret: try Self.bytes(encapsulated),
            decapsulatedSecret: try Self.bytes(self.decapsulatedSecret),
            ourCiphertext:      Data(),
            peerCiphertext:     Data()
        )
    }

    /// A P-256 private key for `scalar` (32 bytes, big-endian), as a software `SecKey` —
    /// the same type an ephemeral key has in production.
    static func privateKey(_ scalar: String?) throws -> SecKey {
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: try Self.bytes(scalar))
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        return try #require(SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error))
    }

    /// The x963 public key (65 bytes) for `scalar`: scalar · G.
    static func publicMaterial(_ scalar: String?) throws -> Data {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: try Self.bytes(scalar)).publicKey.x963Representation
    }

    private static func batch(_ input: Batch) throws -> OccultaBundle.SealedPayload.PrekeySyncBatch {
        OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSinceReferenceDate: input.generatedAt),
            prekeys: try input.prekeys.map {
                OccultaBundle.WirePrekey(id: $0.id, publicKey: try Self.bytes($0.publicKey))
            }
        )
    }

    private static func challenge(_ input: ChallengeInput) throws -> IdentityChallengeEnvelope {
        IdentityChallengeEnvelope(
            kind:        try #require(IdentityChallengeEnvelope.Kind(rawValue: input.kind)),
            payload:     try Self.bytes(input.payload),
            contextNote: input.contextNote
        )
    }

    private static func shardOperation(_ input: ShardOperationInput) throws -> OccultaBundle.ShardOperation {
        OccultaBundle.ShardOperation(
            kind:        try #require(OccultaBundle.ShardOperation.Kind(rawValue: input.kind)),
            attribute:   try input.attribute.map(Self.attribute),
            attributeID: try input.attributeID.map(Self.uuid)
        )
    }

    private static func attribute(_ input: AttributeInput) throws -> SignedAttribute {
        SignedAttribute(
            id:        try Self.uuid(input.id),
            label:     input.label,
            value:     try Self.bytes(input.value),
            category:  try #require(SignedAttribute.Category(rawValue: input.category)),
            signature: try Self.bytes(input.signature),
            createdAt: Date(timeIntervalSinceReferenceDate: input.createdAt),
            expiresAt: input.expiresAt.map(Date.init(timeIntervalSinceReferenceDate:)),
            entryID:   try input.entryID.map(Self.uuid)
        )
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
