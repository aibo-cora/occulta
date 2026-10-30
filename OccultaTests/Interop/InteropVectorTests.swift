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

    /// The `ltKey` and `diceware` vectors run on a software identity key, because `Manager.Key` keeps its identity
    /// in the Enclave. This ties the two together: an Enclave identity and the vector's software peer derive the
    /// same key with each other, so what the vectors pin is what `Manager.Key` produces.
    @Test("The Enclave identity derives the same long-term key as the software one",
          .enabled(if: TestSupport.secureEnclaveAvailable()),
          arguments: try loadVectors().filter { $0.kind == "ltKey" || $0.kind == "diceware" })
    func enclaveIdentityAgrees(_ vector: Vector) throws {
        let tag = UUID().uuidString
        let enclave = Manager.Key(testingTag: tag)
        defer { enclave.delete(using: tag) }
        let enclaveSide = try vector.longTermKey(enclave, peerPublicKey: try Vector.publicMaterial(vector.peerScalar), fromPeer: false)
        let softwareSide = try vector.longTermKey(
            Vector.softwareIdentity(vector.peerScalar), peerPublicKey: try enclave.retrieveIdentity(), fromPeer: true
        )
        #expect(enclaveSide == softwareSide, "\(vector.name): Manager.Key and the software copy disagree")
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

    // ltKey, diceware, cardLongTermKey (with encapsulatedSecret and decapsulatedSecret in the hybrid forms)
    let ownScalar: String?
    let peerScalar: String?

    // diceware
    let ourNonce: String?
    let peerNonce: String?

    // gcm, streamBody
    let key: String?
    let plaintext: String?

    // streamHeaderAAD, streamNonce, streamAAD, streamBody, streamBodyDigest
    let blind: String?
    let header: String?
    let index: UInt64?
    let isFinal: Bool?
    /// A pattern repeated to `length` bytes, for a plaintext too long to write out.
    let repeating: String?
    let length: Int?

    // groupEnvelope
    let group: GroupInput?

    // recipientPayload
    let sessionKey: String?
    let custodyManifestCount: Int?
    let shardMetadataAttempted: Bool?
    let senderEphemeralSignature: String?
    let bodyDigest: String?

    // signingPayload
    let attribute: AttributeInput?

    // card, cardSigningPayload
    let card: CardInput?

    // cardIntroductionSigningPayload
    let introduction: IntroductionInput?

    // cardBootstrapKey, cardBootstrapLayer
    let bootstrap: BootstrapInput?

    // cardMeetingTranscript, cardMeetingProofPayload
    let meeting: MeetingInput?

    // cardField
    let cardState: String?

    // challengeField
    let challengeState: String?
    let challengeSlot: ChallengeSlotInput?

    struct ChallengeSlotInput: Decodable, Sendable {
        let depth: Int
        let nonce: String
        let issuedAt: UInt64
        let verifiedAt: UInt64
    }

    /// Introduction cards (SPEC §2). `expiresAtUnix` is Unix seconds, as on the wire.
    struct CardInput: Decodable, Sendable {
        let agreementKey: String
        let signingKey: String
        let expiresAtUnix: Int
        let mlkemEncapsulationKey: String
        let signature: String?
    }

    struct IntroductionInput: Decodable, Sendable {
        let cardDigest: String
        let agreementKey: String
        let signingKey: String
        let mlkemEncapsulationKey: String
        /// Only `recipientPayload` vectors carry it: the DER signature that travels with the introduction.
        let signature: String?
    }

    struct BootstrapInput: Decodable, Sendable {
        // cardBootstrapKey
        let ecdhOutput: String?
        let ownPublicKey: String?
        let peerPublicKey: String?
        let ss1: String?
        // cardBootstrapLayer
        let outerKey: String?
        let innerKey: String?
        let blind: String?
        let mlkemCiphertext: String?
        let payload: String?
        let outerNonce: String?
        let innerNonce: String?
    }

    struct MeetingInput: Decodable, Sendable {
        // cardMeetingTranscript
        let identityKeys: [String]?
        let nonces: [String]?
        let mlkemCiphertexts: [String]?
        // cardMeetingProofPayload
        let transcript: String?
        let signerIdentityKey: String?
    }

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
        /// Hex. Absent from the vectors recorded before batch IDs existed, which must keep their bytes.
        let id: String?
        /// Absent from the vectors recorded before last-resort keys existed (prekey continuity stage 2).
        let lastResort: WirePrekeyInput?
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
        /// Streamed layout only: the file's content is in the body stream, not the basket.
        let streamedLength: Int?
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

        case "ltKey", "diceware":
            // The long-term identity derivations. `Manager.Key` holds its identity in the Enclave, so these run on
            // TestKeyManager's software identity, and `enclaveIdentityAgrees` checks `Manager.Key` lands on the same
            // bytes. Both phones derive the key, each with itself as "own": the two must agree.
            let key = try self.longTermKey(
                Self.softwareIdentity(self.ownScalar), peerPublicKey: try Self.publicMaterial(self.peerScalar), fromPeer: false
            )
            let otherSide = try self.longTermKey(
                Self.softwareIdentity(self.peerScalar), peerPublicKey: try Self.publicMaterial(self.ownScalar), fromPeer: true
            )
            #expect(key == otherSide, "\(self.name): the two sides disagree")
            return key

        case "cardLongTermKey":
            // The long-term slot key between two card agreement keys (SPEC §3), from production's own ECDH step.
            let ownPublicKey = try Self.publicMaterial(self.ownScalar), peerPublicKey = try Self.publicMaterial(self.peerScalar)
            let encapsulated = try #require(self.encapsulatedSecret)
            let key = try #require(Manager.Crypto.cardLongTermKey(
                ecdhOutput:      try Manager.Crypto.ephemeralECDHOutput(try Self.privateKey(self.ownScalar), peerPublicKey: peerPublicKey),
                ownPublicKey:    ownPublicKey,
                peerPublicKey:   peerPublicKey,
                quantumMaterial: try self.quantumMaterial(encapsulated)
            ))
            let otherSide = try #require(Manager.Crypto.cardLongTermKey(
                ecdhOutput:      try Manager.Crypto.ephemeralECDHOutput(try Self.privateKey(self.peerScalar), peerPublicKey: ownPublicKey),
                ownPublicKey:    peerPublicKey,
                peerPublicKey:   ownPublicKey,
                quantumMaterial: try self.quantumMaterial(encapsulated, swapped: true)
            ))
            let bytes = key.withUnsafeBytes { Data($0) }
            #expect(bytes == otherSide.withUnsafeBytes { Data($0) }, "\(self.name): the two sides disagree")
            return bytes

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
                senderEphemeralSignature: try self.senderEphemeralSignature.map(Self.bytes),
                bodyDigest:               try self.bodyDigest.map(Self.bytes),
                introduction:             try self.introduction.map {
                    CardIntroduction(
                        agreementKey:          try Self.bytes($0.agreementKey),
                        signingKey:            try Self.bytes($0.signingKey),
                        mlkemEncapsulationKey: try Self.bytes($0.mlkemEncapsulationKey),
                        signature:             try Self.bytes($0.signature)
                    )
                }
            )
            // Mirrors `wrapRecipient` (Crypto+Manager+GroupEncrypt.swift), which encodes the
            // payload with a sorted-keys JSONEncoder before wrapping it. Keep the two in step.
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            return try encoder.encode(payload)

        case "signingPayload":
            return try Self.attribute(try #require(self.attribute)).signingPayload()

        case "basket":
            let basket = try self.basket()
            let streamed = self.streamedLengths()
            return streamed.contains { $0 != nil }
                ? try WireHandle.encode(basket: basket, streamedLengths: streamed)
                : try WireHandle.encode(basket: basket)

        case "streamKey":
            return BodyStream.streamKey(sessionKey: SymmetricKey(data: try Self.bytes(self.sessionKey)))
                .withUnsafeBytes { Data($0) }

        case "streamHeaderAAD":
            return try BodyStream.headerAAD(secrecy: try self.secrecy(), blind: try Self.bytes(self.blind))

        case "streamNonce":
            return BodyStream.nonce(index: try #require(self.index)).withUnsafeBytes { Data($0) }

        case "streamAAD":
            guard let isFinal = self.isFinal else { Issue.record("\(self.name): no isFinal"); return Data() }
            return BodyStream.aad(header: try Self.bytes(self.header), index: try #require(self.index), final: isFinal)

        case "streamBody", "streamBodyDigest":
            // The complete chunk stream for a fixed session key, header and plaintext. The long ones record the
            // SHA-256 of the stream, which is what `bodyDigest` is. Production `Opener` must then open the bytes.
            let plaintext = self.kind == "streamBody" ? try Self.bytes(self.plaintext) : try self.repeatedPlaintext()
            let sessionKey = SymmetricKey(data: try Self.bytes(self.sessionKey))
            let header = try Self.bytes(self.header)
            let layout = try BodyStream.Layout(plaintextLength: UInt64(plaintext.count))
            var sealer = BodyStream.Sealer(sessionKey: sessionKey, header: header, layout: layout)
            var stream = Data()
            try sealer.append(plaintext) { stream.append($0) }
            let digest = try sealer.finish { stream.append($0) }

            #expect(UInt64(stream.count) == layout.streamLength, "\(self.name): the stream is not T bytes")
            #expect(digest == Data(SHA256.hash(data: stream)), "\(self.name): the digest is not the stream's")
            var opener = BodyStream.Opener(sessionKey: sessionKey, header: header, layout: layout)
            var opened = Data()
            for index in 0..<layout.chunkCount {
                let start = Int(layout.wireOffset(ofChunk: index))
                opened.append(try opener.open(stream[start..<(start + layout.wireLength(ofChunk: index))], index: index))
            }
            #expect(opened == plaintext, "\(self.name): production Opener did not recover the plaintext")
            return self.kind == "streamBody" ? stream : digest

        case "streamManifest":
            let payload = OccultaBundle.SealedPayload(
                message:     try WireHandle.encode(basket: try self.basket(), streamedLengths: self.streamedLengths()),
                appVersion:  self.appVersion,
                senderProof: try self.senderProof.map(Self.bytes),
                groupID:     try self.groupID.map(Self.uuid)
            )
            return try BodyStream.Manifest.frame(payload: payload)

        case "depth":
            return DepthCodec.encode(try #require(self.value))

        case "card":
            // The 1,768 bytes of a card from fixed parts. The signature is an input: signatures are random.
            let encoded = try Self.introductionCard(try #require(self.card)).encoded
            #expect(encoded.count == IntroductionCard.byteCount, "\(self.name): a card is 1,768 bytes")
            return encoded

        case "cardSigningPayload":
            let input = try #require(self.card)
            return IntroductionCard.signingPayload(
                agreementKey:          try Self.bytes(input.agreementKey),
                signingKey:            try Self.bytes(input.signingKey),
                expiresAt:             Date(timeIntervalSince1970: Double(input.expiresAtUnix)),
                mlkemEncapsulationKey: try Self.bytes(input.mlkemEncapsulationKey)
            )

        case "cardIntroductionSigningPayload":
            let input = try #require(self.introduction)
            return CardIntroduction.signingPayload(
                cardDigest:            try Self.bytes(input.cardDigest),
                agreementKey:          try Self.bytes(input.agreementKey),
                signingKey:            try Self.bytes(input.signingKey),
                mlkemEncapsulationKey: try Self.bytes(input.mlkemEncapsulationKey)
            )

        case "cardBootstrapKey":
            // Carol's K_inner. Both phones derive it, each with itself as "own": the two must agree.
            let input = try #require(self.bootstrap)
            let ecdh = try Self.bytes(input.ecdhOutput), own = try Self.bytes(input.ownPublicKey)
            let peer = try Self.bytes(input.peerPublicKey), ss1 = try Self.bytes(input.ss1)
            let key = try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: own, peerPublicKey: peer, ss1: ss1))
            let otherSide = try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: peer, peerPublicKey: own, ss1: ss1))
            let bytes = key.withUnsafeBytes { Data($0) }
            #expect(bytes == otherSide.withUnsafeBytes { Data($0) }, "\(self.name): the two sides disagree")
            return bytes

        case "cardBootstrapLayer":
            // Fixed nonces, as the `gcm` kind has. What the vector pins is the layering and both AADs; production
            // `openOuter` and `openInner` must then open the recorded bytes.
            let input = try #require(self.bootstrap)
            let outerKey = SymmetricKey(data: try Self.bytes(input.outerKey))
            let innerKey = SymmetricKey(data: try Self.bytes(input.innerKey))
            let blind = try Self.bytes(input.blind), ciphertext = try Self.bytes(input.mlkemCiphertext)
            let payload = try Self.bytes(input.payload)
            let wrapped = try CardBootstrap.seal(
                payload: payload, mlkemCiphertext: ciphertext, outerKey: outerKey, innerKey: innerKey, blind: blind,
                outerNonce: try AES.GCM.Nonce(data: try Self.bytes(input.outerNonce)),
                innerNonce: try AES.GCM.Nonce(data: try Self.bytes(input.innerNonce))
            )
            let outer = try CardBootstrap.openOuter(wrapped, outerKey: outerKey, blind: blind)
            #expect(outer.mlkemCiphertext == ciphertext, "\(self.name): production openOuter changed the ciphertext")
            #expect(try CardBootstrap.openInner(outer.inner, mlkemCiphertext: outer.mlkemCiphertext, innerKey: innerKey, blind: blind) == payload,
                    "\(self.name): production openInner rejected the sealed bytes")
            return wrapped

        case "cardMeetingTranscript":
            let input = try #require(self.meeting)
            let ids = try Self.pair(input.identityKeys), nonces = try Self.pair(input.nonces), cts = try Self.pair(input.mlkemCiphertexts)
            let transcript = CardMeeting.transcript(identityKeys: ids, nonces: nonces, mlkemCiphertexts: cts)
            #expect(transcript == CardMeeting.transcript(
                identityKeys: (ids.1, ids.0), nonces: (nonces.1, nonces.0), mlkemCiphertexts: (cts.1, cts.0)
            ), "\(self.name): the two phones disagree")
            return transcript

        case "cardMeetingProofPayload":
            let input = try #require(self.meeting)
            return CardMeeting.proofPayload(
                transcript:        try Self.bytes(input.transcript),
                signerIdentityKey: try Self.bytes(input.signerIdentityKey)
            )

        case "challengeField":
            // The challenge column's plaintext before sealing (Bug 180).
            switch self.challengeState {
            case "empty": return try ChallengeStateCodec().encode(.empty)
            case "slot":
                guard let input = self.challengeSlot else {
                    Issue.record("\(self.name): no challengeSlot")
                    return Data()
                }
                var state = ChallengeState.empty
                state[depth: input.depth] = .init(
                    challenge: .init(nonce: try Self.bytes(input.nonce), issuedAt: input.issuedAt), verifiedAt: input.verifiedAt
                )
                return try ChallengeStateCodec().encode(state)
            default:
                Issue.record("\(self.name): unknown challenge state \(self.challengeState ?? "nil")")
                return Data()
            }

        case "cardField":
            // The card field's plaintext before sealing. Only the empty state has a fixed encoding to pin; the others
            // hold Enclave blobs.
            switch self.cardState {
            case "empty": return try CardStateCodec().encode(.empty)
            default:
                Issue.record("\(self.name): unknown card state \(self.cardState ?? "nil")")
                return Data()
            }

        default:
            Issue.record("\(self.name): unknown kind \(self.kind)")
            return Data()
        }
    }

    private func basket() throws -> Basket {
        Basket(
            id:    try Self.uuid(self.id),
            files: try (self.files ?? []).map(Self.file),
            date:  self.date.map(Date.init(timeIntervalSinceReferenceDate:)),
            owner: try self.owner.map(Self.bytes)
        )
    }

    private func streamedLengths() -> [UInt64?] {
        (self.files ?? []).map { $0.streamedLength.map(UInt64.init) }
    }

    private func repeatedPlaintext() throws -> Data {
        let unit = try Self.bytes(self.repeating)
        let count = try #require(self.length)
        return Data((0..<count).map { unit[$0 % unit.count] })
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

    /// `swapped` is the other phone's view: what one side encapsulated, the other decapsulated.
    private func quantumMaterial(_ encapsulated: String, swapped: Bool = false) throws -> QuantumKeyMaterial {
        let encapsulated = try Self.bytes(encapsulated), decapsulated = try Self.bytes(self.decapsulatedSecret)
        return QuantumKeyMaterial(
            encapsulatedSecret: swapped ? decapsulated : encapsulated,
            decapsulatedSecret: swapped ? encapsulated : decapsulated,
            ourCiphertext:      Data(),
            peerCiphertext:     Data()
        )
    }

    /// The `ltKey` or `diceware` key `manager`'s identity derives with `peerPublicKey`. `fromPeer` takes the other
    /// phone's view, with the ML-KEM secrets and the nonces the other way round.
    @MainActor
    func longTermKey(_ manager: any KeyManagerProtocol, peerPublicKey: Data, fromPeer: Bool) throws -> Data {
        let key: SymmetricKey?
        if self.kind == "diceware" {
            let ours = try Self.bytes(self.ourNonce), theirs = try Self.bytes(self.peerNonce)
            key = manager.createDicewareKey(
                peerP256Material: peerPublicKey,
                quantumMaterial:  try self.quantumMaterial(try #require(self.encapsulatedSecret), swapped: fromPeer),
                ourNonce:         fromPeer ? theirs : ours,
                peerNonce:        fromPeer ? ours : theirs
            )
        } else if let encapsulated = self.encapsulatedSecret {
            key = manager.createHybridSharedSecret(
                peerP256Material: peerPublicKey, quantumMaterial: try self.quantumMaterial(encapsulated, swapped: fromPeer)
            )
        } else {
            key = manager.createSharedSecret(using: peerPublicKey)
        }
        return try #require(key).withUnsafeBytes { Data($0) }
    }

    /// A TestKeyManager whose identity key is `scalar`. Only the identity takes part in a transport key, so the
    /// other four keys are the same scalar.
    @MainActor
    static func softwareIdentity(_ scalar: String?) throws -> TestKeyManager {
        TestKeyManager(
            scalars: Array(repeating: try Self.bytes(scalar), count: 5),
            tierSecretU: nil, tierSecretB: nil, tierPQRecordU: nil, tierPQRecordB: nil
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

    private static func introductionCard(_ input: CardInput) throws -> IntroductionCard {
        IntroductionCard(
            agreementKey:          try Self.bytes(input.agreementKey),
            signingKey:            try Self.bytes(input.signingKey),
            expiresAt:             Date(timeIntervalSince1970: Double(input.expiresAtUnix)),
            mlkemEncapsulationKey: try Self.bytes(input.mlkemEncapsulationKey),
            signature:             try Self.bytes(input.signature)
        )
    }

    private static func pair(_ hex: [String]?) throws -> (Data, Data) {
        let values = try #require(hex)
        try #require(values.count == 2)
        return (try Self.bytes(values[0]), try Self.bytes(values[1]))
    }

    private static func batch(_ input: Batch) throws -> OccultaBundle.SealedPayload.PrekeySyncBatch {
        OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSinceReferenceDate: input.generatedAt),
            prekeys: try input.prekeys.map {
                OccultaBundle.WirePrekey(id: $0.id, publicKey: try Self.bytes($0.publicKey))
            },
            id: try input.id.map(Self.bytes),
            lastResort: try input.lastResort.map {
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
