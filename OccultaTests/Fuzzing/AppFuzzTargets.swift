//
//  AppFuzzTargets.swift
//  OccultaTests
//
//  The decoders that live in the app module, not in `OccultaFormats`: what a radio peer sends during an exchange,
//  what a contact's shared file holds once it is open, the share extension's manifest, and the at-rest codecs
//  that read a sealed field back.
//
//  Everything in the app module is `@MainActor` by default, so these are `MainActorFuzzTarget`s and run on the
//  main thread (`Fuzzer.runOnMainActor`). Only `ShareManifest` is `nonisolated`.
//
//  Who can reach each one:
//  - `Exchange`, the discovery token: anyone in radio range during an exchange, with no key.
//  - `Contact.Draft`, `RecipientPayload` and the identity-challenge payloads: a contact whose message opened.
//  - the codecs for `CardState`, `PrekeyRecord`, `ChallengeState` and the backup-key record: nobody. They read
//    what the app sealed under a key only this device holds. They are here because a corrupt row (a failed write,
//    a migration, a restored backup) reaches them, and a trap on launch is a crash loop.
//

import Foundation
import CryptoKit
import NearbyInteraction
import MultipeerConnectivity
@testable import Occulta
@testable import OccultaFormats
@testable import OccultaCore

// MARK: - The list

enum AppFuzzTargets {

    @MainActor
    static var all: [any MainActorFuzzTarget] {
        [
            MainActorJSONTarget<Exchange>(name: "Exchange JSON", seeds: Self.exchangeSeeds(), consumer: Self.consume(exchange:)),
            DiscoveryTokenTarget(),
            MainActorJSONTarget<[Contact.Draft]>(name: "Contact.Draft list JSON (imported contacts)", seeds: Self.draftSeeds()),
            MainActorJSONTarget<OccultaBundle.RecipientPayload>(
                name: "RecipientPayload JSON, app consumers", seeds: FormatFuzzTargets.recipientPayloadSeeds(), consumer: Self.consume(recipientPayload:)
            ),
            MainActorJSONTarget<VaultManager.VaultBackup>(name: "Vault backup JSON (.occbak, after the key opens it)", seeds: Self.vaultBackupSeeds()),
            IdentityChallengePayloadTarget(),
            CardStateCodecTarget(),
            PrekeyRecordCodecTarget(),
            ChallengeStateCodecTarget(),
            BackupKeyPayloadCodecTarget(),
        ]
    }

    // MARK: Consumers

    /// What the exchange does with a decoded message besides branching on it.
    @MainActor
    private static func consume(exchange: Exchange) {
        _ = (exchange.isCardProof, exchange.isDiscovery, exchange.isIdentity, exchange.isCiphertext, exchange.supportsPQ)
        _ = exchange.identity?.sha256
        _ = exchange.nonce.map { $0.count == 16 }
    }

    /// What `openGroup` and the shard handlers do with a slot's payload.
    @MainActor
    private static func consume(recipientPayload payload: OccultaBundle.RecipientPayload) {
        _ = ContactManager.receivedManifest(payload, isFallback: false)
        _ = ContactManager.receivedManifest(payload, isFallback: true)
        for operation in payload.shardOperations where operation.kind != .unsupported {
            _ = operation.attribute?.verify(against: FuzzSeeds.signingPublicKey)
        }
        _ = payload.introduction?.verify(cardDigest: Data(repeating: 0x42, count: 32))
        _ = ShardPadding.tier(for: payload.shardOperations.count)
    }

    // MARK: Seeds

    static func exchangeSeeds() -> [FuzzSeedInput] {
        func json(_ exchange: Exchange) -> Data {
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            return try! encoder.encode(exchange)
        }
        let key65 = Data([0x04] + [UInt8](repeating: 5, count: 64))
        return [
            FuzzSeedInput("discovery", json(Exchange(id: UUID().uuidString, token: DiscoveryTokenTarget.archivedToken(), nonce: Data(repeating: 1, count: 16))), isText: true),
            FuzzSeedInput("identity, classical", json(Exchange(id: UUID().uuidString, token: Data(), identity: key65)), isText: true),
            FuzzSeedInput("identity, hybrid", json(Exchange(id: UUID().uuidString, token: Data(), identity: key65, encapsulationKey: FuzzSeeds.mlkemKey)), isText: true),
            FuzzSeedInput("ciphertext", json(Exchange(id: UUID().uuidString, token: Data(), ciphertext: Data(repeating: 9, count: 1_568))), isText: true),
            FuzzSeedInput("card proof", json(Exchange(id: UUID().uuidString, token: Data(), cardProof: Data(repeating: 7, count: 64))), isText: true),
        ]
    }

    static func vaultBackupSeeds() -> [FuzzSeedInput] {
        let entry = VaultManager.VaultBackupEntry(
            id: UUID(), entryType: 0, createdAt: Date(timeIntervalSinceReferenceDate: 800_000_000), label: Data("label".utf8), content: Data("content".utf8)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return [
            FuzzSeedInput("one entry", try! encoder.encode(VaultManager.VaultBackup(version: 1, createdAt: Date(timeIntervalSinceReferenceDate: 800_000_000), entries: [entry])), isText: true),
            FuzzSeedInput("no entries", try! encoder.encode(VaultManager.VaultBackup(version: 1, createdAt: Date(timeIntervalSinceReferenceDate: 800_000_000), entries: [])), isText: true),
        ]
    }

    static func draftSeeds() -> [FuzzSeedInput] {
        let draft = Contact.Draft(
            identifier: "ABC:ABPerson", givenName: "Ada", familyName: "Lovelace", organizationName: "Analytical", birthday: "1815-12-10",
            note: "note", imageData: Data([1, 2, 3]),
            phoneNumbers: [], emailAddresses: [], contactPublicKeys: []
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return [
            FuzzSeedInput("one draft", try! encoder.encode([draft]), isText: true),
            FuzzSeedInput("no drafts", Data("[]".utf8), isText: true),
        ]
    }
}

// MARK: - JSON, on the main actor

/// `FormatFuzzTargets`' `JSONTarget` for a type the app module isolates to the main actor.
struct MainActorJSONTarget<T: Codable>: MainActorFuzzTarget {
    let name: String
    let corpus: [FuzzSeedInput]
    let consumer: @MainActor (T) -> Void

    init(name: String, seeds: [FuzzSeedInput], consumer: @escaping @MainActor (T) -> Void = { _ in }) {
        self.name = name
        self.corpus = seeds
        self.consumer = consumer
    }

    func run(_ input: Data) throws {
        let value = try BoundedJSON.decode(T.self, from: input)
        self.consumer(value)

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let first = try encoder.encode(value)
        let second = try encoder.encode(try JSONDecoder().decode(T.self, from: first))
        guard first == second else { throw FuzzViolation("\(T.self): re-encoding a decoded value is not stable") }
    }
}

// MARK: - The discovery token

/// A discovery message's `token` is `NSKeyedUnarchiver`'s to read, and it is the one field a nearby phone sends that
/// goes to a system parser. The class is pinned to `NIDiscoveryToken`, so what it may build is limited, but the
/// archive's own structure is still the sender's.
struct DiscoveryTokenTarget: MainActorFuzzTarget {
    let name = "NSKeyedUnarchiver of an NIDiscoveryToken"

    /// A real token when this host can make one, otherwise an archive of a type the unarchiver will refuse.
    nonisolated static func archivedToken() -> Data {
        if let token = NISession().discoveryToken,
           let data = try? NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true) {
            return data
        }
        return try! NSKeyedArchiver.archivedData(withRootObject: "token" as NSString, requiringSecureCoding: true)
    }

    var corpus: [FuzzSeedInput] {
        let nested = try! NSKeyedArchiver.archivedData(
            withRootObject: ["a": [1, 2, 3], "b": Data([1])] as NSDictionary, requiringSecureCoding: true
        )
        return [
            FuzzSeedInput("token (or a string where this host has none)", Self.archivedToken(), isValid: NISession().discoveryToken != nil),
            FuzzSeedInput("nested dictionary", nested, isValid: false),
        ]
    }

    func run(_ input: Data) throws {
        guard try NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: input) != nil else { throw FuzzRejection() }
    }
}

// MARK: - Identity challenge payloads

/// The binary payloads of an identity challenge, read from a contact's message. They take their ranges from `Data`
/// subscripts, which are absolute: on a slice that starts past 0 a literal range reads the wrong bytes or traps.
struct IdentityChallengePayloadTarget: MainActorFuzzTarget {
    let name = "IdentityChallenge payloads"

    var corpus: [FuzzSeedInput] {
        let challenge = IdentityChallenge.ChallengePayload(
            nonce: Data(repeating: 1, count: 32), timestamp: IdentityChallenge.encodeTimestamp(1_700_000_000),
            challengerFingerprint: Data(repeating: 3, count: 32)
        ).encoded()
        let response = IdentityChallenge.ResponsePayload(challengeNonce: Data(repeating: 1, count: 32), signature: Data(repeating: 9, count: 71)).encoded()
        return [FuzzSeedInput("challenge payload", challenge), FuzzSeedInput("response payload", response)]
    }

    func run(_ input: Data) throws {
        var accepted = false
        if let challenge = try? IdentityChallenge.ChallengePayload(from: input) {
            accepted = true
            guard challenge.nonce.count == 32, challenge.timestamp.count == 8, challenge.challengerFingerprint.count == 32 else {
                throw FuzzViolation("ChallengePayload: a field of the wrong size")
            }
            _ = try IdentityChallenge.decodeTimestamp(challenge.timestamp)
            guard challenge.encoded() == Data(input) else { throw FuzzViolation("ChallengePayload: encoded() != the 72 bytes it came from") }
        }
        if let response = try? IdentityChallenge.ResponsePayload(from: input) {
            accepted = true
            guard response.challengeNonce.count == 32, response.signature.count == input.count - 32 else {
                throw FuzzViolation("ResponsePayload: a field of the wrong size")
            }
            guard response.encoded() == Data(input) else { throw FuzzViolation("ResponsePayload: encoded() != the bytes it came from") }
        }
        _ = try? IdentityChallenge.decodeTimestamp(input)
        if !accepted { throw FuzzRejection() }
    }
}

// MARK: - Sealed-field codecs

/// A padded plaintext (`version ‖ u32 length ‖ binary plist ‖ zeros`) and the plist inside it.
struct CardStateCodecTarget: MainActorFuzzTarget {
    let name = "CardStateCodec"

    var corpus: [FuzzSeedInput] {
        let codec = CardStateCodec()
        let key = Data(repeating: 5, count: 200)
        let states: [CardState] = [
            .empty,
            .issued(card: FuzzSeeds.card().encoded, agreementKey: key, signingKey: key, mlkemKey: key, expiresAt: Date(timeIntervalSinceReferenceDate: 800_000_000)),
            .imported(peerCard: FuzzSeeds.card().encoded, agreementKey: key, signingKey: key, mlkemKey: key, ss1: Data(repeating: 1, count: 32), ct1: Data(repeating: 2, count: 1_568), expiresAt: Date(timeIntervalSinceReferenceDate: 800_000_000), sentFirstMessage: true),
        ]
        var seeds = states.enumerated().map { FuzzSeedInput("state \($0.offset)", try! codec.encode($0.element), lengthFields: [FuzzLengthField(offset: 1, width: 4)]) }
        seeds += FuzzVectors.entries(ofKind: "cardField").map { FuzzSeedInput($0.name, $0.bytes, lengthFields: [FuzzLengthField(offset: 1, width: 4)]) }
        return seeds
    }

    func run(_ input: Data) throws {
        let state = try CardStateCodec().decode(input)
        _ = state.isCardContact
        let again = try CardStateCodec().decode(try CardStateCodec().encode(state))
        guard again == state else { throw FuzzViolation("CardState: changed across a re-encode") }
    }
}

struct PrekeyRecordCodecTarget: MainActorFuzzTarget {
    let name = "PrekeyRecordCodec"

    var corpus: [FuzzSeedInput] {
        let codec = PrekeyRecordCodec()
        var record = PrekeyRecord.empty
        record.ownBatches = [PrekeyRecord.OwnBatch(
            id: Data(repeating: 1, count: 16), createdAt: Date(timeIntervalSinceReferenceDate: 800_000_000), retiredAt: nil, isPending: true,
            keys: [PrekeyRecord.OwnKey(id: Data(repeating: 2, count: 16), blob: Data(repeating: 3, count: 120), publicKey: Data([0x04] + [UInt8](repeating: 4, count: 64)))]
        )]
        record.acceptedBatchIDs = [Data(repeating: 6, count: 16)]
        return [
            FuzzSeedInput("empty record", try! codec.encode(.empty), lengthFields: [FuzzLengthField(offset: 1, width: 4)]),
            FuzzSeedInput("record with a batch", try! codec.encode(record), lengthFields: [FuzzLengthField(offset: 1, width: 4)]),
        ]
    }

    func run(_ input: Data) throws {
        let record = try PrekeyRecordCodec().decode(input)
        let again = try PrekeyRecordCodec().decode(try PrekeyRecordCodec().encode(record))
        guard again == record else { throw FuzzViolation("PrekeyRecord: changed across a re-encode") }
    }
}

struct ChallengeStateCodecTarget: MainActorFuzzTarget {
    let name = "ChallengeStateCodec"

    var corpus: [FuzzSeedInput] {
        FuzzVectors.entries(ofKind: "challengeField").map { FuzzSeedInput($0.name, $0.bytes) }
    }

    func run(_ input: Data) throws {
        let state = try ChallengeStateCodec().decode(input)
        let again = try ChallengeStateCodec().decode(try ChallengeStateCodec().encode(state))
        guard again == state else { throw FuzzViolation("ChallengeState: changed across a re-encode") }
    }
}

struct BackupKeyPayloadCodecTarget: MainActorFuzzTarget {
    let name = "Backup key payload codec"

    var corpus: [FuzzSeedInput] {
        let shard = ShardRecord(trustee: TrusteeTag(identifier: "trustee"), attributeID: UUID(), status: .confirmed, distributedAt: Date(timeIntervalSince1970: 1_700_000_000))
        let payload = BackupEncryptionKey.Payload(
            bekBytes: Data(repeating: 1, count: 32), distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 2, shards: [shard, shard])
        )
        let bytes = try! VaultManager.Backup.PayloadCodec.encode(payload)
        return [FuzzSeedInput("payload with two shards", bytes, lengthFields: [FuzzLengthField(offset: 0, width: 2), FuzzLengthField(offset: 50, width: 1)])]
    }

    func run(_ input: Data) throws {
        guard let payload = VaultManager.Backup.PayloadCodec.decode(input) else { throw FuzzRejection() }
        guard payload.bekBytes.count == 32 else { throw FuzzViolation("backup key of \(payload.bekBytes.count) bytes") }
    }
}
