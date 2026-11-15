//
//  FuzzSeeds.swift
//  OccultaTests
//
//  The valid inputs the fuzzer mutates. Two sources:
//  - the encodings recorded in `Interop/InteropVectors.json`, which never change, and
//  - encodings built here with the real encoders and real keys, for what the vectors don't carry: a card
//    whose keys are genuine points and whose signature verifies, a signed shard, a sealed bootstrap slot.
//
//  Plain Foundation and OccultaFormats, so it builds into the standalone harness as well (see `FuzzEngine.swift`).
//

import Foundation
import CryptoKit
#if canImport(OccultaFormats)
@testable import OccultaFormats
#endif
#if canImport(OccultaCore)
@testable import OccultaCore
#endif

// MARK: - Recorded vectors

/// `InteropVectors.json`, read for its `expected` bytes only.
nonisolated enum FuzzVectors {

    struct Entry {
        let name: String
        let kind: String
        let bytes: Data
    }

    private final class BundleToken {}

    /// The fixture, from the test bundle or, for the standalone harness, from `OCCULTA_FUZZ_VECTORS`.
    static let all: [Entry] = {
        var candidates: [URL] = []
        if let path = ProcessInfo.processInfo.environment["OCCULTA_FUZZ_VECTORS"] { candidates.append(URL(fileURLWithPath: path)) }
        let bundle = Bundle(for: BundleToken.self)
        candidates += [
            bundle.url(forResource: "InteropVectors", withExtension: "json"),
            bundle.url(forResource: "InteropVectors", withExtension: "json", subdirectory: "Interop"),
        ].compactMap { $0 }

        for url in candidates {
            guard let data = try? Data(contentsOf: url),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let vectors = root["vectors"] as? [[String: Any]]
            else { continue }
            return vectors.compactMap { vector in
                guard let name = vector["name"] as? String, let kind = vector["kind"] as? String,
                      let hex = vector["expected"] as? String, let bytes = Hex.decode(hex)
                else { return nil }
                return Entry(name: name, kind: kind, bytes: bytes)
            }
        }
        return []
    }()

    static func entries(ofKind kinds: String...) -> [Entry] {
        Self.all.filter { kinds.contains($0.kind) }
    }
}

// MARK: - Big-endian walkers, for the length fields

nonisolated enum FuzzLayout {

    static func uint(_ bytes: Data, at offset: Int, width: Int) -> UInt64? {
        guard offset >= 0, offset + width <= bytes.count else { return nil }
        let start = bytes.startIndex + offset
        return bytes[start..<(start + width)].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    }

    /// The header's ciphertext length, and the TLV section lengths that follow the ciphertext.
    static func envelope(_ bytes: Data) -> [FuzzLengthField] {
        var fields = [FuzzLengthField(offset: 159, width: 8)]
        guard let length = Self.uint(bytes, at: 159, width: 8), length < UInt64(bytes.count) else { return fields }
        var offset = 167 + Int(length)
        while offset + 5 <= bytes.count {
            fields.append(FuzzLengthField(offset: offset + 1, width: 4))
            guard let section = Self.uint(bytes, at: offset + 1, width: 4), section < UInt64(bytes.count) else { break }
            offset += 5 + Int(section)
        }
        return fields
    }

    /// `u32 metaLength ‖ meta ‖ u64 messageLength ‖ message`.
    static func payload(_ bytes: Data) -> [FuzzLengthField] {
        var fields = [FuzzLengthField(offset: 0, width: 4)]
        if let meta = Self.uint(bytes, at: 0, width: 4), meta < UInt64(bytes.count) {
            fields.append(FuzzLengthField(offset: 4 + Int(meta), width: 8))
        }
        return fields
    }

    /// `u32 metaLength ‖ meta ‖ u32 fileCount ‖ (u32 fileMetaLength ‖ fileMeta ‖ u64 contentLength ‖ content)*`.
    static func basket(_ bytes: Data) -> [FuzzLengthField] {
        var fields = [FuzzLengthField(offset: 0, width: 4)]
        guard let meta = Self.uint(bytes, at: 0, width: 4), meta < UInt64(bytes.count) else { return fields }
        var offset = 4 + Int(meta)
        fields.append(FuzzLengthField(offset: offset, width: 4))
        guard let count = Self.uint(bytes, at: offset, width: 4) else { return fields }
        offset += 4
        for _ in 0..<min(count, 16) {
            fields.append(FuzzLengthField(offset: offset, width: 4))
            guard let fileMeta = Self.uint(bytes, at: offset, width: 4), fileMeta < UInt64(bytes.count) else { break }
            offset += 4 + Int(fileMeta)
            fields.append(FuzzLengthField(offset: offset, width: 8))
            guard let content = Self.uint(bytes, at: offset, width: 8), content < UInt64(bytes.count) else { break }
            offset += 8 + Int(content)
        }
        return fields
    }

    /// A streamed manifest: `u32 manifestLength ‖ payload`.
    static func manifest(_ bytes: Data) -> [FuzzLengthField] {
        var fields = [FuzzLengthField(offset: 0, width: 4)]
        if let manifest = Self.uint(bytes, at: 4, width: 4), manifest < UInt64(bytes.count) {
            fields.append(FuzzLengthField(offset: 4 + 4 + Int(manifest), width: 8))
            fields.append(FuzzLengthField(offset: 4, width: 4))
        }
        return fields
    }
}

// MARK: - Seeds built with the real encoders

nonisolated enum FuzzSeeds {

    /// One signing key for everything built here. Deterministic, so a failure's input is the same on every run.
    static let signingKey: P256.Signing.PrivateKey = {
        try! P256.Signing.PrivateKey(rawRepresentation: Data((1...32).map { UInt8($0) }))
    }()

    static let agreementKey: P256.KeyAgreement.PrivateKey = {
        try! P256.KeyAgreement.PrivateKey(rawRepresentation: Data((1...32).map { UInt8(33 - $0) }))
    }()

    static var signingPublicKey: Data { Self.signingKey.publicKey.x963Representation }

    private static let id1 = UUID(uuidString: "A1A1A1A1-0000-4000-8000-000000000001")!
    private static let id2 = UUID(uuidString: "A1A1A1A1-0000-4000-8000-000000000002")!
    private static let date = Date(timeIntervalSinceReferenceDate: 800_000_000)

    /// A shard attribute signed by `signingKey`, so it verifies.
    static func signedAttribute(category: SignedAttribute.Category = .shard, expiresAt: Date? = nil) -> SignedAttribute {
        let value = Data((0..<33).map { UInt8($0 &* 7) })
        let payload = SignedAttribute.signingPayload(
            id: id1, category: category, value: value, entryID: id2, createdAt: Self.date, expiresAt: expiresAt
        )
        let signature = try! Self.signingKey.signature(for: payload)
        return SignedAttribute(
            id: id1, label: "vault-bek-shard", value: value, category: category, signature: signature.derRepresentation,
            createdAt: Self.date, expiresAt: expiresAt, entryID: id2
        )
    }

    static func prekeyBatch() -> OccultaBundle.SealedPayload.PrekeySyncBatch {
        let key = { (n: UInt8) in OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data([0x04] + [UInt8](repeating: n, count: 64))) }
        return OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Self.date, prekeys: [key(1), key(2)], id: Data(repeating: 9, count: 16), lastResort: key(3)
        )
    }

    /// Every optional field of a payload present.
    static func richPayload() -> OccultaBundle.SealedPayload {
        OccultaBundle.SealedPayload(
            message: try! WireHandle.encode(basket: richBasket()),
            prekeyBatch: Self.prekeyBatch(),
            identityChallenge: IdentityChallengeEnvelope.challenge(payload: Data(repeating: 5, count: 72), contextNote: "Is this you?"),
            shardOperations: [
                OccultaBundle.ShardOperation(kind: .distribute, attribute: Self.signedAttribute()),
                OccultaBundle.ShardOperation(kind: .replace, attribute: Self.signedAttribute(expiresAt: Date(timeIntervalSinceReferenceDate: 900_000_000)), attributeID: id2),
                OccultaBundle.ShardOperation(kind: .handback, attribute: Self.signedAttribute()),
                OccultaBundle.ShardOperation(kind: .unsupported),
            ],
            custodyManifest: [id1, id2],
            appVersion: "2.0.0",
            senderProof: Data(repeating: 6, count: 32),
            groupID: id1
        )
    }

    static func richBasket() -> Basket {
        Basket(
            id: id1,
            files: [
                File(id: id1, content: Data("hello".utf8), format: .text, date: Self.date),
                File(id: id2, content: Data([0xFF, 0xD8, 0xFF]), format: .file(File.Metadata(name: "a", extension: "jpg", note: "n")), date: Self.date),
                File(id: UUID(), content: Data(), format: .link, date: nil),
                File(id: UUID(), content: Data("[]".utf8), format: .contacts, date: Self.date),
            ],
            date: Self.date, owner: Data(repeating: 4, count: 32)
        )
    }

    static func richRecipientPayload() -> OccultaBundle.RecipientPayload {
        OccultaBundle.RecipientPayload(
            sessionKey: Data(repeating: 1, count: 32), prekeyBatch: Self.prekeyBatch(),
            shardOperations: [OccultaBundle.ShardOperation(kind: .distribute, attribute: Self.signedAttribute())],
            custodyManifest: [id1, id2], custodyManifestCount: 2, shardMetadataAttempted: true,
            senderEphemeralSignature: Data(repeating: 2, count: 70), bodyDigest: Data(repeating: 3, count: 32),
            introduction: nil
        )
    }

    /// A group bundle in the binary envelope, and the same bundle as legacy JSON.
    static func groupBundle() -> OccultaBundle {
        let recipient = { (mode: OccultaBundle.Mode, prekeyID: String?) in
            OccultaBundle.Recipient(
                secrecyContext: OccultaBundle.SecrecyContext(
                    mode: mode, ephemeralPublicKey: mode == .forwardSecret ? Data([0x04] + [UInt8](repeating: 7, count: 64)) : Data(), prekeyID: prekeyID
                ),
                wrappedPayload: Data(repeating: 8, count: 120)
            )
        }
        return OccultaBundle(
            version: .v4, secrecy: OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data(), prekeyID: nil),
            ciphertext: Data(repeating: 0xC1, count: 80), fingerprintNonce: Data(repeating: 0xA, count: 16),
            senderFingerprint: Data(repeating: 0xB, count: 32),
            group: OccultaBundle.GroupEnvelope(
                blind: Data(repeating: 0xD, count: 32), blindNonce: Data(repeating: 0xE, count: 16),
                recipients: [recipient(.forwardSecret, UUID().uuidString), recipient(.longTermFallback, nil)]
            )
        )
    }

    // MARK: Introduction cards

    /// A modulus-valid ML-KEM-1024 key: 1,024 coefficients below 3329, then ρ. CryptoKit's own check is a length check.
    static var mlkemKey: Data {
        var bytes = [UInt8](repeating: 0, count: 1_568)
        for index in 0..<1_536 { bytes[index] = index % 3 == 1 ? 0x01 : UInt8(index % 251) & 0x7F }
        return Data(bytes)
    }

    /// A genuine card: both keys are curve points and the signature verifies, so `recognize` accepts it.
    static func card(expiresAt: Date = Date(timeIntervalSince1970: 4_000_000_000)) -> IntroductionCard {
        let agreement = Self.agreementKey.publicKey.x963Representation
        let signing = Self.signingPublicKey
        let payload = IntroductionCard.signingPayload(
            agreementKey: agreement, signingKey: signing, expiresAt: expiresAt, mlkemEncapsulationKey: Self.mlkemKey
        )
        let signature = try! Self.signingKey.signature(for: payload)
        return IntroductionCard(
            agreementKey: agreement, signingKey: signing, expiresAt: expiresAt, mlkemEncapsulationKey: Self.mlkemKey,
            signature: signature.rawRepresentation
        )
    }

    /// `bytes` with the last 64 re-signed by `signingKey` over the card's signing payload, so a mutation that left the
    /// signing key alone still reaches the checks behind the signature.
    static func resigned(_ bytes: Data) -> Data? {
        guard bytes.count == IntroductionCard.byteCount else { return nil }
        let body = Data(bytes.prefix(IntroductionCard.signedByteCount))
        guard body.subdata(in: 64..<128) == Self.signingPublicKey.dropFirst(),
              let signature = try? Self.signingKey.signature(for: IntroductionCard.signingLabel + body)
        else { return nil }
        return body + signature.rawRepresentation
    }

    static func introduction(cardDigest: Data) -> CardIntroduction {
        let agreement = Self.agreementKey.publicKey.x963Representation
        let signing = Self.signingPublicKey
        let payload = CardIntroduction.signingPayload(
            cardDigest: cardDigest, agreementKey: agreement, signingKey: signing, mlkemEncapsulationKey: Self.mlkemKey
        )
        return CardIntroduction(
            agreementKey: agreement, signingKey: signing, mlkemEncapsulationKey: Self.mlkemKey,
            signature: try! Self.signingKey.signature(for: payload).derRepresentation
        )
    }
}
