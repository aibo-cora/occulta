//
//  OccultaBundleTests.swift
//  OccultaTests
//
//  Simulator safe — no Secure Enclave, no SwiftData.
//  Tests: AAD computation, fingerprint math, nonce generation, Codable roundtrips.
//

import Testing
import CryptoKit
import Foundation
import Security

@testable import Occulta

// MARK: - AAD

@Suite("OccultaBundle — AAD")
struct OccultaBundleAADTests {

    private func makeSecrecy(
        mode:    OccultaBundle.Mode = .forwardSecret,
        epk:     Data              = Data(count: 65),
        prekeyID: String?          = "test-id"
    ) -> OccultaBundle.SecrecyContext {
        OccultaBundle.SecrecyContext(mode: mode, ephemeralPublicKey: epk, prekeyID: prekeyID)
    }

    @Test func aad_isDeterministic() throws {
        let secrecy = makeSecrecy()
        let a = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: secrecy)
        let b = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: secrecy)
        #expect(a == b)
    }

    @Test func aad_beginsWithVersionBytes() throws {
        let aad = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy())
        let prefix = "v3fs".data(using: .utf8)!
        #expect(aad.prefix(prefix.count) == prefix)
    }

    @Test func aad_differentVersion_producesDifferentAAD() throws {
        let secrecy = makeSecrecy()
        let v3  = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: secrecy)
        let v1  = try OccultaBundle.computeAdditionalAuthentication(version: .v1,   secrecy: secrecy)
        #expect(v3 != v1)
    }

    @Test func aad_differentMode_producesDifferentAAD() throws {
        let a = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(mode: .forwardSecret))
        let b = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(mode: .longTermFallback))
        #expect(a != b)
    }

    @Test func aad_differentPrekeyID_producesDifferentAAD() throws {
        let a = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(prekeyID: "id-A"))
        let b = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(prekeyID: "id-B"))
        #expect(a != b)
    }

    @Test func aad_nilPrekeyID_vs_nonNil_producesDifferentAAD() throws {
        let a = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(prekeyID: nil))
        let b = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(prekeyID: "id"))
        #expect(a != b)
    }

    @Test func aad_differentEphemeralPublicKey_producesDifferentAAD() throws {
        let a = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(epk: Data(repeating: 0x01, count: 65)))
        let b = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: makeSecrecy(epk: Data(repeating: 0x02, count: 65)))
        #expect(a != b)
    }
}

// MARK: - Fingerprint

@Suite("OccultaBundle — Fingerprint")
struct OccultaBundleFingerprintTests {

    @Test func fingerprint_is32Bytes() {
        let fp = OccultaBundle.SecrecyContext.fingerprint(
            for:   Data(repeating: 0x42, count: 65),
            nonce: Data(repeating: 0x01, count: 16)
        )
        #expect(fp.count == 32)
    }

    @Test func fingerprint_isDeterministic() {
        let key   = Data(repeating: 0x42, count: 65)
        let nonce = Data(repeating: 0x01, count: 16)
        #expect(
            OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: nonce) ==
            OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: nonce)
        )
    }

    @Test func fingerprint_differentKey_producesDifferentResult() {
        let nonce = Data(repeating: 0x01, count: 16)
        let a = OccultaBundle.SecrecyContext.fingerprint(for: Data(repeating: 0x42, count: 65), nonce: nonce)
        let b = OccultaBundle.SecrecyContext.fingerprint(for: Data(repeating: 0x43, count: 65), nonce: nonce)
        #expect(a != b)
    }

    @Test func fingerprint_differentNonce_producesDifferentResult() {
        let key = Data(repeating: 0x42, count: 65)
        let a = OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: Data(repeating: 0x01, count: 16))
        let b = OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: Data(repeating: 0x02, count: 16))
        #expect(a != b)
    }

    @Test func fingerprint_equalsSHA256_keyAppendedNonce() {
        let key   = Data(repeating: 0x42, count: 65)
        let nonce = Data(repeating: 0x01, count: 16)
        var input = key; input.append(nonce)
        let expected = Data(SHA256.hash(data: input))
        #expect(OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: nonce) == expected)
    }
}

// MARK: - Nonce generation

@Suite("OccultaBundle — Nonce")
struct OccultaBundleNonceTests {

    @Test func nonce_is16Bytes() throws {
        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        #expect(nonce.count == 16)
    }

    @Test func nonce_isNotAllZero() throws {
        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        #expect(!nonce.allSatisfy { $0 == 0 })
    }

    @Test func nonce_consecutiveCallsDiffer() throws {
        let a = try OccultaBundle.SecrecyContext.generateNonce()
        let b = try OccultaBundle.SecrecyContext.generateNonce()
        #expect(a != b)
    }

    @Test func nonce_entropyFailure_throwsEntropyUnavailable() {
        #expect(throws: OccultaBundle.BundleError.entropyUnavailable) {
            try OccultaBundle.SecrecyContext._generateNonce { _, _ in errSecParam }
        }
    }

    @Test func nonce_entropyFailure_doesNotReturnData() {
        var result: Data? = nil
        try? { result = try OccultaBundle.SecrecyContext._generateNonce { _, _ in errSecParam } }()
        #expect(result == nil)
    }
}

// MARK: - WirePrekey Codable

@Suite("OccultaBundle — WirePrekey")
struct WirePrekeyTests {

    @Test func wirePrekey_codableRoundtrip() throws {
        let original = OccultaBundle.WirePrekey(id: "abc-123", publicKey: Data(repeating: 0x04, count: 65))
        let data     = try JSONEncoder().encode(original)
        let decoded  = try JSONDecoder().decode(OccultaBundle.WirePrekey.self, from: data)
        #expect(decoded.id == original.id)
        #expect(decoded.publicKey == original.publicKey)
    }

    @Test func wirePrekey_hasNoContactID() throws {
        let prekey = OccultaBundle.WirePrekey(id: "x", publicKey: Data(count: 65))
        let json   = try JSONEncoder().encode(prekey)
        let string = String(data: json, encoding: .utf8)!
        #expect(!string.contains("contactID"))
    }
}

// MARK: - SealedPayload Codable

@Suite("OccultaBundle — SealedPayload")
struct SealedPayloadTests {

    @Test func sealedPayload_withoutBatch_roundtrips() throws {
        let payload  = OccultaBundle.SealedPayload(message: Data("hello".utf8), prekeyBatch: nil)
        let data     = try JSONEncoder().encode(payload)
        let decoded  = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: data)
        #expect(decoded.message == payload.message)
        #expect(decoded.prekeyBatch == nil)
    }

    @Test func sealedPayload_withBatch_roundtrips() throws {
        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSince1970: 1_000_000),
            prekeys: [
                OccultaBundle.WirePrekey(id: "k1", publicKey: Data(repeating: 0x04, count: 65)),
                OccultaBundle.WirePrekey(id: "k2", publicKey: Data(repeating: 0x05, count: 65))
            ]
        )
        let payload = OccultaBundle.SealedPayload(message: Data("msg".utf8), prekeyBatch: batch)
        let data    = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: data)

        #expect(decoded.message == payload.message)
        #expect(decoded.prekeyBatch?.prekeys.count == 2)
        #expect(decoded.prekeyBatch?.prekeys.first?.id == "k1")
        // generatedAt roundtrip — tolerance for JSON Date encoding
        let diff = abs(decoded.prekeyBatch!.generatedAt.timeIntervalSince1970 - 1_000_000)
        #expect(diff < 0.001)
    }

    @Test func prekeySyncBatch_batchContainsNoContactIDs() throws {
        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(),
            prekeys: [OccultaBundle.WirePrekey(id: "x", publicKey: Data(count: 65))]
        )
        let json   = String(data: try JSONEncoder().encode(batch), encoding: .utf8)!
        #expect(!json.contains("contactID"))
    }
}

// MARK: - OccultaBundle Codable + UI helpers

@Suite("OccultaBundle — Bundle")
struct OccultaBundleTests {

    private func makeBundle(mode: OccultaBundle.Mode = .forwardSecret) -> OccultaBundle {
        OccultaBundle(
            version:           .v3fs,
            secrecy:           OccultaBundle.SecrecyContext(
                mode:               mode,
                ephemeralPublicKey: Data(count: 65),
                prekeyID:           mode == .forwardSecret ? "test-prekey-id" : nil
            ),
            ciphertext:        Data(repeating: 0xFF, count: 64),
            fingerprintNonce:  Data(repeating: 0x01, count: 16),
            senderFingerprint: Data(repeating: 0xAB, count: 32)
        )
    }

    @Test func bundle_codableRoundtrip() throws {
        let original = makeBundle()
        let decoded  = try OccultaBundle.decoded(from: original.encoded())
        #expect(decoded.version == original.version)
        #expect(decoded.secrecy.mode == original.secrecy.mode)
        #expect(decoded.secrecy.ephemeralPublicKey == original.secrecy.ephemeralPublicKey)
        #expect(decoded.secrecy.prekeyID == original.secrecy.prekeyID)
        #expect(decoded.ciphertext == original.ciphertext)
        #expect(decoded.fingerprintNonce == original.fingerprintNonce)
        #expect(decoded.senderFingerprint == original.senderFingerprint)
    }

    @Test func bundle_fallback_nilPrekeyID() throws {
        let bundle = makeBundle(mode: .longTermFallback)
        let decoded = try OccultaBundle.decoded(from: bundle.encoded())
        #expect(decoded.secrecy.prekeyID == nil)
    }

    @Test func bundle_isForwardSecret_true_forFS() {
        #expect(makeBundle(mode: .forwardSecret).isForwardSecret == true)
    }

    @Test func bundle_isForwardSecret_false_forFallback() {
        #expect(makeBundle(mode: .longTermFallback).isForwardSecret == false)
    }

    @Test func bundle_securityLabel_forwardSecret() {
        #expect(makeBundle(mode: .forwardSecret).securityLabel == "Forward Secret")
    }

    @Test func bundle_securityLabel_fallback() {
        #expect(makeBundle(mode: .longTermFallback).securityLabel == "Standard Encryption")
    }

    @Test func bundle_currentVersion_isV3fs() {
        #expect(OccultaBundle.currentVersion == .v3fs)
    }

    @Test func bundle_malformedData_throwsOnDecode() {
        #expect(throws: (any Error).self) {
            try OccultaBundle.decoded(from: Data(repeating: 0xDE, count: 40))
        }
    }
}
