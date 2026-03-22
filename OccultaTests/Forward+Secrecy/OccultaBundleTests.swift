//
//  OccultaBundleTests.swift
//  OccultaTests
//
//  Tests for OccultaBundle structure, serialisation, fingerprint math, and AAD.
//  No SE. No Manager.Crypto. No SwiftData.
//  Safe to run in the simulator.
//

import XCTest
import CryptoKit
@testable import Occulta

final class OccultaBundleTests: XCTestCase {

    // MARK: - Helpers

    private func makeBundle(
        mode:        OccultaBundle.Mode = .forwardSecret,
        version:     OccultaBundle.Version = .v3fs,
        prekeyID:    String?            = "test-prekey-id",
        prekeySeq:   Int?               = 3,
        nonce:       Data               = Data(repeating: 0x01, count: 16),
        fingerprint: Data               = Data(repeating: 0xAB, count: 32),
        ciphertext:  Data               = Data(repeating: 0xFF, count: 64),
        prekeyBatch: OccultaBundle.PrekeySyncBatch? = nil
    ) -> OccultaBundle {
        let secrecy = OccultaBundle.SecrecyContext(
            mode:               mode,
            ephemeralPublicKey: Data(count: 65),
            prekeyID:           prekeyID,
            prekeySequence:     prekeySeq,
            prekeyBatch:        prekeyBatch
        )
        return OccultaBundle(
            version:           version,
            secrecy:           secrecy,
            ciphertext:        ciphertext,
            fingerprintNonce:  nonce,
            senderFingerprint: fingerprint
        )
    }

    // MARK: - Version

    func test_currentVersion_isV3fs() {
        XCTAssertEqual(OccultaBundle.currentVersion, .v3fs)
    }

    func test_versionRawValues() {
        XCTAssertEqual(OccultaBundle.Version.v1.rawValue,   "v1")
        XCTAssertEqual(OccultaBundle.Version.v2.rawValue,   "v2")
        XCTAssertEqual(OccultaBundle.Version.v3fs.rawValue, "v3fs")
    }

    // MARK: - Mode

    func test_modeRawValues() {
        XCTAssertEqual(OccultaBundle.Mode.forwardSecret.rawValue,    "forwardSecret")
        XCTAssertEqual(OccultaBundle.Mode.longTermFallback.rawValue, "longTermFallback")
    }

    // MARK: - UI helpers

    func test_isForwardSecret_trueForFSMode()       { XCTAssertTrue(makeBundle(mode: .forwardSecret).isForwardSecret) }
    func test_isForwardSecret_falseForFallback()    { XCTAssertFalse(makeBundle(mode: .longTermFallback).isForwardSecret) }
    func test_securityLabel_forwardSecret()         { XCTAssertEqual(makeBundle(mode: .forwardSecret).securityLabel, "Forward Secret") }
    func test_securityLabel_fallback()              { XCTAssertEqual(makeBundle(mode: .longTermFallback).securityLabel, "Standard Encryption") }

    // MARK: - Serialisation roundtrip

    func test_encodeDecode_preservesVersion() throws {
        let decoded = try OccultaBundle.decoded(from: makeBundle().encoded())
        XCTAssertEqual(decoded.version, .v3fs)
    }

    func test_encodeDecode_preservesMode() throws {
        for mode in [OccultaBundle.Mode.forwardSecret, .longTermFallback] {
            let decoded = try OccultaBundle.decoded(from: makeBundle(mode: mode).encoded())
            XCTAssertEqual(decoded.secrecy.mode, mode)
        }
    }

    func test_encodeDecode_preservesPrekeyIDAndSequence() throws {
        let decoded = try OccultaBundle.decoded(from: makeBundle(prekeyID: "xyz", prekeySeq: 7).encoded())
        XCTAssertEqual(decoded.secrecy.prekeyID,       "xyz")
        XCTAssertEqual(decoded.secrecy.prekeySequence, 7)
    }

    func test_encodeDecode_nilPrekeyIDOnFallback() throws {
        let decoded = try OccultaBundle.decoded(from: makeBundle(mode: .longTermFallback, prekeyID: nil, prekeySeq: nil).encoded())
        XCTAssertNil(decoded.secrecy.prekeyID)
        XCTAssertNil(decoded.secrecy.prekeySequence)
    }

    func test_encodeDecode_preservesFingerprintFields() throws {
        let nonce       = Data((0..<16).map { UInt8($0) })
        let fingerprint = Data((0..<32).map { UInt8($0 &+ 100) })
        let decoded     = try OccultaBundle.decoded(from: makeBundle(nonce: nonce, fingerprint: fingerprint).encoded())
        XCTAssertEqual(decoded.fingerprintNonce,  nonce)
        XCTAssertEqual(decoded.senderFingerprint, fingerprint)
    }

    func test_encodeDecode_preservesCiphertext() throws {
        let ct      = Data((0..<128).map { UInt8($0) })
        let decoded = try OccultaBundle.decoded(from: makeBundle(ciphertext: ct).encoded())
        XCTAssertEqual(decoded.ciphertext, ct)
    }

    func test_encodeDecode_preservesPrekeyBatch() throws {
        let prekeys = [
            Prekey(id: "A", contactID: "c", sequence: 1, publicKey: Data(count: 65)),
            Prekey(id: "B", contactID: "c", sequence: 1, publicKey: Data(count: 65))
        ]
        let batch   = OccultaBundle.PrekeySyncBatch(sequence: 1, prekeys: prekeys)
        let decoded = try OccultaBundle.decoded(from: makeBundle(prekeyBatch: batch).encoded())
        XCTAssertEqual(decoded.secrecy.prekeyBatch?.sequence,         1)
        XCTAssertEqual(decoded.secrecy.prekeyBatch?.prekeys.count,    2)
        XCTAssertEqual(decoded.secrecy.prekeyBatch?.prekeys[0].id,    "A")
        XCTAssertEqual(decoded.secrecy.prekeyBatch?.prekeys[1].id,    "B")
    }

    func test_decodeMalformedData_throws() {
        XCTAssertThrowsError(try OccultaBundle.decoded(from: Data("not json".utf8)))
    }

    // MARK: - fullAAD

    func test_fullAAD_includesVersion() throws {
        let bundle     = makeBundle(version: .v3fs)
        let aad        = try bundle.fullAAD()
        let versionTag = "v3fs".data(using: .utf8)!
        XCTAssertTrue(aad.starts(with: versionTag), "AAD must begin with version raw value")
    }

    func test_fullAAD_differentVersionProducesDifferentAAD() throws {
        let b1 = makeBundle(version: .v3fs)
        let b2 = makeBundle(version: .v1)
        XCTAssertNotEqual(try b1.fullAAD(), try b2.fullAAD(),
                          "Different versions must produce different AAD")
    }

    func test_fullAAD_deterministicAcrossCalls() throws {
        let bundle = makeBundle()
        XCTAssertEqual(try bundle.fullAAD(), try bundle.fullAAD(),
                       "fullAAD must be deterministic for the same bundle")
    }

    func test_fullAAD_sealAndOpenProduceSameBytes() throws {
        // The seal-side AAD is computed by Crypto+ForwardSecrecy.computeAAD.
        // The open-side AAD is computed by bundle.fullAAD().
        // This test verifies they produce identical bytes for the same inputs.
        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .forwardSecret,
            ephemeralPublicKey: Data(count: 65),
            prekeyID:           "test-id",
            prekeySequence:     2,
            prekeyBatch:        nil
        )
        let bundle = OccultaBundle(
            version:           .v3fs,
            secrecy:           secrecy,
            ciphertext:        Data(count: 28),
            fingerprintNonce:  Data(count: 16),
            senderFingerprint: Data(count: 32)
        )
        let sealAAD = try Manager.Crypto.computeAAD(version: .v3fs, secrecy: secrecy)
        let openAAD = try bundle.fullAAD()
        XCTAssertEqual(sealAAD, openAAD,
                       "Seal and open AAD must be byte-identical for the same inputs")
    }

    // MARK: - Fingerprint math

    func test_fingerprint_isSHA256OfPublicKeyPlusNonce() {
        let key   = Data(repeating: 0x42, count: 65)
        let nonce = Data(repeating: 0x11, count: 16)
        var input = key; input.append(nonce)
        XCTAssertEqual(
            OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: nonce),
            Data(SHA256.hash(data: input))
        )
    }

    func test_fingerprint_differentNonce_producesDifferentResult() {
        let key = Data(repeating: 0x42, count: 65)
        XCTAssertNotEqual(
            OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: Data(repeating: 0x01, count: 16)),
            OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: Data(repeating: 0x02, count: 16))
        )
    }

    func test_fingerprint_differentKey_producesDifferentResult() {
        let nonce = Data(repeating: 0x99, count: 16)
        XCTAssertNotEqual(
            OccultaBundle.SecrecyContext.fingerprint(for: Data(repeating: 0x01, count: 65), nonce: nonce),
            OccultaBundle.SecrecyContext.fingerprint(for: Data(repeating: 0x02, count: 65), nonce: nonce)
        )
    }

    func test_fingerprint_is32Bytes() {
        XCTAssertEqual(
            OccultaBundle.SecrecyContext.fingerprint(for: Data(count: 65), nonce: Data(count: 16)).count,
            32
        )
    }

    // MARK: - generateNonce

    func test_generateNonce_is16Bytes() throws {
        XCTAssertEqual(try OccultaBundle.SecrecyContext.generateNonce().count, 16)
    }

    func test_generateNonce_isRandomEachCall() throws {
        let n1 = try OccultaBundle.SecrecyContext.generateNonce()
        let n2 = try OccultaBundle.SecrecyContext.generateNonce()
        XCTAssertNotEqual(n1, n2, "Consecutive nonces must not be equal")
    }

    func test_generateNonce_isNonZero() throws {
        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        XCTAssertFalse(nonce.allSatisfy { $0 == 0 }, "Nonce must not be all-zero bytes")
    }

    // MARK: - PrekeySyncBatch

    func test_prekeySyncBatch_encodeDecode() throws {
        let batch  = OccultaBundle.PrekeySyncBatch(
            sequence: 5,
            prekeys: [Prekey(id: "X", contactID: "c", sequence: 5, publicKey: Data(count: 65))]
        )
        let data    = try JSONEncoder().encode(batch)
        let decoded = try JSONDecoder().decode(OccultaBundle.PrekeySyncBatch.self, from: data)
        XCTAssertEqual(decoded.sequence,            5)
        XCTAssertEqual(decoded.prekeys.count,       1)
        XCTAssertEqual(decoded.prekeys[0].id,       "X")
        XCTAssertEqual(decoded.prekeys[0].sequence, 5)
    }
}
