//
//  WireHandleLengthTests.swift
//  OccultaTests
//
//  Simulator safe — no Secure Enclave, no SwiftData.
//  Bug 174: a length field read off the wire as a UInt64 went through `Int(_:)` and then into
//  `offset + count`. From 2^63 up the conversion traps; just under Int.max the addition does.
//  A trap is not a throw, so no `try?` upstream could catch it and a 167-byte file killed the
//  app before anything was authenticated. These tests pass only if the parser throws.
//

import Testing
import Foundation

@testable import Occulta
@testable import OccultaFormats

@Suite("WireHandle — hostile length fields")
struct WireHandleLengthTests {

    /// The last three trapped; 1000 is representable but larger than the file.
    private static let hostileLengths: [UInt64] = [
        1000,
        UInt64(Int.max),
        1 << 63,
        UInt64.max,
    ]

    private func be64(_ v: UInt64) -> Data {
        Data((0..<8).map { UInt8((v >> (56 - 8 * UInt64($0))) & 0xFF) })
    }

    private func be32(_ v: UInt32) -> Data {
        Data((0..<4).map { UInt8((v >> (24 - 8 * UInt32($0))) & 0xFF) })
    }

    /// The 159-byte outer header, then the 8 length bytes: 167 bytes in all.
    private func outerEnvelope(ctLen: UInt64) -> Data {
        var d = Data(WireHandle.magic)
        d.append(contentsOf: [0x04, 0x04, 0x01, 0x00, 0x00, 0x00])  // version, minReader, mode, flags(2), hasPrekey
        d.append(Data(count: 36 + 65 + 16 + 32))                    // prekeyID, ephemeral, nonce, fingerprint
        d.append(self.be64(ctLen))
        return d
    }

    // MARK: - Outer envelope

    @Test(arguments: WireHandleLengthTests.hostileLengths)
    func outerEnvelope_oversizedCiphertextLengthThrows(ctLen: UInt64) {
        let file = self.outerEnvelope(ctLen: ctLen)
        #expect(file.count == 167)

        #expect(throws: OccultaBundle.BundleError.self) {
            _ = try OccultaBundle.decoded(from: file)
        }
    }

    @Test func outerEnvelope_lengthEqualToRemainingBytesStillParses() throws {
        let ciphertext = Data(repeating: 0xAB, count: 40)
        let file = self.outerEnvelope(ctLen: UInt64(ciphertext.count)) + ciphertext

        let parsed = try WireHandle.parse(file)

        #expect(parsed.ciphertext == ciphertext)
    }

    @Test func outerEnvelope_lengthOneMoreThanRemainingThrows() {
        let file = self.outerEnvelope(ctLen: 41) + Data(repeating: 0xAB, count: 40)

        #expect(throws: OccultaBundle.BundleError.self) {
            _ = try WireHandle.parse(file)
        }
    }

    // MARK: - Payload

    @Test(arguments: WireHandleLengthTests.hostileLengths)
    func payload_oversizedMessageLengthThrows(msgLen: UInt64) {
        let metaJSON = Data("{}".utf8)
        let bytes = self.be32(UInt32(metaJSON.count)) + metaJSON + self.be64(msgLen)

        #expect(throws: OccultaBundle.BundleError.self) {
            _ = try WireHandle.decode(payload: bytes)
        }
    }

    @Test func payload_roundTripStillWorks() throws {
        let message = Data("hello".utf8)
        let encoded = try WireHandle.encode(payload: OccultaBundle.SealedPayload(message: message, prekeyBatch: nil))

        let decoded = try WireHandle.decode(payload: encoded)

        #expect(decoded.message == message)
    }

    // MARK: - Basket

    @Test(arguments: WireHandleLengthTests.hostileLengths)
    func basket_oversizedFileContentLengthThrows(contentLen: UInt64) {
        let basketMeta = Data("{\"id\":\"\(UUID().uuidString)\"}".utf8)
        let fileMeta   = Data("{\"id\":\"\(UUID().uuidString)\"}".utf8)
        let bytes = self.be32(UInt32(basketMeta.count)) + basketMeta
                  + self.be32(1)
                  + self.be32(UInt32(fileMeta.count)) + fileMeta
                  + self.be64(contentLen)

        #expect(throws: OccultaBundle.BundleError.self) {
            _ = try WireHandle.decode(basket: bytes)
        }
    }

    @Test func basket_roundTripStillWorks() throws {
        let content = Data("round trip".utf8)
        let encoded = try WireHandle.encode(basket: Basket(files: [
            OccultaFormats.File(content: content, format: .text, date: Date())
        ]))

        let decoded = try WireHandle.decode(basket: encoded)

        #expect(decoded.files.count == 1)
        #expect(decoded.files.first?.content == content)
    }
}
