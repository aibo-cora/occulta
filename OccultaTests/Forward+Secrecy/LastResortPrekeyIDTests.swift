//
//  LastResortPrekeyIDTests.swift
//  OccultaTests
//
//  The cleartext prekey ID of a bundle sealed to a last-resort key (prekey continuity §3.1, stage 2):
//  HMAC-SHA256(the key's ID as UUID bytes, the ephemeral public key), truncated to a version-4 UUID. Both sides
//  compute it, so its bytes are pinned by a known answer computed independently (Python's hmac and uuid).
//

import Testing
import Foundation
@testable import OccultaFormats

@Suite("Last-resort prekey ID")
struct LastResortPrekeyIDTests {

    let keyID = "D1D2D3D4-0000-4000-8000-000000000001"
    let ephemeral = Data([0x04] + Array(repeating: 0x11, count: 32) + Array(repeating: 0x22, count: 32))

    private func randomEphemeral() -> Data {
        Data([0x04] + (0..<64).map { _ in UInt8.random(in: .min ... .max) })
    }

    @Test("Matches the known answer")
    func knownAnswer() {
        #expect(OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: self.keyID, ephemeralPublicKey: self.ephemeral)
                == "6EBC19E2-D5A8-4418-A051-6F72E2EF4335")
    }

    /// Indistinguishable in form from a one-time key's ID, which is `UUID().uuidString`.
    @Test("Is a version-4 UUID string, formatted as a one-time key's ID is")
    func looksLikeAOneTimeID() throws {
        for _ in 0..<50 {
            let id = try #require(OccultaBundle.SecrecyContext.lastResortPrekeyID(
                keyID: self.keyID, ephemeralPublicKey: self.randomEphemeral()
            ))
            let uuid = try #require(UUID(uuidString: id))
            #expect(id == uuid.uuidString)
            #expect(uuid.uuid.6 >> 4 == 4, "version 4")
            #expect(uuid.uuid.8 >> 6 == 0b10, "RFC 4122 variant")
        }
    }

    /// The key's own ID is its secret: it must never be what a bundle carries, and two bundles must never share one.
    @Test("Differs on every send and never equals the key's own ID")
    func unlinkable() throws {
        let ids = try (0..<200).map { _ in
            try #require(OccultaBundle.SecrecyContext.lastResortPrekeyID(
                keyID: self.keyID, ephemeralPublicKey: self.randomEphemeral()
            ))
        }
        #expect(Set(ids).count == ids.count)
        #expect(!ids.contains(self.keyID))
    }

    @Test("Depends on the key: another key's ID gives another prekey ID for the same ephemeral key")
    func keyedByTheKeyID() {
        let other = "D1D2D3D4-0000-4000-8000-000000000002"
        #expect(OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: self.keyID, ephemeralPublicKey: self.ephemeral)
                != OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: other, ephemeralPublicKey: self.ephemeral))
    }

    @Test("A key ID that isn't a UUID gives none")
    func nonUUIDKeyID() {
        #expect(OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: "prekey-1", ephemeralPublicKey: self.ephemeral) == nil)
    }
}
