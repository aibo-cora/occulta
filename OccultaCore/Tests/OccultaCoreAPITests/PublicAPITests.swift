//
//  PublicAPITests.swift
//  OccultaCoreAPITests
//
//  Uses OccultaCore the way another app would: a plain `import`, no `@testable`, and no
//  dependency on OccultaFormats. If something the API needs stops being public, or something
//  app-only becomes reachable through it, this target is where it shows.
//

import Testing
import Foundation
import OccultaCore

@Suite("OccultaCore public API — Shamir")
struct ShamirPublicAPITests {

    private let secret = Data((0..<32).map { UInt8($0) })

    @Test("Any threshold-sized subset of the shares reconstructs the secret")
    func roundTrip() throws {
        let shares = try ShamirSecretSharing.split(secret: self.secret, threshold: 2, shares: 3)

        #expect(shares.count == 3)
        for subset in [[shares[0], shares[1]], [shares[1], shares[2]], shares] {
            #expect(try ShamirSecretSharing.reconstruct(shares: subset) { $0 == self.secret } == self.secret)
        }
    }

    @Test("Invalid input is reported through the public error cases")
    func publicErrors() throws {
        #expect(throws: ShamirSecretSharing.Error.invalidParameters) {
            try ShamirSecretSharing.split(secret: self.secret, threshold: 1, shares: 3)
        }
        #expect(throws: ShamirSecretSharing.Error.invalidSecretLength) {
            try ShamirSecretSharing.split(secret: Data(count: 16), threshold: 2, shares: 3)
        }
        let shares = try ShamirSecretSharing.split(secret: self.secret, threshold: 2, shares: 3)
        #expect(throws: ShamirSecretSharing.Error.insufficientShares) {
            try ShamirSecretSharing.reconstruct(shares: [shares[0]]) { _ in true }
        }
        #expect(throws: ShamirSecretSharing.Error.invalidParameters) {
            try ShamirSecretSharing.reconstruct(shares: shares, maxAttempts: 0) { _ in true }
        }
        #expect(throws: ShamirSecretSharing.Error.noVerifiedSubset) {
            try ShamirSecretSharing.reconstruct(shares: shares) { _ in false }
        }
    }
}

@Suite("OccultaCore public API — post-quantum provider")
struct PostQuantumProviderPublicAPITests {

    @Test("Encapsulating to a public key and decapsulating with its handle agree on the secret",
          .enabled(if: ProcessInfo.processInfo.isOperatingSystemAtLeast(OperatingSystemVersion(majorVersion: 26, minorVersion: 0, patchVersion: 0))))
    func roundTrip() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let keyPair = try #require(provider.generateKeyPair())

        let sent = try #require(provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData))
        let received = provider.decapsulate(ciphertext: sent.ciphertext, privateKeyHandle: keyPair.privateKeyHandle)

        #expect(sent.sharedSecret.count == 32)
        #expect(received == sent.sharedSecret)
    }
}
