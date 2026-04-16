//
//  IdentityChallengeSigningTests.swift
//  OccultaTests
//
//  Simulator safe — uses TestKeyManager (in-memory P-256, no SE).
//

import Testing
import Foundation
import Security
@testable import Occulta

// MARK: - Fixtures

@MainActor
private func freshCrypto() -> (crypto: Manager.Crypto, km: TestKeyManager) {
    let km = TestKeyManager()
    return (Manager.Crypto(keyManager: km), km)
}

private func samplePieces() -> (nonce: Data, timestamp: Data, fingerprint: Data) {
    let nonce       = Data(repeating: 0xAB, count: 32)
    let timestamp   = IdentityChallenge.encodeTimestamp(1_700_000_000)
    let fingerprint = Data(repeating: 0xCD, count: 32)
    return (nonce, timestamp, fingerprint)
}

private func makePublicKey(from x963: Data) -> SecKey {
    let attrs: [String: Any] = [
        kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256
    ]
    var err: Unmanaged<CFError>?
    return SecKeyCreateWithData(x963 as CFData, attrs as CFDictionary, &err)!
}

// MARK: - buildSignedData layout

@Suite("IdentityChallenge — buildSignedData")
struct BuildSignedDataTests {

    @Test func deterministic_sameInputs_sameOutput() {
        let (n, t, fp) = samplePieces()
        let a = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        let b = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        #expect(a == b)
    }

    @Test func startsWithDomainPrefixBytes() {
        let (n, t, fp) = samplePieces()
        let signed     = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        let prefix     = Data(IdentityChallenge.domainPrefix.utf8)
        #expect(signed.prefix(prefix.count) == prefix)
    }

    @Test func totalLength_isPrefixPlusFields() {
        let (n, t, fp) = samplePieces()
        let signed     = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        let prefixLen  = IdentityChallenge.domainPrefix.utf8.count
        #expect(signed.count == prefixLen + 32 + 8 + 32)
    }

    @Test func differentNonce_producesDifferentBytes() {
        let (_, t, fp) = samplePieces()
        let a = Manager.Crypto.buildSignedData(nonce: Data(repeating: 0x01, count: 32), timestamp: t, challengerFingerprint: fp)
        let b = Manager.Crypto.buildSignedData(nonce: Data(repeating: 0x02, count: 32), timestamp: t, challengerFingerprint: fp)
        #expect(a != b)
    }

    @Test func differentTimestamp_producesDifferentBytes() {
        let (n, _, fp) = samplePieces()
        let a = Manager.Crypto.buildSignedData(nonce: n, timestamp: IdentityChallenge.encodeTimestamp(1), challengerFingerprint: fp)
        let b = Manager.Crypto.buildSignedData(nonce: n, timestamp: IdentityChallenge.encodeTimestamp(2), challengerFingerprint: fp)
        #expect(a != b)
    }

    @Test func differentFingerprint_producesDifferentBytes() {
        let (n, t, _) = samplePieces()
        let a = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: Data(repeating: 0xAA, count: 32))
        let b = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: Data(repeating: 0xBB, count: 32))
        #expect(a != b)
    }
}

// MARK: - Sign + verify roundtrip

@Suite("IdentityChallenge — sign + verify")
@MainActor struct SignVerifyTests {

    @Test func signAndVerify_succeeds() throws {
        let (crypto, km)  = freshCrypto()
        let (n, t, fp)    = samplePieces()
        let signedData    = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)

        let signature     = try crypto.signChallenge(signedData)
        let publicKeyData = try km.retrieveIdentity()
        let publicKey     = makePublicKey(from: publicKeyData)

        #expect(crypto.verifyChallenge(signedData, signature: signature, publicKey: publicKey))
    }

    @Test func verifyWithWrongPublicKey_fails() throws {
        let (crypto, _)   = freshCrypto()
        let (otherCrypto, otherKM) = freshCrypto()
        _ = otherCrypto

        let (n, t, fp) = samplePieces()
        let signedData = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)

        let signature = try crypto.signChallenge(signedData)
        let wrongKey  = makePublicKey(from: try otherKM.retrieveIdentity())

        #expect(!crypto.verifyChallenge(signedData, signature: signature, publicKey: wrongKey))
    }

    @Test func verifyWithTamperedSignedData_fails() throws {
        let (crypto, km)  = freshCrypto()
        let (n, t, fp)    = samplePieces()
        let signedData    = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        let signature     = try crypto.signChallenge(signedData)
        let publicKey     = makePublicKey(from: try km.retrieveIdentity())

        // Flip one bit anywhere in signedData → verify must fail.
        var tampered = signedData
        tampered[tampered.count - 1] ^= 0x01
        #expect(!crypto.verifyChallenge(tampered, signature: signature, publicKey: publicKey))
    }

    @Test func verifyWithTamperedSignature_fails() throws {
        let (crypto, km)  = freshCrypto()
        let (n, t, fp)    = samplePieces()
        let signedData    = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        var signature     = try crypto.signChallenge(signedData)
        let publicKey     = makePublicKey(from: try km.retrieveIdentity())

        // Flip one byte in the signature.
        signature[signature.count - 1] ^= 0xFF
        #expect(!crypto.verifyChallenge(signedData, signature: signature, publicKey: publicKey))
    }

    @Test func verifyWithEmptySignature_fails() throws {
        let (crypto, km)  = freshCrypto()
        let (n, t, fp)    = samplePieces()
        let signedData    = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        let publicKey     = makePublicKey(from: try km.retrieveIdentity())

        #expect(!crypto.verifyChallenge(signedData, signature: Data(), publicKey: publicKey))
    }

    // MARK: - Domain separation

    @Test func domainSeparation_signedWithChallengePrefix_doesNotVerifyWithDifferentPrefix() throws {
        let (crypto, km)  = freshCrypto()
        let (n, t, fp)    = samplePieces()
        let publicKey     = makePublicKey(from: try km.retrieveIdentity())

        // Sign a payload with the production challenge prefix.
        let realSignedData = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        let signature      = try crypto.signChallenge(realSignedData)

        // Construct an alternative payload with a *different* prefix
        // (simulating a future Document Signing feature).
        var fakeSignedData = Data("occulta-document-signing-v1".utf8)
        fakeSignedData.append(n)
        fakeSignedData.append(t)
        fakeSignedData.append(fp)

        // The signature must NOT verify against the alternative prefix.
        // This is the cross-protocol-reuse defence.
        #expect(!crypto.verifyChallenge(fakeSignedData, signature: signature, publicKey: publicKey))
    }

    // MARK: - Stability

    @Test func multipleSignatures_allVerify() throws {
        let (crypto, km)  = freshCrypto()
        let (n, t, fp)    = samplePieces()
        let signedData    = Manager.Crypto.buildSignedData(nonce: n, timestamp: t, challengerFingerprint: fp)
        let publicKey     = makePublicKey(from: try km.retrieveIdentity())

        // ECDSA is randomised — same input produces different signatures, all valid.
        let s1 = try crypto.signChallenge(signedData)
        let s2 = try crypto.signChallenge(signedData)

        #expect(crypto.verifyChallenge(signedData, signature: s1, publicKey: publicKey))
        #expect(crypto.verifyChallenge(signedData, signature: s2, publicKey: publicKey))
    }
}
