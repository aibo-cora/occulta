//
//  ReadmeExamplesTests.swift
//  OccultaCoreAPITests
//
//  The code in `OccultaCore/README.md`, line for line where it can be, through the public API only
//  (a plain `import`, no `@testable`). If an example stops compiling or stops doing what the README
//  says, this is where it shows. Change one, change the other.
//

import Testing
import Foundation
import CryptoKit
import OccultaCore

// MARK: - Shamir

@Suite("README — Shamir")
struct ReadmeShamirTests {

    @Test("Split a 32-byte secret 2-of-3 and recover it from any two shares, checked against a digest")
    func splitAndReconstruct() throws {
        let secret = Data((0..<32).map { UInt8($0) })
        let expectedDigest = SHA256.hash(data: secret)      // kept alongside the shares, or derived from your own data

        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 3)

        // Any two shares will do. A bad share among those passed would be searched past.
        var recovered = try ShamirSecretSharing.reconstruct(shares: [shares[0], shares[2]]) { candidate in
            SHA256.hash(data: candidate) == expectedDigest
        }
        #expect(recovered == secret)
        recovered.resetBytes(in: recovered.indices)         // the caller zeroes what it was handed
    }
}

// MARK: - Post-quantum provider and key check

/// The README's example, with the provider passed in so the test can use the in-memory one.
private func readmePostQuantumExample(provider: PostQuantumProvider) -> Bool {
    // Bob makes a key pair. The private key is a Secure Enclave key; `keyBlob` is its
    // `dataRepresentation`, usable only on this device. He stores the blob, sends the public key.
    guard let bob = provider.generatePersistentKeyPair() else { return false }

    // Alice refuses a malformed key where it arrives, then encapsulates to it. She keeps
    // `sharedSecret` and sends `ciphertext`.
    guard
        MLKEMKeyCheck.isValidEncapsulationKey1024(bob.publicKeyData),
        let sent = provider.encapsulate(peerPublicKeyData: bob.publicKeyData)
    else { return false }

    // Bob decapsulates. Both sides now hold the same 32 bytes.
    let received = provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: bob.keyBlob)
    return received == sent.sharedSecret
}

@Suite("README — post-quantum provider and key check")
struct ReadmePostQuantumTests {

    @Test("The factory answers without throwing on any OS, and the key check refuses a malformed key")
    func factoryAndCheck() {
        let _: PostQuantumProvider? = PostQuantumProviderFactory.create()    // nil below iOS 26
        #expect(!MLKEMKeyCheck.isValidEncapsulationKey1024(Data(repeating: 0xFF, count: 1_568)))
    }

    #if DEBUG
    @Test("Bob's key pair, Alice's encapsulation and Bob's decapsulation agree",
          .enabled(if: ProcessInfo.processInfo.isOperatingSystemAtLeast(OperatingSystemVersion(majorVersion: 26, minorVersion: 0, patchVersion: 0))))
    func roundTrip() throws {
        #expect(readmePostQuantumExample(provider: try #require(PostQuantumProviderFactory.createForTesting())))
    }
    #endif
}

// MARK: - Transport key derivation

/// What the host app keeps per peer. `postQuantumSecrets` is set when the peer is added, from the
/// ML-KEM exchange the app ran with them, and read from here on every message. It is never read from
/// a message: a flag the sender controls lets whoever can alter the message turn the hybrid form off.
private struct ReadmePeer {
    var publicKey: Data                                 // x963 P-256, 65 bytes
    var postQuantumSecrets: (Data, Data)?               // nil: this peer is classical-only
}

private enum ReadmeTransportError: Error { case badKeyMaterial, malformed }

/// One label per purpose, chosen by the host app. The version is part of it.
private let readmeLabel = Data("com.example.myapp.message.v1".utf8)

private func readmeSessionKey(
    own: P256.KeyAgreement.PrivateKey, peer: ReadmePeer
) throws -> SymmetricKey {
    // The ECDH output is the X9.63 KDF's, SHA-256, no shared info, 32 bytes.
    let ecdhOutput = try own
        .sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer.publicKey))
        .x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
        .withUnsafeBytes { Data($0) }

    guard let key = TransportKeyDerivation.sessionKey(
        ecdhOutput: ecdhOutput,
        ownPublicKey: own.publicKey.x963Representation,
        peerPublicKey: peer.publicKey,
        postQuantumSecrets: peer.postQuantumSecrets,
        info: readmeLabel
    ) else { throw ReadmeTransportError.badKeyMaterial }
    return key
}

/// `header` is whatever else the receiver acts on (a message ID, the sender, a timestamp). It travels
/// in the clear and the tag covers it.
private func readmeSeal(
    _ plaintext: Data, header: Data, from own: P256.KeyAgreement.PrivateKey, to peer: ReadmePeer
) throws -> Data {
    let key = try readmeSessionKey(own: own, peer: peer)
    guard let combined = try AES.GCM.seal(plaintext, using: key, authenticating: header).combined
    else { throw ReadmeTransportError.malformed }
    return combined
}

private func readmeOpen(
    _ combined: Data, header: Data, as own: P256.KeyAgreement.PrivateKey, from peer: ReadmePeer
) throws -> Data {
    let key = try readmeSessionKey(own: own, peer: peer)
    return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key, authenticating: header)
}

@Suite("README — transport key derivation")
struct ReadmeTransportTests {

    private let alice = P256.KeyAgreement.PrivateKey()
    private let bob = P256.KeyAgreement.PrivateKey()
    private let secrets = (Data(repeating: 0xa5, count: 32), Data(repeating: 0x5a, count: 32))
    private let header = Data("message-id: 7".utf8)
    private let message = Data("hello".utf8)

    @Test("A hybrid peer: Bob opens what Alice sealed, holding the two secrets in the other order")
    func hybridRoundTrip() throws {
        let bobAsAlicePeer = ReadmePeer(publicKey: self.bob.publicKey.x963Representation, postQuantumSecrets: self.secrets)
        let aliceAsBobPeer = ReadmePeer(publicKey: self.alice.publicKey.x963Representation,
                                        postQuantumSecrets: (self.secrets.1, self.secrets.0))

        let sealed = try readmeSeal(self.message, header: self.header, from: self.alice, to: bobAsAlicePeer)
        #expect(try readmeOpen(sealed, header: self.header, as: self.bob, from: aliceAsBobPeer) == self.message)
    }

    @Test("A classical peer round-trips, and a receiver pinned to the other mode cannot open it")
    func classicalRoundTripAndPinnedMode() throws {
        let classical = ReadmePeer(publicKey: self.bob.publicKey.x963Representation, postQuantumSecrets: nil)
        let sealed = try readmeSeal(self.message, header: self.header, from: self.alice, to: classical)

        let aliceClassical = ReadmePeer(publicKey: self.alice.publicKey.x963Representation, postQuantumSecrets: nil)
        #expect(try readmeOpen(sealed, header: self.header, as: self.bob, from: aliceClassical) == self.message)

        let aliceHybrid = ReadmePeer(publicKey: self.alice.publicKey.x963Representation, postQuantumSecrets: self.secrets)
        #expect(throws: CryptoKitError.self) {
            try readmeOpen(sealed, header: self.header, as: self.bob, from: aliceHybrid)
        }
    }

    @Test("Changing the header makes the open fail")
    func tamperedHeaderFails() throws {
        let bobAsAlicePeer = ReadmePeer(publicKey: self.bob.publicKey.x963Representation, postQuantumSecrets: self.secrets)
        let aliceAsBobPeer = ReadmePeer(publicKey: self.alice.publicKey.x963Representation, postQuantumSecrets: self.secrets)

        let sealed = try readmeSeal(self.message, header: self.header, from: self.alice, to: bobAsAlicePeer)
        #expect(throws: CryptoKitError.self) {
            try readmeOpen(sealed, header: Data("message-id: 8".utf8), as: self.bob, from: aliceAsBobPeer)
        }
    }

    @Test("A public key that is not 65 bytes is refused rather than repaired")
    func malformedPeerKeyIsRefused() {
        #expect(TransportKeyDerivation.sessionKey(
            ecdhOutput: Data(repeating: 0x9a, count: 32),
            ownPublicKey: self.alice.publicKey.x963Representation,
            peerPublicKey: Data(self.bob.publicKey.x963Representation.dropFirst()),   // 64 bytes: the 0x04 prefix gone
            postQuantumSecrets: nil,
            info: readmeLabel
        ) == nil)
    }
}
