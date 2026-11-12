# OccultaCore

Cryptographic primitives extracted from [Occulta](../README.md), an offline-first iOS contact book,
so another app can use them. CryptoKit and Security.framework only: no package dependency, and
never `apple/swift-crypto`.

> ## License: AGPL-3.0
>
> This package is part of Occulta and is licensed under the **GNU Affero General Public License
> v3.0** (see [`../LICENSE`](../LICENSE)). Any app that links `OccultaCore` must itself be
> released under AGPL-3.0, and you must publish its complete source to its users, including users
> who reach it over a network.
>
> **That rules out the App Store for a closed-source app,** and the AGPL's terms are generally held
> to clash with the App Store's even for an open-source one. If you cannot ship your app under
> AGPL-3.0, do not link this package: closed-source and App Store adopters are ruled out.

## What is in it

The package has two library products. Only the first is for you.

| Product | For | Contents |
|---|---|---|
| `OccultaCore` | Any app | `ShamirSecretSharing`, `PostQuantumProvider` (with `PostQuantumProviderFactory`), `MLKEMKeyCheck`, `TransportKeyDerivation` |
| `OccultaFormats` | Occulta only | Occulta's wire and at-rest formats. They carry Occulta-identifying constants (the `OCCB` magic, the `occulta-signed-attribute-v2` prefix), so an app using them would put Occulta's name in every message it sends. Don't link it. |

`OccultaCore` doesn't reach `OccultaFormats`; the dependency runs the other way.

You choose your own HKDF labels and key tags. Nothing in `OccultaCore` is named for Occulta, and
Occulta's own labels are wire format that never changes, so a host app has no reason to know them.
Your app will not interoperate with Occulta, and this package doesn't try to make it.

## Requirements

- iOS 18.6 or later. The package declares no other platform.
- Swift 6.2 tools. The package builds in Swift 6 mode, nonisolated by default (unlike Occulta
  itself, which is `MainActor` by default), so the primitives are callable from any actor.
- ML-KEM-1024 needs **iOS 26**. `PostQuantumProviderFactory.create()` returns `nil` below it, and
  your app then runs classical-only. Everything else works from 18.6.

## Adding it

It is a local package in the Occulta repository. It is not published and has no version tags. Copy
the `OccultaCore/` directory into your source tree, then add it in Xcode with File > Add Package
Dependencies > Add Local, or in `Package.swift`:

```swift
dependencies: [.package(path: "../OccultaCore")],
targets: [.target(name: "MyApp", dependencies: [.product(name: "OccultaCore", package: "OccultaCore")])]
```

Link only the `OccultaCore` product. The directory has no resources, so nothing but compiled code
reaches your bundle.

## Shamir secret sharing

`ShamirSecretSharing` splits a **32-byte** secret into `n` shares of 33 bytes, any `k` of which
rebuild it (`2 <= k <= n <= 255`), over GF(2^8).

There is no unchecked reconstruction in the public API, because interpolation can't tell a bad
share from a good one: it returns a wrong 32 bytes without throwing. `reconstruct(shares:maxAttempts:isCorrect:)`
instead tries all the shares, then subsets with shares left out, fewest first, and returns the first
secret your `isCorrect` accepts. It throws `noVerifiedSubset` if none passes within `maxAttempts`
(default 1,024).

```swift
import CryptoKit
import OccultaCore

let secret = Data((0..<32).map { UInt8($0) })
let expectedDigest = SHA256.hash(data: secret)      // kept alongside the shares, or derived from your own data

let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 3)

// Any two shares will do. A bad share among those passed would be searched past.
var recovered = try ShamirSecretSharing.reconstruct(shares: [shares[0], shares[2]]) { candidate in
    SHA256.hash(data: candidate) == expectedDigest
}
recovered.resetBytes(in: recovered.indices)         // the caller zeroes what it was handed
```

The result is only as good as `isCorrect`:

- It must be a check that someone holding one share can't satisfy. A hash or MAC of the secret, or
  opening an AES-GCM box you made yourself, qualifies.
- AES-GCM is **not key-committing**. A check built on a GCM tag over ciphertext an attacker supplied
  can be satisfied by ciphertext crafted to open under two keys. Where the ciphertext isn't yours,
  check a hash or MAC of the secret instead.
- It must not keep `candidate`. Rejected candidates are zeroed as soon as the check returns, and a
  copy the check made is out of reach of that.

Zero `secret` after `split`, and the reconstructed value after use.

## Post-quantum key encapsulation

`PostQuantumProvider` wraps ML-KEM-1024. Production keys are Secure Enclave keys: the private key
never exists in app memory. `generatePersistentKeyPair()` returns the public key and a `keyBlob`, the
Enclave key's `dataRepresentation`, which only this device's Enclave can use; you store it, and
deleting it deletes the key. (`generateKeyPair()` is the same with a handle that lives only as long
as the process.)

`MLKEMKeyCheck.isValidEncapsulationKey1024` is the FIPS 203 modulus check. CryptoKit's
`MLKEM1024.PublicKey(rawRepresentation:)` checks only the length, so a random 1,568-byte string
"parses" and fails later at `encapsulate()`. **Run the check on a peer's key where it arrives**
(a scan, a received message, an import), before you store it. `encapsulate` doesn't do it for you.

```swift
import OccultaCore

guard let provider = PostQuantumProviderFactory.create() else {
    return   // below iOS 26: run classical-only
}

// Bob makes a key pair. `keyBlob` is the Secure Enclave key's dataRepresentation, usable only on
// this device. He stores the blob and sends the public key.
guard let bob = provider.generatePersistentKeyPair() else { return }

// Alice refuses a malformed key where it arrives, then encapsulates to it. She keeps
// `sharedSecret` and sends `ciphertext`.
guard
    MLKEMKeyCheck.isValidEncapsulationKey1024(bob.publicKeyData),
    let sent = provider.encapsulate(peerPublicKeyData: bob.publicKeyData)
else { return }

// Bob decapsulates. Both sides now hold the same 32 bytes.
let received = provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: bob.keyBlob)
assert(received == sent.sharedSecret)
```

`PostQuantumProviderFactory.createForTesting()` returns an in-memory provider for your tests. It
exists only in Debug builds (`#if DEBUG`), because its private keys live in app memory; a Release
build can't reach it. Its `keyBlob` **is** the private key.

## Transport key derivation

`TransportKeyDerivation.sessionKey(ecdhOutput:ownPublicKey:peerPublicKey:postQuantumSecrets:info:)`
derives one 256-bit key with HKDF-SHA256:

```
IKM  = ecdhOutput                               (classical)
     = ecdhOutput || sorted(secret1, secret2)   (hybrid: lexicographic order)
Salt = ownPublicKey XOR peerPublicKey
key  = HKDF-SHA256(IKM, Salt, info, 32 bytes)
```

- `ecdhOutput` is 32 bytes you computed with your own private key, wherever it lives: the X9.63 KDF
  output of the exchange, with SHA-256 and no shared info (`SecKeyCopyKeyExchangeResult` with
  `.ecdhKeyExchangeCofactorX963SHA256` and size 32, or CryptoKit's `x963DerivedSymmetricKey`). No
  private key reaches this function. It must be exactly 32 bytes.
- `ownPublicKey` and `peerPublicKey` are x963 P-256 keys, 65 bytes. Each side passes its own as
  `ownPublicKey`; both then derive the same key.
- `postQuantumSecrets` is two 32-byte ML-KEM shared secrets, in either order, or `nil` for the
  classical form.
- `info` is **your** label, one per purpose, with your version in it. It is the only domain
  separation the function has. Occulta's labels are not for you.
- It throws `TransportKeyDerivation.Error` for input of the wrong size, and the case says which:
  `invalidOwnPublicKeyLength`, `invalidPeerPublicKeyLength` (not 65 bytes), `invalidECDHOutputLength`
  (not 32) or `invalidPostQuantumSecretLength` (either secret not 32). It checks in that order and
  reports the first that fails. The cases carry no data.

**Pin the post-quantum mode per peer. Do not infer it from a message.** Store, when you add a
peer, whether you hold ML-KEM secrets for them, and pass `postQuantumSecrets` from that record on
every message. If the mode were read from the message (a flag, a version byte, a length), whoever
can alter the message could switch the hybrid form off. A message that doesn't match the pinned mode
then simply fails to open. The function can't tell the two apart for you, and the keys differ
between the forms.

The function derives a key and does no more. **Seal and open are your own AES-GCM call**, and the
header goes into it as authenticated data, so the tag covers everything the receiver acts on:

```swift
import CryptoKit
import OccultaCore

/// What your app keeps per peer.
struct Peer {
    var publicKey: Data                          // x963 P-256, 65 bytes
    var postQuantumSecrets: (Data, Data)?        // set when the peer was added; nil: classical-only
}

enum TransportError: Error { case malformed }

/// One label per purpose, chosen by your app. The version is part of it.
let label = Data("com.example.myapp.message.v1".utf8)

func sessionKey(own: P256.KeyAgreement.PrivateKey, peer: Peer) throws -> SymmetricKey {
    // The X9.63 KDF's output: SHA-256, no shared info, 32 bytes.
    let ecdhOutput = try own
        .sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer.publicKey))
        .x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
        .withUnsafeBytes { Data($0) }

    return try TransportKeyDerivation.sessionKey(
        ecdhOutput: ecdhOutput,
        ownPublicKey: own.publicKey.x963Representation,
        peerPublicKey: peer.publicKey,
        postQuantumSecrets: peer.postQuantumSecrets,     // from the record, never from the message
        info: label
    )
}

/// `header` is whatever else the receiver acts on (a message ID, the sender, a timestamp). It travels
/// in the clear and the tag covers it.
func seal(_ plaintext: Data, header: Data, from own: P256.KeyAgreement.PrivateKey, to peer: Peer) throws -> Data {
    let key = try sessionKey(own: own, peer: peer)
    guard let combined = try AES.GCM.seal(plaintext, using: key, authenticating: header).combined
    else { throw TransportError.malformed }
    return combined
}

func open(_ combined: Data, header: Data, as own: P256.KeyAgreement.PrivateKey, from peer: Peer) throws -> Data {
    let key = try sessionKey(own: own, peer: peer)
    return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key, authenticating: header)
}
```

What it does not give you: authentication of the sender (a static-static ECDH only implies it; a
forward-secret exchange authenticates nobody), forward secrecy beyond how long you keep your keys,
key confirmation, replay resistance, or direction binding (both directions get the same key). Don't
trial-decrypt a message under several keys to find which one fits: GCM is not key-committing.

## The examples are tested

Every example above is mirrored in `Tests/OccultaCoreAPITests/ReadmeExamplesTests.swift`, through the
public API only. Change an example and that file together.

Run the package's tests from this directory:

```
xcodebuild test -scheme OccultaCore-Package -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

(With Xcode 27.x locally, add `,OS=26.2` to the destination.) The ML-KEM tests need an iOS 26
simulator and are skipped on earlier ones.
