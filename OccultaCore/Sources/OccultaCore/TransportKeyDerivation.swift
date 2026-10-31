//
//  TransportKeyDerivation.swift
//  Occulta
//
//  The one derivation every transport key goes through: an ECDH output, optionally two ML-KEM
//  shared secrets, and the two public keys, through HKDF-SHA256 under a label the caller chooses.
//  No labels here: Occulta passes its own (`SaltInfo`, wire format), a host app passes its own.
//
//  CRYPTO_REVIEW_CHECKLIST — Transport Key Derivation Path
//  ════════════════════════════════════════
//  1. Key ownership map
//     - ecdhOutput: 32 bytes, caller-owned. The X9.63 output of an ECDH the caller ran with its
//       own private key, wherever that lives (Occulta: the SE identity key, an in-memory
//       ephemeral key, a prekey in the Keychain or as an Enclave blob, a card agreement key).
//       No private key reaches this file.
//     - ownPublicKey, peerPublicKey: x963 P-256 public keys (65 bytes). Public; they only form
//       the salt.
//     - postQuantumSecrets: two ML-KEM shared secrets (32 bytes each), caller-owned.
//     - Output: a 256-bit SymmetricKey, returned to the caller. Nothing is stored, tagged or
//       exported here.
//     - Key material shared between contacts: No. Each key is shared by exactly the two parties
//       to its ECDH; another contact has a different ECDH output and so a different key.
//
//  2. Consumption events
//     - Nothing is one-time-use inside this file. Consuming a prekey (deleting its private
//       half on a successful open) is the caller's — PrekeySecretsManager in Occulta.
//     - The local `ikm` (ecdhOutput ‖ secrets) is released on return, not zeroed: Data can't
//       be zeroed reliably, the same as before this moved here. The returned key is the
//       caller's to drop.
//     - Pure and deterministic: idempotent, and re-derivable for as long as the caller keeps
//       the inputs.
//
//  3. Multi-party trace — example: Alice sends to Bob and to Carol
//     - To Bob, forward-secret: Alice's ephemeral e, Bob's prekey p. Alice computes
//       ECDH(e, P), Bob ECDH(p, E): the same output. The salt E ⊕ P is the same both ways, and
//       the secrets are sorted, so Bob's (ss2, ss1) gives Alice's IKM: both derive one key.
//     - To Carol, Alice uses a fresh ephemeral against Carol's prekey: a different ECDH output,
//       so a key unrelated to Bob's. Neither recipient learns anything about the other's key.
//     - An observer sees E, P and the ciphertexts, so the salt; without the ECDH output (and,
//       in a hybrid form, one of the ML-KEM secrets) the key is out of reach.
//     - The same pair under two labels gets two independent keys (HKDF info).
//     - Malformed input is rejected, not repaired: a public key that is not 65 bytes, or an
//       ML-KEM secret that is not 32, returns nil.
//
//  4. Security property verification
//     - Property: the output is indistinguishable from random to anyone who doesn't know the
//       ECDH output, or, in a hybrid form, to anyone who doesn't know the ECDH output or doesn't
//       know both ML-KEM secrets.
//     - Bound: computational — HKDF-SHA256 as extractor and PRF, P-256 CDH, ML-KEM IND-CCA.
//     - 4.3 Domain separation: the info label alone, and it is the caller's. Occulta's
//       (`SaltInfo` in Key+Manager.swift) are wire format and unchanged by this file; a host
//       app must give each purpose its own. Two of Occulta's forms share a label —
//       classical long-term and classical forward-secret both use kTransportKeyInfo — so what
//       separates those two is their ECDH inputs, not the label. The IKM is fixed-width
//       (32 ‖ 32 ‖ 32), so it parses one way only. The salt binds the two public keys only up
//       to XOR and in no order; the ECDH output is what binds the pair.
//     - 4.4 Harvest-now: the classical form falls with P-256 (recorded public keys and
//       ciphertexts give the key). The hybrid forms hold while ML-KEM-1024 does; the secrets
//       come from PostQuantumProvider, iOS 26+.
//     - 4.5 Access control: no keychain item or Enclave key is touched here. The keys behind
//       ecdhOutput keep their own flags (Occulta's identity key: `[.privateKeyUsage]`,
//       kSecAttrAccessibleWhenUnlockedThisDeviceOnly, no biometric flag). N/A for this file.
//     - 4.6 Prekeys: the forward-secret form takes a prekey public key as one of the two
//       public keys. Publishing, one-time use and deletion are the callers'; nothing here can
//       tell a prekey from an identity key, so the caller's label and inputs decide which
//       form it is.
//     - 4.7 Not achieved: authentication (a long-term form is only implicitly authenticated
//       by static-static ECDH; a forward-secret form authenticates nobody — Occulta signs the
//       sender's ephemeral key separately), forward secrecy beyond the caller's key lifetimes,
//       key confirmation, replay resistance, direction binding (both directions get the same
//       key), zeroing of intermediates. ecdhOutput's length is not checked: every Occulta
//       caller passes 32 bytes.
//
//  5. Layer boundary check
//     - Input: Data, (Data, Data)?. Output: SymmetricKey?. One pure function.
//     - External calls: CryptoKit's HKDF<SHA256>.deriveKey, nothing else.
//     - No SwiftData, no UI, no KeyManagerProtocol, no SecKey, no Enclave.
//     - Tested without an Enclave: OccultaCoreAPITests (properties and rejections), and the
//       app's interop vectors (fsKey, ltKey, diceware, card.v1.longTermKey), checked against
//       an independent implementation.
//

import Foundation
import CryptoKit

// MARK: - TransportKeyDerivation

public enum TransportKeyDerivation {

    /// A 256-bit session key from an ECDH output and, in a hybrid form, two ML-KEM shared secrets.
    ///
    /// ```
    /// IKM  = ecdhOutput                          (classical)
    ///      = ecdhOutput ‖ sorted(secret1, secret2)  (hybrid; lexicographic)
    /// Salt = ownPublicKey ⊕ peerPublicKey
    /// key  = HKDF-SHA256(IKM, Salt, info, 32 bytes)
    /// ```
    ///
    /// Both sides derive the same key: ECDH is symmetric, the salt is, and the secrets are sorted, so each side
    /// passes its own public key as `ownPublicKey` and the secrets in whichever order it holds them.
    ///
    /// - Parameters:
    ///   - ecdhOutput:         `SecKeyCopyKeyExchangeResult` with `.ecdhKeyExchangeCofactorX963SHA256` and a
    ///                         requested size of 32 — ECDH then the X9.63 KDF with SHA-256 and no shared info, not
    ///                         the raw shared point. From CryptoKit, `x963DerivedSymmetricKey(using: SHA256.self,
    ///                         sharedInfo: Data(), outputByteCount: 32)`.
    ///   - ownPublicKey:       x963 public key (65 bytes) of the private key used in the ECDH.
    ///   - peerPublicKey:      x963 public key (65 bytes) of the other side.
    ///   - postQuantumSecrets: the two ML-KEM shared secrets (32 bytes each), or nil for the classical form.
    ///   - info:               the HKDF info: the caller's label for this purpose.
    /// - Returns: The key, or nil if a public key is not 65 bytes or a secret is not 32.
    public static func sessionKey(
        ecdhOutput: Data,
        ownPublicKey: Data,
        peerPublicKey: Data,
        postQuantumSecrets: (Data, Data)?,
        info: Data
    ) -> SymmetricKey? {
        guard ownPublicKey.count == 65, peerPublicKey.count == 65 else { return nil }

        var ikm = ecdhOutput
        if let secrets = postQuantumSecrets {
            guard secrets.0.count == 32, secrets.1.count == 32 else { return nil }
            let sorted = [secrets.0, secrets.1].sorted { $0.lexicographicallyPrecedes($1) }
            ikm.append(contentsOf: sorted[0])
            ikm.append(contentsOf: sorted[1])
        }

        let salt = Data(zip(peerPublicKey, ownPublicKey).map { $0 ^ $1 })

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: 32
        )
    }
}
