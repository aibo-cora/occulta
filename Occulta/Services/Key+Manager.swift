//
//  Key+Manager.swift
//  Occulta
//
//  Created by Yura on 11/12/25.
//

import Foundation
import CryptoKit
import LocalAuthentication
import OccultaCore

// MARK: - HKDF info strings

struct SaltInfo {
    static let kTransportKeyInfo = "Occulta-v1-transport-2025".data(using: .utf8)!
    static let kLocalDBKeyInfo   = "Occulta-v1-encryption-key-2025".data(using: .utf8)!
    /// Domain separator for the hybrid local DB key, **legacy form** (ECDH against G, a function of the key's public point;
    /// the current form is `kLocalDBEnclaveBoundKeyInfo`). Distinct from kLocalDBKeyInfo
    /// to ensure the old (identity-derived) and new (hybrid) keys are never equivalent,
    /// even if the same SE key is used during migration.
    static let kLocalDBHybridKeyInfo = "Occulta-v2-local-db-pq-2026".data(using: .utf8)!
    /// Hybrid transport key: ECDH + ML-KEM combined input keying material.
    /// Used for long-term fallback encryption between PQ-capable contacts.
    static let kHybridTransportKeyInfo = "Occulta-v2-hybrid-pq-transport-2026".data(using: .utf8)!
    /// Hybrid forward-secret transport key: ECDH(ephemeral, prekey) + ML-KEM combined IKM.
    /// Domain-separated from the fallback hybrid path to prevent key collision.
    static let kHybridFSTransportKeyInfo = "Occulta-v2-hybrid-pq-fs-transport-2026".data(using: .utf8)!
    /// Diceware verification key: same hybrid IKM, but with exchange nonces
    /// appended to the info field for per-session uniqueness.
    /// The nonces are appended at call time — this is the static prefix only.
    static let kDicewareKeyInfo = "Occulta-v2-diceware-2026".data(using: .utf8)!
    /// Vault key, **legacy form**: ECDH(vault_SE_priv, G) → HKDF. A function of the vault Enclave key's public point
    /// (`bugs.md` Bug 171), so nothing in it needs the biometric gate. Kept to open what the vault rewrap has not moved
    /// yet and what a downgraded build writes; the current form is `kVaultEnclaveBoundKeyInfo`, below. The vault SE key is
    /// a dedicated SE key protected by .biometryCurrentSet — separate from the identity key.
    /// The derived SymmetricKey lives only as a local per-operation value; never stored.
    /// Domain-separated from all transport and local-DB paths.
    static let kVaultKeyInfo = "Occulta-v1-vault-2026".data(using: .utf8)!
    /// Shard custody key, **legacy form**: ECDH(shard_custody_SE_priv, G) → HKDF, a function of the key's public point
    /// (Bug 171); the current form is `kShardCustodyEnclaveBoundKeyInfo`. Dedicated SE key
    /// with device-unlock-level access (no biometric). Used to seal CustodyShard
    /// records locally — fully automatic, no user friction.
    static let kShardCustodyKeyInfo = "Occulta-v1-shard-custody-2026".data(using: .utf8)!
    /// Secure Mode PIN key: ECDH(secureModePin_SE_priv, G) → HKDF. This stays the *inner* verifier key and is a function of
    /// the PIN Enclave key's public point (Bug 171); every verifier is sealed again under the wrap key
    /// (`kSecureModeWrapKeyInfo`), which is what needs this device. Dedicated SE key
    /// with device-unlock-level access (no biometric). Used to wrap PIN sentinels in
    /// AppLayerConfig. Domain-separated from all other key paths.
    static let kSecureModeKeyInfo = "Occulta-v1-secure-mode-pin-2026".data(using: .utf8)!
    /// Restore vault key, **legacy form**: same SE key as shard custody, distinct HKDF info →
    /// dedicated symmetric key (the current form is `kRestoreVaultEnclaveBoundKeyInfo`). Used to encrypt PendingShamirSecretRestore.shards —
    /// the transient set of returned shards Alice's device collects during
    /// reconstruction. Domain-separated from kShardCustodyKeyInfo so a custody
    /// blob and a reconstruct blob are never decryptable with the same key.
    ///
    /// **The value must never change.** It keys every banked recovery piece on disk,
    /// including the `ReconstructShard` rows v1.10.3 wrote, which is why it still reads
    /// "recovery-buffer" after `deriveRecoveryBufferKey` was renamed. That rename once
    /// changed this string too, re-keying the key, so the upgrade migration couldn't open
    /// a single legacy row and deleted them all (`bugs.md` Bug 137). Pinned by
    /// `RecoveryBufferKeyTests.infoStringIsV1_10_3s`.
    static let kRestoreVaultKeyInfo = "Occulta-v1-recovery-buffer-2026".data(using: .utf8)!
    nonisolated static let kFileKeyInfo           = AttachmentKeyInfo.fileKey

    // MARK: Enclave-bound keys (Bug 171)
    //
    // The info strings of `enclaveBoundKey(_:)`: HKDF(ECDH(enclave_priv, P) ‖ r_tier). Each differs from the
    // legacy string of the same key above, which stays as it is (`kRestoreVaultKeyInfo` is pinned by
    // `RecoveryBufferKeyTests`), so the two forms of a key are never equivalent. Share staging's is
    // `ShareStagingKeyManager`'s own, as the extension links only that file.

    /// Local DB key: t_localDB ‖ r_U.
    static let kLocalDBEnclaveBoundKeyInfo = "Occulta-v3-local-db-2026".data(using: .utf8)!
    /// Vault key: t_vault ‖ r_B.
    static let kVaultEnclaveBoundKeyInfo = "Occulta-v2-vault-2026".data(using: .utf8)!
    /// Shard custody key: t_custody ‖ r_U.
    static let kShardCustodyEnclaveBoundKeyInfo = "Occulta-v2-shard-custody-2026".data(using: .utf8)!
    /// Restore buffer key: t_custody ‖ r_U. Same Enclave key as shard custody, as before.
    static let kRestoreVaultEnclaveBoundKeyInfo = "Occulta-v2-restore-buffer-2026".data(using: .utf8)!
    /// Wrap around the PIN verifiers: t_pin ‖ r_U. `kSecureModeKeyInfo` stays the inner verifier key's.
    static let kSecureModeWrapKeyInfo = "Occulta-v2-secure-mode-pin-wrap-2026".data(using: .utf8)!
    /// Compose staging key: t_localDB ‖ r_U. The key that seals attachments staged for a recipient with no per-contact
    /// key (a group, or a contact we hold no public key for). Same Enclave key and tier secret as the local DB key, so no
    /// new Keychain item; the info string alone separates the two keys.
    static let kComposeStagingEnclaveBoundKeyInfo = "Occulta-v2-compose-staging-2026".data(using: .utf8)!

    // MARK: Hybrid form (Bug 171, term 3)
    //
    // The same keys when the tier's `TierPQRecord` is hybrid (iOS 26+): the Enclave's ML-KEM secret goes into the
    // IKM, `t ‖ ss ‖ r`, and the info is the string below followed by SHA-256(c), the record's ciphertext. Each mode
    // derives a distinct key, and a swapped c changes the key and can't choose it.

    static let kLocalDBEnclaveBoundPQKeyInfo      = "Occulta-v3-local-db-pq-2026".data(using: .utf8)!
    static let kVaultEnclaveBoundPQKeyInfo        = "Occulta-v2-vault-pq-2026".data(using: .utf8)!
    static let kShardCustodyEnclaveBoundPQKeyInfo = "Occulta-v2-shard-custody-pq-2026".data(using: .utf8)!
    static let kRestoreVaultEnclaveBoundPQKeyInfo = "Occulta-v2-restore-buffer-pq-2026".data(using: .utf8)!
    static let kSecureModeWrapPQKeyInfo           = "Occulta-v2-secure-mode-pin-wrap-pq-2026".data(using: .utf8)!
    static let kComposeStagingEnclaveBoundPQKeyInfo = "Occulta-v2-compose-staging-pq-2026".data(using: .utf8)!
}

// MARK: - SE Key Inventory
//
// Manager.Key manages five distinct Secure Enclave P-256 key objects:
//
//  Tag                                      │ Biometric gate │ Purpose
//  ─────────────────────────────────────────┼────────────────┼──────────────────────────────────────
//  "master.key.privacy.turtles.are.cute"    │ No             │ Identity — ECDSA signing, ECDH transport
//  "local.db.se.key.occulta"                │ No             │ Local DB key and compose staging key: the Enclave term (ECDH against P)
//  "vault.key.occulta.v1"                   │ Yes (.biometryCurrentSet + .devicePasscode) │ Vault key (and so every per-entry key it wraps)
//  "shard.custody.occulta"                  │ No             │ Shard custody records + restore vault key
//  "app.layer.key.occulta.v1"               │ No             │ Secure Mode PIN verifiers: the inner key, and the wrap key
//
// All five carry `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — never backed up,
// never synced to iCloud Keychain.
//
// The vault SE key requires a pre-evaluated `LAContext`; the other four operate
// automatically while the device is unlocked.
//
// What the gate guards is *use of the private scalar*, not the symmetric keys built from its public point. Before Bug 171
// every key below was `HKDF(ECDH(enclave_priv, G))`: ECDH against the generator is d·G = Q, the key's own public point, so
// each was a function of Q and the gate was never reached (`bugs.md` Bug 171). Now each is
// `HKDF(ECDH(enclave_priv, P) ‖ [ss ‖] r_tier)`: it needs the Enclave key, the tier's Keychain secret and, on iOS 26+, the
// Enclave's ML-KEM secret. The legacy form stays derivable (`legacyKey(_:)`) for what the reseal has not moved and what
// a downgraded build writes.
//
// Beside the Enclave keys, all generic-password Keychain items, `WhenUnlockedThisDeviceOnly`:
//   - `r_U`  "local.db.random.key.occulta"        32 bytes, tier U (device unlock): local DB, custody, restore, PIN wrap
//   - `r_B`  "vault.random.key.occulta"           32 bytes, tier B, with the vault's access control
//   - the tier PQ records U and B                  9,763 bytes each (`TierPQRecord`); a pending record exists only during an upgrade
//   - in the shared group, `r_S` and the S record  share staging (`ShareStagingKeyManager`)
//
// The shard custody key is reused as the base for the restore vault key — the two
// derived symmetric keys are domain-separated by `kShardCustodyKeyInfo` vs
// `kRestoreVaultKeyInfo` in HKDF.

extension Manager {
    class Key {
        let tag: String

        /// The Enclave keys and Keychain items this key manager creates, reads and removes. The production items,
        /// unless a test gives it its own with `init(items:)`.
        private let items: Items

        init() {
            self.tag = Tags.identity.rawValue
            self.items = .canonical
            #if DEBUG
            Manager.Ambient.override?.recordRealKeyConstruction()
            #endif
        }

        init(testingTag tag: String) {
            self.tag = tag
            self.items = .canonical
            #if DEBUG
            Manager.Ambient.override?.recordRealKeyConstruction()
            #endif
        }

        #if DEBUG
        /// A key manager on the Keychain items `items` names, so a test can run the tier secrets, the tier PQ records
        /// and Erase All Data without touching the Simulator's canonical ones, which other tests are using. The Enclave
        /// keys are the canonical ones (`items.enclaveTags` is only what `deleteAllKeys()` removes). Everything else is
        /// `init()`'s, except that it doesn't count as a real key under `Manager.Ambient.override`: a test binds it
        /// there itself.
        init(items: Items) {
            self.tag = Tags.identity.rawValue
            self.items = items
        }
        #endif

        private enum Tags: String, CaseIterable {
            case identity      = "master.key.privacy.turtles.are.cute"
            case localDB       = "local.db.se.key.occulta"
            case vault         = "vault.key.occulta.v1"
            case shardCustody  = "shard.custody.occulta"
            case secureModePin = "app.layer.key.occulta.v1"
        }

        /// The Secure Enclave keys and Keychain items a key manager works on: the Enclave keys by tag (what
        /// `deleteAllKeys()` removes), the tier secrets `r_U` and `r_B`, and the two tier PQ records.
        struct Items {
            var enclaveTags: [String]
            var tierSecretU: String
            var tierSecretB: String
            var recordU: String
            var recordB: String

            /// Every item the app keeps, which is what Erase All Data removes.
            static let canonical = Items(
                enclaveTags: Tags.allCases.map(\.rawValue),
                tierSecretU: Manager.Key.localDBRandomKeychainAccount,
                tierSecretB: Manager.Key.vaultRandomKeychainAccount,
                recordU:     Manager.Key.localDBPQKeychainAccount,
                recordB:     Manager.Key.vaultPQKeychainAccount
            )
        }

        // MARK: - SE key creation

        private func create() throws -> Bool {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                &error
            ) else { throw error!.takeRetainedValue() as Error }

            let attributes: NSDictionary = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs: [
                    kSecAttrIsPermanent: true,
                    kSecAttrApplicationTag: self.tag.data(using: .utf8)!,
                    kSecAttrAccessControl: access
                ]
            ]
            guard let _ = SecKeyCreateRandomKey(attributes, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            return true
        }

        // P-256 generator base point G — fixed peer for local DB key derivation.
        let fixedX963: Data = Data([
            0x04,
            0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
            0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
            0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
            0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
            0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
            0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
            0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
        ])

        /// A nothing-up-my-sleeve P-256 point P — the peer of `enclaveBoundKey(_:)`. Nobody knows its discrete
        /// log, so ECDH(d, P) is a secret only the Enclave holding d can compute. ECDH(d, G) = Q is not (`bugs.md`
        /// Bug 171).
        ///
        /// Found by try-and-increment: x = SHA-256("Occulta-NUMS-P256-v1" ‖ be32(ctr)) for ctr = 0, 1, 2, …, taking
        /// the first x for which 0x02 ‖ x decompresses to a point (`P256.KeyAgreement.PublicKey(compressedRepresentation:)`).
        /// That is ctr = 1, x = 918e1d3b…696186. Pinned here as uncompressed X9.63; `NUMSPointTests` recomputes it.
        ///
        /// Compiled in: there is no stored point to swap and no scalar anywhere. `ShareStagingKeyManager` and
        /// `TestKeyManager` each carry their own copy, for the reason each carries its own G, and the same test
        /// checks all three.
        let numsX963: Data = Data([
            0x04,
            0x91, 0x8E, 0x1D, 0x3B, 0xBC, 0x67, 0xC9, 0xDE,
            0xBF, 0x17, 0x5B, 0x38, 0x4E, 0x8D, 0xEB, 0xE1,
            0xB6, 0x19, 0x34, 0x83, 0x0F, 0xC7, 0x2E, 0x77,
            0x8B, 0x17, 0xA8, 0xB8, 0x71, 0x69, 0x61, 0x86,
            0x7B, 0x9E, 0x15, 0xCF, 0xD2, 0xF5, 0x0E, 0x04,
            0x5A, 0xE4, 0x45, 0x0C, 0x9C, 0xD8, 0xC4, 0xAE,
            0x93, 0xE1, 0x55, 0xAA, 0x5B, 0xEC, 0x75, 0x37,
            0x2E, 0x88, 0x46, 0x25, 0x64, 0xA1, 0x3D, 0xE6
        ])

        // MARK: - Local DB encryption key (kLocalDBKeyInfo)

        func createLocalEncryptionKey() throws -> SymmetricKey? {
            guard let ourPrivateKey = try? self.retrievePrivateKey() else { return nil }
            guard let fixedPubKey = self.convert(material: self.fixedX963) else { return nil }

            var error: Unmanaged<CFError>?
            guard
                let rawSecret = SecKeyCopyKeyExchangeResult(
                    ourPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                    [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                    &error
                ) as? Data
            else { return nil }

            guard let ourPubData = self.convert(key: self.retrivePublicKey(using: ourPrivateKey))
            else { return nil }

            let salt = Data(zip(self.fixedX963.map { $0 }, ourPubData.map { $0 }).map { $0 ^ $1 })
            
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: rawSecret),
                salt: salt, info: SaltInfo.kLocalDBKeyInfo, outputByteCount: 32
            )
        }

        // MARK: - SE retrieval

        /// Retrieve the SE identity private key by tag, creating it if absent.
        ///
        /// **SE operations:** `SecItemCopyMatching` + conditionally `SecKeyCreateRandomKey`.
        ///
        /// - Returns: The private key reference, or `nil` if the SE is unavailable.
        func retrievePrivateKey() throws -> SecKey? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: self.tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
            var item: CFTypeRef?
            
            switch SecItemCopyMatching(query as CFDictionary, &item) {
            case errSecItemNotFound:
                item = nil
                _ = try self.create()
                
                return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess ? (item as! SecKey) : nil
            case errSecSuccess:
                return (item as! SecKey)
            default:
                return nil
            }
        }

        /// Copy the public key from a private key reference via `SecKeyCopyPublicKey`.
        ///
        /// - Returns: Public key reference, or `nil` if `key` is nil or the copy fails.
        ///
        /// Note: the method name contains a typo ("retrive"). Call sites use this name;
        /// rename only when all references can be updated atomically.
        func retrivePublicKey(using key: SecKey?) -> SecKey? {
            key.flatMap { SecKeyCopyPublicKey($0) }
        }

        /// Delete the SE key with the given application tag.
        ///
        /// - Returns: `true` if the key was deleted or did not exist; `false` on unexpected error.
        @discardableResult
        func delete(using tag: String) -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
            let status = SecItemDelete(query as CFDictionary)
            
            return status == errSecSuccess || status == errSecItemNotFound
        }


        // MARK: - Transport session key — long-term identity path (kTransportKeyInfo)

        /// Derive a session key using our SE long-term identity key and a peer's public key.
        ///
        /// Returns nil — never crashes — on: nil/wrong-length material, SE unavailable, ECDH failure.
        func createSharedSecret(using material: Data?) -> SymmetricKey? {
            guard let peerKey = self.convert(material: material) else { return nil }
            guard let ourPriv = try? self.retrievePrivateKey()   else { return nil }

            var error: Unmanaged<CFError>?
            guard
                let rawSecret = SecKeyCopyKeyExchangeResult(
                    ourPriv, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                    [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                    &error
                ) as? Data
            else { return nil }

            guard
                let peerData = self.convert(key: peerKey),
                let ourData  = self.convert(key: self.retrivePublicKey(using: ourPriv))
            else { return nil }

            return try? TransportKeyDerivation.sessionKey(
                ecdhOutput: rawSecret, ownPublicKey: ourData, peerPublicKey: peerData,
                postQuantumSecrets: nil, info: SaltInfo.kTransportKeyInfo
            )
        }

        // MARK: - Shared secret derivation (ephemeral or prekey private key)

        /// Derive a session key using any in-memory private key and a peer's public key.
        ///
        /// Used on both sides of the forward-secret exchange:
        ///
        /// **Encryption (sender):**
        /// ```
        /// sessionKey = HKDF(ECDH(ephemeralPriv, recipientPrekeyPub))
        /// ```
        ///
        /// **Decryption (recipient):**
        /// ```
        /// sessionKey = HKDF(ECDH(ourPrekeyPriv, senderEphemeralPub))
        /// ```
        ///
        /// ECDH commutativity guarantees both sides arrive at the same raw shared secret.
        /// The XOR salt is also commutative, so HKDF output is identical on both sides.
        ///
        /// Uses identical parameters to the existing `createSharedSecret(using:)`:
        /// - Algorithm: `.ecdhKeyExchangeCofactorX963SHA256`
        /// - Salt: XOR(peerPublicKey, ourPublicKey) — 65 bytes
        /// - Info: `SaltInfo.kTransportKeyInfo` (`"Occulta-v1-transport-2025"`, UTF-8)
        /// - Output: 32 bytes
        ///
        /// - Parameters:
        ///   - ephemeralPrivateKey: Any in-memory `SecKey` — throwaway or prekey private.
        ///   - recipientMaterial:   Peer's public key in x963 format.
        /// - Returns: 256-bit `SymmetricKey`, or `nil` on failure.
        func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey? {
            guard recipientMaterial.count == 65 else { return nil }

            guard
                let ephPub     = SecKeyCopyPublicKey(ephemeralPrivateKey),
                let ephPubData = SecKeyCopyExternalRepresentation(ephPub, nil) as Data?
            else { return nil }

            guard let peerKey = self.convert(material: recipientMaterial) else { return nil }

            var error: Unmanaged<CFError>?
            guard
                let rawSecret = SecKeyCopyKeyExchangeResult(
                    ephemeralPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                    [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                    &error
                ) as? Data
            else { return nil }

            return Self.forwardSecretSessionKey(
                ecdhOutput: rawSecret, ownPublicKey: ephPubData, peerMaterial: recipientMaterial, quantumMaterial: nil
            )
        }

        // MARK: - SE signing (general purpose)

        /// ECDSA-sign `data` with the SE identity key.
        ///
        /// **SE operations performed:**
        /// 1. `retrievePrivateKey` — reads the identity private key by tag.
        /// 2. `SecKeyCreateSignature` — signs; SE applies SHA-256 internally.
        ///
        /// ⚠️ DO NOT pre-hash `data`. `.ecdsaSignatureMessageX962SHA256` hashes
        /// internally. Pre-hashing produces a signature no verifier will accept,
        /// and the failure is silent — identical to a key mismatch.
        ///
        /// - Returns: DER-encoded ECDSA signature.
        func signData(_ data: Data) throws -> Data {
            guard let key = try self.retrievePrivateKey() else { throw Errors.noIdentityAvailable }
            var error: Unmanaged<CFError>?
            guard
                let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data?
            else { throw error!.takeRetainedValue() as Error }
            return sig
        }

        /// Generate a throwaway in-memory P-256 key pair for a single FS message.
        ///
        /// `kSecAttrIsPermanent: false` — key is never written to any keychain.
        /// The private key exists only in memory for the duration of ECDH, then ARC releases it.
        func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)? {
            let attributes: NSDictionary = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
            ]
            var error: Unmanaged<CFError>?
            guard
                let priv    = SecKeyCreateRandomKey(attributes, &error),
                let pub     = SecKeyCopyPublicKey(priv),
                let pubData = SecKeyCopyExternalRepresentation(pub, nil) as Data?
            else { return nil }
            
            return (priv, pubData)
        }
    }
}

// MARK: - Helpers

extension Manager.Key {
    /// Export a `SecKey` to its x963 external representation.
    ///
    /// For P-256 public keys the result is 65 bytes (`0x04 ∥ x ∥ y`).
    /// - Returns: Raw key bytes, or `nil` if `key` is nil or the export fails.
    func convert(key: SecKey?) -> Data? {
        key.flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? }
    }

    /// Validates `data` is exactly 65 bytes before creating a SecKey.
    /// Prevents ECDH from receiving malformed input (Finding 6).
    func convert(material data: Data?) -> SecKey? {
        guard let data, data.count == 65 else { return nil }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
    }

    /// Retrieve and export the identity public key as x963 `Data` (65 bytes).
    ///
    /// **SE operations:** `retrievePrivateKey` (read), `SecKeyCopyPublicKey` (derive public),
    /// `SecKeyCopyExternalRepresentation` (export).
    ///
    /// - Throws: `.noIdentityAvailable` if the SE key is absent or cannot be exported.
    func retrieveIdentity() throws -> Data {
        guard
            let priv = try self.retrievePrivateKey(),
            let pub  = self.retrivePublicKey(using: priv),
            let data = self.convert(key: pub)
        else { throw Errors.noIdentityAvailable }
        
        return data
    }
}

extension Manager.Key {
    enum Errors: Error {
        case noIdentityAvailable
        /// A tier secret couldn't be generated: no entropy.
        case entropyUnavailable
        /// `createTierSecretIfAbsent` found the item already there, but it won't read as a 32-byte secret.
        case tierSecretUnreadable
        /// A tier PQ record exists but isn't a `TierPQRecord`: wrong size or an unknown mode.
        case tierPQRecordUnreadable
        /// An ML-KEM provider exists but couldn't make the tier's key, encapsulate to it, or fit its blob.
        /// Nothing is created: a classical record in its place would lower a device that could be hybrid.
        case postQuantumKeyUnavailable
    }
}

/// The v1 local DB key is `Manager.Key.createLocalEncryptionKey()`, reachable through this and nothing else.
extension Manager.Key: LegacyLocalKeyProviding {}

//  Hybrid local database encryption key, **legacy form** (`legacyKey(.localDB)`), as the release before Bug 171 derived it:
//
//  Derivation: HKDF(ikm: ECDH(SE_priv, G) || randomKey,
//                    salt: SE_pub_x963,
//                    info: "Occulta-v1-local-db-pq-2025")
//
//  What each half buys, as measured by `EnclaveGeneratorECDHTests`: ECDH against G is d·G = Q, the key's own public
//  point, so the "SE component" is a function of Q and adds no secrecy; anyone who holds Q has it, with no Enclave. The
//  key was in effect its random Keychain half alone, and a quantum adversary's Shor step on the Enclave key is moot,
//  since Q already gave away what the exchange computes. An attacker needed the random half and Q, not the chip.
//
//  The current form, `enclaveBoundKey(.localDB)`, exchanges with a point P nobody knows the discrete log of, so the
//  Enclave term is real, and mixes in `r_U` (this same random half, the symmetric term a quantum computer meets with
//  Grover's square-root speed-up only) and, on iOS 26+, the Enclave's ML-KEM secret. The legacy form is derived now to
//  open what the reseal has not moved and what a downgraded build writes.
extension Manager.Key: KeyManagerProtocol {

    // MARK: - Tags and identifiers


    /// Keychain account identifier for the random symmetric component.
    private static let localDBRandomKeychainAccount = "local.db.random.key.occulta"

    /// Keychain account of `r_B`, the vault tier's secret (`TierSecret.biometry`). Created with the vault's access
    /// control, so it opens only through the vault's evaluated `LAContext`.
    private static let vaultRandomKeychainAccount = "vault.random.key.occulta"

    /// Keychain accounts of the tier PQ records (`TierPQRecord`): tier U's, which serves the local DB, shard custody,
    /// restore and PIN wrap keys as `localDBRandomKeychainAccount` does, and tier B's, the vault's.
    private static let localDBPQKeychainAccount = "local.db.pq.key.occulta"
    private static let vaultPQKeychainAccount   = "vault.pq.key.occulta"

    // MARK: - Legacy entry points

    /// Today's derivations, ECDH against the generator G (`bugs.md` Bug 171). The four protocol methods of the
    /// same names below delegate here, so every existing caller computes exactly what it did before. The
    /// bodies are the `deriveLegacy…` functions further down, unchanged.
    func legacyKey(_ key: LegacyKey) throws -> SymmetricKey? {
        switch key {
        case .localDB:            return try self.deriveLegacyLocalDBKey()
        case .shardCustody:       return try self.deriveLegacyShardCustodyKey()
        case .restoreVault:       return try self.deriveLegacyRestoreVaultKey()
        case .vault(let context): return try self.deriveLegacyVaultKey(context: context)
        }
    }

    /// Tier U's three keys follow the epoch: the Enclave-bound derivation once `AppLayerConfig.keyEpoch` exists, the
    /// legacy one before (`Manager.Ambient.tierUKeys`, decided once per process at launch).
    func createHybridLocalEncryptionKey() throws -> SymmetricKey? { try self.tierUKey(.localDB, legacy: .localDB) }

    /// The compose staging key follows tier U's process state like the other tier U keys, but has no legacy form: in a
    /// process the reseal left on the legacy keys there is none (nil), so every import is refused and nothing is staged
    /// in plaintext (Stage 8). It was only ever in dev builds, which is why there is nothing to fall back to.
    func deriveComposeStagingKey() throws -> SymmetricKey? {
        switch Manager.Ambient.tierUKeys {
        case .legacy:       return nil
        case .enclaveBound: return try self.enclaveBoundKey(.composeStaging)
        }
    }
    func deriveShardCustodyKey() throws -> SymmetricKey? { try self.tierUKey(.shardCustody, legacy: .shardCustody) }
    func deriveRestoreVaultKey() throws -> SymmetricKey? { try self.tierUKey(.restoreVault, legacy: .restoreVault) }

    /// The vault key follows the vault's epoch: the Enclave-bound derivation once `VaultManager.unlock(context:)` has
    /// moved the vault onto it (`Manager.Ambient.vaultKeys`), the legacy one before.
    func deriveVaultKey(context: LAContext) throws -> SymmetricKey? {
        switch Manager.Ambient.vaultKeys {
        case .legacy:                return try self.legacyKey(.vault(context))
        case .enclaveBound:          return try self.enclaveBoundKey(.vault(context))
        case .enclaveBoundClassical: return try self.enclaveBoundKey(.vault(context), record: .classical)
        }
    }

    private func tierUKey(_ key: EnclaveBoundKey, legacy: LegacyKey) throws -> SymmetricKey? {
        switch Manager.Ambient.tierUKeys {
        case .legacy:       return try self.legacyKey(legacy)
        case .enclaveBound: return try self.enclaveBoundKey(key)
        }
    }

    // MARK: - Hybrid key derivation

    /// Derive the hybrid local DB encryption key. The body of `legacyKey(.localDB)`.
    ///
    /// **SE operations performed:**
    /// 1. Retrieve (or create) the local DB SE private key by tag.
    /// 2. Copy the public key from the private key reference.
    /// 3. ECDH key exchange with the fixed generator point G.
    ///
    /// **Keychain operations performed:**
    /// 1. Retrieve (or generate and store) the 256-bit random component.
    ///
    /// - Returns: 256-bit `SymmetricKey`, or `nil` if SE or Keychain is unavailable.
    private func deriveLegacyLocalDBKey() throws -> SymmetricKey? {
        // Step 1: SE-derived component — ECDH(localDB_SE_privkey, G)
        guard let seComponent = try self.deriveLocalDBSEComponent() else { return nil }

        // Step 2: Random Keychain component
        guard let randomComponent = try self.retrieveOrCreateRandomComponent() else { return nil }

        // Step 3: Combine via HKDF
        //   IKM  = SE_derived (32 bytes) || random (32 bytes)
        //   Salt = SE public key x963 (65 bytes) — binds to this specific SE key
        //   Info = domain separator
        guard
            let localDBPrivateKey = try self.retrieveLocalDBPrivateKey(),
            let localDBPubKey = self.retrivePublicKey(using: localDBPrivateKey),
            let pubKeyData = self.convert(key: localDBPubKey)
        else { return nil }

        var ikm = Data(seComponent)
        ikm.append(randomComponent)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: pubKeyData,
            info: SaltInfo.kLocalDBHybridKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - SE key for local DB

    /// Retrieve the dedicated local DB SE private key, creating it if absent.
    ///
    /// **SE operations:** SecItemCopyMatching, conditionally SecKeyCreateRandomKey.
    private func retrieveLocalDBPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Tags.localDB.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)

        case errSecItemNotFound:
            item = nil
            try self.createLocalDBSEKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                return nil
            }
            return (item as! SecKey)

        default:
            return nil
        }
    }

    /// Create the dedicated local DB P-256 key in the Secure Enclave.
    ///
    /// **SE operations:** SecKeyCreateRandomKey (single write, no ECDH).
    private func createLocalDBSEKey() throws {
        try self.createLocalDBSEKey(tag: Tags.localDB.rawValue)
    }

    /// Create a local-DB-style P-256 SE key with an explicit application tag.
    /// Access policy: `.privateKeyUsage` only, device-unlock level, no biometric.
    private func createLocalDBSEKey(tag: String) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag.data(using: .utf8)!,
                kSecAttrAccessControl: access
            ]
        ]

        guard let _ = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }
    }

    // MARK: - SE component derivation

    /// ECDH with the fixed generator point G, using the local DB SE key.
    /// Returns 32 raw bytes of shared secret.
    ///
    /// **SE operations:** ECDH key exchange (single call).
    private func deriveLocalDBSEComponent() throws -> Data? {
        guard let privateKey = try self.retrieveLocalDBPrivateKey() else { return nil }
        guard let fixedPubKey = self.convert(material: fixedX963) else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                privateKey,
                .ecdhKeyExchangeCofactorX963SHA256,
                fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        return rawSecret
    }

    // MARK: - Random Keychain component

    /// Retrieve the 256-bit random component from Keychain, or generate and store it.
    ///
    /// **Keychain operations:** SecItemCopyMatching, conditionally SecItemAdd.
    private func retrieveOrCreateRandomComponent() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.localDBRandomKeychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else { return nil }
            return data

        case errSecItemNotFound:
            return try self.generateAndStoreRandomComponent()

        default:
            return nil
        }
    }

    /// Generate 32 cryptographically random bytes and store in Keychain.
    ///
    /// The key is stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
    /// - Not included in unencrypted backups
    /// - Not synced to iCloud Keychain
    /// - Encrypted at rest by the device's hardware key
    ///
    /// ⚠️ If this Keychain entry is lost (device restore without Keychain migration),
    /// all locally encrypted data becomes permanently irrecoverable. This is the
    /// intended security posture — no recovery path exists by design.
    private func generateAndStoreRandomComponent() throws -> Data? {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        guard status == errSecSuccess else { return nil }

        let randomData = Data(bytes)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.localDBRandomKeychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: randomData
        ]

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else { return nil }

        return randomData
    }

    // MARK: - Vault SE key

    /// Dedicated SE key tag for vault derivation — separate from identity and local DB keys.

    // CRYPTO_REVIEW_CHECKLIST — Vault Key Derivation Path (v2)
    // ══════════════════════════════════════════════════════════
    // 1. Key ownership map
    //    - Vault SE key: dedicated P-256 key in SE (tag: Tags.vault). Single owner.
    //    - Private half: hardware-bound, never extractable.
    //    - Public half Q: the app never stores or exports it, but it is not secret and not gated. `SecKeyCopyPublicKey`
    //      returns it from a key reference fetched by tag with no evaluated `LAContext` (measured on a device, Bug 171),
    //      and the keychain row records SHA-1(Q). Nothing here rests on Q staying private.
    //    - Static peer: since Bug 171 the nothing-up-my-sleeve point P, whose discrete log nobody knows. The generator G
    //      was the peer before it: ECDH against G is d·G = Q, so the legacy key (`legacyKey(.vault)`) is a function of Q.
    //    - Second input: `r_B`, a 32-byte Keychain secret under the same access control, read through the same context.
    //    - Shared between contacts: No. Vault key is derived entirely locally.
    //
    // 2. Consumption events
    //    - No one-time consumption. Re-derivable on demand via ECDH(vault_SE_priv, P) and r_B (ECDH against G before the
    //      vault is rewrapped).
    //    - Key lives only as a local SymmetricKey for the duration of each vault op.
    //    - No zeroing needed — scope-bounded by the calling function's stack frame.
    //
    // 3. Multi-party trace
    //    - Single owner only. No contact ever receives this key or material from it.
    //    - SSS shards split the vault entry key (separate per-entry concern).
    //
    // 4. Security property verification
    //    - Harvest-now-decrypt-later: the app's own storage keeps no copy of Q, but a keychain row and the public-key
    //      accessor do, so "no harvest surface" is not claimed. What a holder of Q gets is no key: the vault key needs
    //      the Enclave key (d), `r_B` (symmetric, so Grover only) and, on iOS 26+, the Enclave's ML-KEM secret from the
    //      tier B record, none of which Q yields. Below iOS 26 a keychain dump that holds Q and `r_B`, analysed later with
    //      a quantum computer, is open, needs a decision (Bug 171, D1).
    //    - Biometric gate: .biometryCurrentSet OR .devicePasscode gates *use* of the Enclave key and the read of `r_B`.
    //      It did not gate the symmetric key before Bug 171, which could be rebuilt from Q with no chip. What a change of
    //      the enrolled biometrics does to the key and to `r_B`, and with no biometrics enrolled, is not checked (a
    //      device-only check, Bug 171 0b): open, needs a decision.
    //    - Device binding: kSecAttrAccessibleWhenUnlockedThisDeviceOnly on the key and on `r_B`. The legacy key was not
    //      device-bound, being a function of Q; the Enclave-bound one is.
    //    - LAContext: pre-evaluated once per session; passed to SE to avoid per-op prompts.
    //    - Not achieved: forward secrecy (same key re-derived on each unlock).
    //    - No prekey public keys involved. Checklist item 4.6: N/A.
    //
    // 5. Layer boundary check
    //    - Input: LAContext. Output: SymmetricKey. No SwiftData, no UI.
    //    - SE operations: key retrieval (biometric-gated via context), ECDH (compute).

    /// Create the vault SE key with biometric access control.
    ///
    /// Access control: (`.biometryCurrentSet` OR `.devicePasscode`) + `.privateKeyUsage`.
    /// `.biometryCurrentSet` invalidates the key if the enrolled biometric set changes.
    private func createVaultSEKey() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: Tags.vault.rawValue.data(using: .utf8)!,
                kSecAttrAccessControl:  access
            ]
        ]
        var createError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes, &createError) != nil else {
            throw createError!.takeRetainedValue() as Error
        }
    }

    /// Retrieve the vault SE private key, creating it on first use.
    ///
    /// Passes the pre-evaluated `context` to the Keychain query so the SE uses
    /// the already-verified biometric instead of prompting the user again.
    ///
    /// - Throws: Keychain/SE error if retrieval fails (e.g. biometric mismatch,
    ///           context invalidated). VaultManager.currentKey() converts these to .locked.
    private func retrieveVaultPrivateKey(context: LAContext) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:                    kSecClassKey,
            kSecAttrApplicationTag as String:       Tags.vault.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String:              kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:                true,
            kSecAttrTokenID as String:              kSecAttrTokenIDSecureEnclave,
            kSecUseAuthenticationContext as String: context
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            try self.createVaultSEKey()
            // `r_B` is made at the same moment as the key it goes with, so its creation date adds nothing (Bug 171,
            // Stage 4). A failure here is not this call's to report: the first unlock after it creates `r_B`.
            _ = try? self.createTierSecretIfAbsent(.biometry(context))
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                return nil
            }
            return (item as! SecKey)
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /// Derive the vault session key: ECDH(vault_SE_priv, G) → HKDF-SHA256.
    ///
    /// **SE operations:**
    /// 1. `retrieveVaultPrivateKey(context:)` — retrieves vault SE key via pre-evaluated LAContext.
    /// 2. `SecKeyCopyKeyExchangeResult` — ECDH with the P-256 generator point G.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    private func deriveLegacyVaultKey(context: LAContext) throws -> SymmetricKey? {
        guard let vaultPriv   = try self.retrieveVaultPrivateKey(context: context) else { return nil }
        guard let fixedPubKey = self.convert(material: fixedX963)                  else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                vaultPriv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        // Salt = vault public key x963 — binds derivation to this specific SE key.
        guard
            let vaultPub     = self.retrivePublicKey(using: vaultPriv),
            let vaultPubData = self.convert(key: vaultPub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: vaultPubData,
            info: SaltInfo.kVaultKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Shard custody SE key

    /// Dedicated SE key tag for shard custody — no biometric, device-unlock level.

    /// Create the shard custody P-256 key in the Secure Enclave.
    ///
    /// Access control: `.privateKeyUsage` only — no biometric flag.
    /// This allows fully automatic shard operations while the device is unlocked,
    /// without requiring the user to approve each SE access.
    private func createShardCustodySEKey() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: Tags.shardCustody.rawValue.data(using: .utf8)!,
                kSecAttrAccessControl:  access
            ]
        ]
        var createError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes, &createError) != nil else {
            throw createError!.takeRetainedValue() as Error
        }
    }

    /// Retrieve the shard custody SE private key, creating it on first use.
    ///
    /// **SE operations:** `SecItemCopyMatching` + conditionally `SecKeyCreateRandomKey`.
    ///
    /// No `LAContext` is passed — access control is device-unlock level, so no biometric
    /// prompt is required. Throws an `NSError` (NSOSStatusErrorDomain) on unexpected
    /// Keychain failure.
    private func retrieveShardCustodyPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: Tags.shardCustody.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            try self.createShardCustodySEKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                return nil
            }
            return (item as! SecKey)
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /// Derive the shard custody key: ECDH(shardCustody_SE_priv, G) → HKDF-SHA256.
    ///
    /// No LAContext needed — access control is device-unlock level (no biometric).
    /// This enables fully automatic shard operations triggered by bundle receipt.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    private func deriveLegacyShardCustodyKey() throws -> SymmetricKey? {
        guard let custodyPriv  = try self.retrieveShardCustodyPrivateKey() else { return nil }
        guard let fixedPubKey  = self.convert(material: fixedX963)         else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                custodyPriv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        guard
            let custodyPub     = self.retrivePublicKey(using: custodyPriv),
            let custodyPubData = self.convert(key: custodyPub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: custodyPubData,
            info: SaltInfo.kShardCustodyKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Restore vault key

    /// Derive the restore vault key: ECDH(shardCustody_SE_priv, G) → HKDF-SHA256
    /// with `kRestoreVaultKeyInfo`. Reuses the shard custody SE key (same access
    /// policy: device-unlock, no biometric) but produces a distinct symmetric key
    /// via HKDF domain separation.
    ///
    /// Used to seal PendingShamirSecretRestore.shards — the transient set of
    /// returned shards collected during reconstruction.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    private func deriveLegacyRestoreVaultKey() throws -> SymmetricKey? {
        guard let custodyPriv  = try self.retrieveShardCustodyPrivateKey() else { return nil }
        guard let fixedPubKey  = self.convert(material: fixedX963)         else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                custodyPriv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        guard
            let custodyPub     = self.retrivePublicKey(using: custodyPriv),
            let custodyPubData = self.convert(key: custodyPub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: custodyPubData,
            info: SaltInfo.kRestoreVaultKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Secure Mode PIN SE key

    /// Derive the Secure Mode PIN key: ECDH(secureModePin_SE_priv, G) → HKDF-SHA256.
    ///
    /// No LAContext needed — device-unlock level access, no biometric.
    /// Used by PINManager to wrap/unwrap PIN sentinels stored in AppLayerConfig.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    func deriveSecureModeKey() throws -> SymmetricKey? {
        guard let priv        = try self.retrieveSecureModePINPrivateKey() else { return nil }
        guard let fixedPubKey = self.convert(material: fixedX963)          else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                priv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        guard
            let pub     = self.retrivePublicKey(using: priv),
            let pubData = self.convert(key: pub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: pubData,
            info: SaltInfo.kSecureModeKeyInfo,
            outputByteCount: 32
        )
    }

    private func retrieveSecureModePINPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: Tags.secureModePin.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            try self.createSecureModePINKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
            return (item as! SecKey)
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    private func createSecureModePINKey() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: Tags.secureModePin.rawValue.data(using: .utf8)!,
                kSecAttrAccessControl:  access
            ]
        ]
        var createError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes, &createError) != nil else {
            throw createError!.takeRetainedValue() as Error
        }
    }

    // MARK: - Cleanup

    /// Deletes all SE keys enumerated in Tags, the local DB random Keychain component (`r_U`), the
    /// vault tier's secret (`r_B`) and the two tier PQ records (`TierPQRecord`, U and B). A missing item counts
    /// as deleted.
    /// Adding a new case to Tags automatically includes it here — no manual update needed.
    /// After this call every encrypted blob in Occulta is permanently unreadable.
    @discardableResult
    func deleteAllKeys() -> Bool {
        let seDeleted = self.items.enclaveTags.allSatisfy { self.delete(using: $0) }
        let legacyDeleted = self.deleteLegacyRotationArtefacts()
        let keychainQuery: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: self.items.tierSecretU
        ]
        let keychainStatus = SecItemDelete(keychainQuery as CFDictionary)
        // Every deletion runs whatever an earlier one returned: a failure must not leave `r_B` or a record behind.
        let vaultSecretDeleted = self.deleteTierSecret(account: self.items.tierSecretB)
        // The pending records exist only during an upgrade that was interrupted, and a wipe must not leave one behind.
        let recordsDeleted = [self.items.recordU, self.items.recordB, self.items.recordU + Self.pendingSuffix, self.items.recordB + Self.pendingSuffix]
            .map { self.deleteTierSecret(account: $0) }
        return seDeleted && legacyDeleted
            && (keychainStatus == errSecSuccess || keychainStatus == errSecItemNotFound)
            && vaultSecretDeleted
            && !recordsDeleted.contains(false)
    }

    /// Deletes the generic-password item `account`: `r_B` or a tier PQ record for `deleteAllKeys()`. A missing item
    /// counts as deleted.
    /// Apart from `deleteAllKeys()` so a test can run it on an item of its own: calling `deleteAllKeys()` itself
    /// would delete the canonical keys other tests are using.
    func deleteTierSecret(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)

        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// The names v1.10.3's local-DB key rotation used for its transient keys (`bugs.md` Bug 139).
    /// Nothing creates or reads them any more: they exist only so the wipe can delete leftovers
    /// from a rotation that was interrupted before this branch removed rotation.
    private static let legacyRotationSETags          = ["local.db.se.key.occulta.staged", "local.db.se.key.occulta.superseded"]
    private static let legacyRotationRandomAccount   = "local.db.random.key.occulta.staged"

    /// Deletes any keys left by an interrupted v1.10.3 rotation (`bugs.md` Bug 139). Their
    /// names show Secure Mode was activated, and they must not outlive a wipe. Always safe from
    /// `deleteAllKeys()`: after a wipe no data remains that any of them could be needed for.
    /// Not called at launch, where a `.superseded` key can still be the one existing data is
    /// sealed under. Missing items count as deleted.
    func deleteLegacyRotationArtefacts() -> Bool {
        let seDeleted = Self.legacyRotationSETags.allSatisfy { self.delete(using: $0) }
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: Self.legacyRotationRandomAccount
        ]
        let status = SecItemDelete(query as CFDictionary)
        return seDeleted && (status == errSecSuccess || status == errSecItemNotFound)
    }
}

// MARK: - Enclave-bound keys and tier secrets (Bug 171)
//
//  Every key in the `KeyManagerProtocol` extension above is HKDF(ECDH(enclave_priv, G) …). ECDH against G is
//  d·G = Q, so each is a function of the key's public point, and the Enclave and the biometric gate never
//  see it (`bugs.md` Bug 171). These are the replacements:
//
//      t = ECDH(enclave_priv, P)         P: a point whose discrete log nobody knows (`numsX963`)
//      r = the tier's Keychain secret    r_U (device unlock, app) or r_B (biometry or passcode)
//      key = HKDF(ikm: t ‖ r, salt: the Enclave key's public point, info: the key's `-2026` string)
//
//  On iOS 26+ the tier's `TierPQRecord` is hybrid and the Enclave's ML-KEM secret goes in as well:
//
//      ss = the Enclave key's decapsulation of the record's ciphertext c
//      key = HKDF(ikm: t ‖ ss ‖ r, salt: as above, info: the key's `-pq-2026` string ‖ SHA-256(c))
//
//  Same Enclave keys as the legacy derivations, so none is added or replaced; only the peer, the IKM and
//  the info string change. Since Stage 2 the three tier U accessors call `enclaveBoundKey(_:)` once the tier's epoch
//  exists (`tierUKey(_:legacy:)`), and the PIN verifiers are wrapped under `.secureModeWrap`, and the vault key follows the vault
//  epoch (Stage 4). Share staging's key is `ShareStagingKeyManager`'s own copy of the derivation (Stage 5).
extension Manager.Key {

    // MARK: - Derivation

    func enclaveBoundKey(_ key: EnclaveBoundKey) throws -> SymmetricKey? {
        try self.enclaveBoundKey(key, provider: PostQuantumProviderFactory.create())
    }

    /// `enclaveBoundKey(_:)` in the form `record` says (Stage 6), whatever the tier's stored record is. The record is not
    /// read from the Keychain at all, so a classical key derives from `.classical` even after the stored record has
    /// become hybrid, and the hybrid key of a pending record derives before that record is the tier's own.
    func enclaveBoundKey(_ key: EnclaveBoundKey, record: TierPQRecord) throws -> SymmetricKey? {
        try self.enclaveBoundKey(key, provider: PostQuantumProviderFactory.create(), overriding: record)
    }

    /// `enclaveBoundKey(_:)` with the ML-KEM provider passed in, so a test can use the in-memory one. Production
    /// passes `PostQuantumProviderFactory.create()`, which is nil below iOS 26.
    ///
    /// `overriding` is the record to derive in the form of, instead of the one the tier has stored.
    func enclaveBoundKey(_ key: EnclaveBoundKey, provider: (any PostQuantumProvider)?, overriding: TierPQRecord? = nil) throws -> SymmetricKey? {
        switch key {
        case .localDB:
            return try self.deriveEnclaveBound(
                secret:        { try self.tierSecret(.deviceUnlock) },
                record:        { try overriding ?? self.tierPQRecord(.deviceUnlock) },
                provider:      provider,
                privateKey:    { try self.retrieveLocalDBPrivateKey() },
                classicalInfo: SaltInfo.kLocalDBEnclaveBoundKeyInfo,
                hybridInfo:    SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
            )
        case .shardCustody:
            return try self.deriveEnclaveBound(
                secret:        { try self.tierSecret(.deviceUnlock) },
                record:        { try overriding ?? self.tierPQRecord(.deviceUnlock) },
                provider:      provider,
                privateKey:    { try self.retrieveShardCustodyPrivateKey() },
                classicalInfo: SaltInfo.kShardCustodyEnclaveBoundKeyInfo,
                hybridInfo:    SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo
            )
        case .restoreVault:
            return try self.deriveEnclaveBound(
                secret:        { try self.tierSecret(.deviceUnlock) },
                record:        { try overriding ?? self.tierPQRecord(.deviceUnlock) },
                provider:      provider,
                privateKey:    { try self.retrieveShardCustodyPrivateKey() },
                classicalInfo: SaltInfo.kRestoreVaultEnclaveBoundKeyInfo,
                hybridInfo:    SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo
            )
        case .composeStaging:
            return try self.deriveEnclaveBound(
                secret:        { try self.tierSecret(.deviceUnlock) },
                record:        { try overriding ?? self.tierPQRecord(.deviceUnlock) },
                provider:      provider,
                privateKey:    { try self.retrieveLocalDBPrivateKey() },
                classicalInfo: SaltInfo.kComposeStagingEnclaveBoundKeyInfo,
                hybridInfo:    SaltInfo.kComposeStagingEnclaveBoundPQKeyInfo
            )
        case .secureModeWrap:
            return try self.deriveEnclaveBound(
                secret:        { try self.tierSecret(.deviceUnlock) },
                record:        { try overriding ?? self.tierPQRecord(.deviceUnlock) },
                provider:      provider,
                privateKey:    { try self.retrieveSecureModePINPrivateKey() },
                classicalInfo: SaltInfo.kSecureModeWrapKeyInfo,
                hybridInfo:    SaltInfo.kSecureModeWrapPQKeyInfo
            )
        case .vault(let context):
            return try self.deriveEnclaveBound(
                secret:        { try self.tierSecret(.biometry(context)) },
                record:        { try overriding ?? self.tierPQRecord(.vault) },
                provider:      provider,
                privateKey:    { try self.retrieveVaultPrivateKey(context: context) },
                classicalInfo: SaltInfo.kVaultEnclaveBoundKeyInfo,
                hybridInfo:    SaltInfo.kVaultEnclaveBoundPQKeyInfo
            )
        }
    }

    /// Reads the tier secret, then the tier's PQ record, and only then touches an Enclave key. A missing secret or
    /// record gives nil with nothing fetched, let alone created, so a missing one writes nothing anywhere.
    ///
    /// A classical record derives `t ‖ r`. A hybrid record decapsulates its ciphertext with `provider` first, and
    /// derives `t ‖ ss ‖ r`; if there is no provider, or the blob or ciphertext won't decapsulate to 32 bytes, the
    /// answer is nil. A hybrid record is never read as classical, whatever fails.
    ///
    /// Internal, with the secret, the record and the key as closures, so a test can prove exactly that.
    func deriveEnclaveBound(
        secret: () throws -> Data?,
        record: () throws -> TierPQRecord?,
        provider: (any PostQuantumProvider)?,
        privateKey: () throws -> SecKey?,
        classicalInfo: Data,
        hybridInfo: Data
    ) throws -> SymmetricKey? {
        guard let tierSecret = try secret() else { return nil }
        guard let tierRecord = try record() else { return nil }

        var info = classicalInfo
        var postQuantum: (secret: Data, ciphertext: Data)?

        switch tierRecord.mode {
        case .classical:
            break
        case .hybrid:
            guard
                let provider,
                let shared = provider.decapsulate(ciphertext: tierRecord.ciphertext, keyBlob: tierRecord.keyBlob),
                shared.count == 32
            else { return nil }

            info        = hybridInfo
            postQuantum = (shared, tierRecord.ciphertext)
        }

        guard let enclaveKey = try privateKey() else { return nil }

        return self.deriveEnclaveBound(exchangingWith: enclaveKey, secret: tierSecret, postQuantum: postQuantum, info: info)
    }

    /// The derivation itself, for any P-256 private key reference — an Enclave key in production, a software key
    /// in a test that rebuilds it. `privateKey` is the only input that has to stay in the Enclave.
    ///
    /// `postQuantum` is the hybrid form's ML-KEM shared secret and the ciphertext it came from. With it the IKM is
    /// `t ‖ ss ‖ r` and `info` becomes `info ‖ SHA-256(c)`, so `info` is the base string of the mode in use.
    func deriveEnclaveBound(
        exchangingWith privateKey: SecKey,
        secret: Data,
        postQuantum: (secret: Data, ciphertext: Data)? = nil,
        info: Data
    ) -> SymmetricKey? {
        guard let peer = self.convert(material: self.numsX963) else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let exchange = SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, peer,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        // Salt = the key's public point, as every legacy derivation but the identity-derived one.
        guard let publicKey = self.convert(key: self.retrivePublicKey(using: privateKey)) else { return nil }

        var ikm = exchange
        var info = info

        if let postQuantum {
            ikm.append(postQuantum.secret)
            info.append(Data(SHA256.hash(data: postQuantum.ciphertext)))
        }
        ikm.append(secret)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: publicKey,
            info: info,
            outputByteCount: 32
        )
    }

    // MARK: - Tier secrets

    private func account(for tier: TierSecret) -> String {
        switch tier {
        case .deviceUnlock: return self.items.tierSecretU
        case .biometry:     return self.items.tierSecretB
        }
    }

    /// The tier's secret, or nil when the Keychain has no item for it, or one that isn't 32 bytes. Reads only; a
    /// missing secret is never created here, because a new one would leave everything sealed under the old one
    /// unreadable. Throws for any other failure, such as a locked device: that is not a missing secret.
    func tierSecret(_ tier: TierSecret) throws -> Data? {
        try self.readTierSecret(tier, account: self.account(for: tier))
    }

    /// `tierSecret(_:)` for a named account, so a test can use an item of its own.
    func readTierSecret(_ tier: TierSecret, account: String) throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String:  true
        ]
        switch tier {
        case .deviceUnlock:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .biometry(let context):
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else { return nil }
            return data
        case errSecItemNotFound:
            return nil
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    @discardableResult
    func createTierSecretIfAbsent(_ tier: TierSecret) throws -> Bool {
        try self.createTierSecretIfAbsent(tier, account: self.account(for: tier))
    }

    /// `createTierSecretIfAbsent(_:)` for a named account, so a test can use an item of its own.
    ///
    /// Adds first and reads on `errSecDuplicateItem`, so two processes racing to create it end with one secret and
    /// both read it. Never replaces an existing item. `r_B` is created with the vault's access control
    /// (`[.biometryCurrentSet, .or, .devicePasscode]`, `WhenUnlockedThisDeviceOnly`); adding needs no
    /// authentication, reading it does.
    ///
    /// See `KeyManagerProtocol.createTierSecretIfAbsent` for when it may be called.
    @discardableResult
    func createTierSecretIfAbsent(_ tier: TierSecret, account: String) throws -> Bool {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw Errors.entropyUnavailable
        }

        var attributes: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String:   Data(bytes)
        ]
        switch tier {
        case .deviceUnlock:
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .biometry:
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.biometryCurrentSet, .or, .devicePasscode],
                &error
            ) else { throw error!.takeRetainedValue() as Error }
            attributes[kSecAttrAccessControl as String] = access
        }

        switch SecItemAdd(attributes as CFDictionary, nil) {
        case errSecSuccess:
            return true
        case errSecDuplicateItem:
            guard try self.readTierSecret(tier, account: account) != nil else { throw Errors.tierSecretUnreadable }
            return false
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    // MARK: - Tier PQ records

    private func pqAccount(for tier: PostQuantumTier) -> String {
        switch tier {
        case .deviceUnlock: return self.items.recordU
        case .vault:        return self.items.recordB
        }
    }

    /// The tier's PQ record, or nil when the Keychain has no item for it. Reads only; a missing record is never
    /// created here, because a new one is a new key and would leave everything sealed under the old one unreadable.
    /// Throws for anything else: a locked device, and an item that isn't a `TierPQRecord` (a record that won't read
    /// is not a missing one).
    func tierPQRecord(_ tier: PostQuantumTier) throws -> TierPQRecord? {
        try self.readTierPQRecord(account: self.pqAccount(for: tier))
    }

    /// `tierPQRecord(_:)` for a named account, so a test can use an item of its own.
    func readTierPQRecord(account: String) throws -> TierPQRecord? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String:  true
        ]

        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data, let record = TierPQRecord(decoding: data) else {
                throw Errors.tierPQRecordUnreadable
            }
            return record
        case errSecItemNotFound:
            return nil
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    @discardableResult
    func createTierPQRecordIfAbsent(_ tier: PostQuantumTier) throws -> Bool {
        try self.createTierPQRecordIfAbsent(account: self.pqAccount(for: tier), provider: PostQuantumProviderFactory.create())
    }

    /// `createTierPQRecordIfAbsent(_:)` for a named account and a given provider, so a test can use an item of its
    /// own and the in-memory ML-KEM key.
    ///
    /// Reads first, so an existing record costs no Enclave key. Then builds the record: with a provider, a fresh
    /// Enclave key, its public key encapsulated to, and both stored; without one, the classical record. A provider
    /// that can't make the key, or whose blob doesn't fit `TierPQRecord.blobCapacity`, throws and stores nothing.
    ///
    /// See `KeyManagerProtocol.createTierPQRecordIfAbsent` for when it may be called.
    @discardableResult
    func createTierPQRecordIfAbsent(account: String, provider: (any PostQuantumProvider)?) throws -> Bool {
        if try self.readTierPQRecord(account: account) != nil { return false }

        let record: TierPQRecord
        if let provider {
            guard let hybrid = try? self.makeHybridPQRecord(provider: provider) else { throw Errors.postQuantumKeyUnavailable }
            record = hybrid
        } else {
            record = .classical
        }

        return try self.addTierPQRecord(record, account: account)
    }

    // MARK: - The upgrade to hybrid (Stage 6)

    var postQuantumAvailable: Bool { PostQuantumProviderFactory.create() != nil }

    func makeHybridPQRecord() throws -> TierPQRecord? {
        try self.makeHybridPQRecord(provider: PostQuantumProviderFactory.create())
    }

    /// `makeHybridPQRecord()` with the provider passed in, so a test can use the in-memory one. nil without a provider.
    /// Throws, with nothing stored, if a provider exists and can't make the key or its blob doesn't fit the record.
    func makeHybridPQRecord(provider: (any PostQuantumProvider)?) throws -> TierPQRecord? {
        guard let provider else { return nil }
        guard
            let pair         = provider.generatePersistentKeyPair(),
            let encapsulated = provider.encapsulate(peerPublicKeyData: pair.publicKeyData)
        else { throw Errors.postQuantumKeyUnavailable }

        return try TierPQRecord.hybrid(keyBlob: pair.keyBlob, ciphertext: encapsulated.ciphertext)
    }

    /// The account of a tier's pending record: the tier's own, with a suffix. The item exists only during one upgrade.
    private func pendingAccount(for tier: PostQuantumTier) -> String {
        self.pqAccount(for: tier) + Self.pendingSuffix
    }

    static let pendingSuffix = ".pending"

    func pendingTierPQRecord(_ tier: PostQuantumTier) throws -> TierPQRecord? {
        try self.readTierPQRecord(account: self.pendingAccount(for: tier))
    }

    @discardableResult
    func addPendingTierPQRecord(_ record: TierPQRecord, tier: PostQuantumTier) throws -> Bool {
        try self.addTierPQRecord(record, account: self.pendingAccount(for: tier))
    }

    func replaceTierPQRecord(_ tier: PostQuantumTier, with record: TierPQRecord) throws {
        try self.replaceTierPQRecord(account: self.pqAccount(for: tier), with: record)
    }

    /// Replaces the data of the item `account` in one atomic update. The item keeps its creation date and its protection.
    /// Throws if there is no such item: this never creates a record.
    func replaceTierPQRecord(account: String, with record: TierPQRecord) throws {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: try record.encoded()] as CFDictionary)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    @discardableResult
    func deletePendingTierPQRecord(_ tier: PostQuantumTier) -> Bool {
        self.deleteTierSecret(account: self.pendingAccount(for: tier))
    }

    /// Adds `record` under `account`, or on `errSecDuplicateItem` leaves what is there and reads it: two processes or
    /// two launches racing to create it end with one record, and both use it. Returns whether this call added it.
    @discardableResult
    func addTierPQRecord(_ record: TierPQRecord, account: String) throws -> Bool {
        let attributes: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrAccount as String:    account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String:      try record.encoded()
        ]

        switch SecItemAdd(attributes as CFDictionary, nil) {
        case errSecSuccess:
            return true
        case errSecDuplicateItem:
            guard try self.readTierPQRecord(account: account) != nil else { throw Errors.tierPQRecordUnreadable }
            return false
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
}

extension Manager.Key {
 
    // MARK: - Hybrid shared secret (ECDH + ML-KEM)
 
    /// Derive a hybrid transport key combining ECDH and ML-KEM shared secrets.
    ///
    /// Option A — mutual encapsulation: both sides encapsulate and decapsulate,
    /// producing two independent ML-KEM shared secrets. Both are included in the IKM.
    ///
    /// The two ML-KEM secrets are sorted lexicographically before concatenation
    /// so both sides produce identical IKM regardless of who encapsulated first.
    ///
    /// ```
    /// IKM  = ECDH_secret || sorted(ML-KEM_secret_A, ML-KEM_secret_B)
    /// Salt = XOR(peerP256Pub, ourP256Pub)
    /// Info = kHybridTransportKeyInfo
    /// ```
    ///
    /// SE operations: one ECDH via SE identity key.
    ///
    /// - Parameters:
    ///   - peerP256Material: Peer's P-256 public key, x963 format (65 bytes).
    ///   - quantumMaterial: ML-KEM shared secrets from the exchange.
    /// - Returns: 256-bit hybrid SymmetricKey, or nil on failure.
    func createHybridSharedSecret(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial
    ) -> SymmetricKey? {
        guard let ecdh = self.identityECDH(peerP256Material: peerP256Material) else { return nil }

        return try? TransportKeyDerivation.sessionKey(
            ecdhOutput: ecdh.rawECDH, ownPublicKey: ecdh.ownPublicKey, peerPublicKey: peerP256Material,
            postQuantumSecrets: quantumMaterial.sharedSecrets, info: SaltInfo.kHybridTransportKeyInfo
        )
    }
    
    /// Derive a hybrid forward-secret session key combining ephemeral ECDH and ML-KEM shared secrets.
    ///
    /// Same hybrid pattern as `createHybridSharedSecret`, but uses an ephemeral/prekey
    /// ECDH instead of the identity-level ECDH. Each FS message becomes independently
    /// quantum-resistant rather than relying on transitive chain protection.
    ///
    /// ```
    /// IKM  = ECDH(ephemeralPriv, prekeyPub) || sorted(ML-KEM_secret_1, ML-KEM_secret_2)
    /// Salt = XOR(prekeyPub, ephemeralPub)
    /// Info = kHybridFSTransportKeyInfo
    /// ```
    ///
    /// SE operations: none (ephemeral key is in-memory, passed in by caller).
    ///
    /// - Parameters:
    ///   - ephemeralPrivateKey: Sender's throwaway in-memory P-256 private key.
    ///   - recipientMaterial: Contact's prekey public key, x963 format (65 bytes).
    ///   - quantumMaterial: ML-KEM shared secrets from the contact's exchange.
    /// - Returns: 256-bit hybrid SymmetricKey, or nil on failure.
    func createHybridFSSharedSecret(
        ephemeralPrivateKey: SecKey,
        recipientMaterial: Data,
        quantumMaterial: QuantumKeyMaterial
    ) -> SymmetricKey? {
        guard recipientMaterial.count == 65 else { return nil }
        guard quantumMaterial.isValid else { return nil }

        guard
            let ephemeralPublicKey = SecKeyCopyPublicKey(ephemeralPrivateKey),
            let ephemeralPublicKeyData = SecKeyCopyExternalRepresentation(ephemeralPublicKey, nil) as Data?
        else { return nil }

        guard let peerKey = self.convert(material: recipientMaterial) else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(
                ephemeralPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        return Self.forwardSecretSessionKey(
            ecdhOutput: rawECDH, ownPublicKey: ephemeralPublicKeyData, peerMaterial: recipientMaterial,
            quantumMaterial: quantumMaterial
        )
    }

    /// The forward-secret session key from an ECDH output, shared by every kind of private key.
    ///
    /// A `SecKey` reaches here through `createSharedSecret(ephemeralPrivateKey:recipientMaterial:)` and
    /// `createHybridFSSharedSecret`; a CryptoKit key through `Manager.Crypto.deriveSessionKey(sharedSecret:…)`.
    /// One derivation, so the two can't drift: a prekey held as an Enclave blob in the contact's record
    /// (Prekey Continuity D9) has to open exactly what a keychain prekey opens.
    ///
    /// ```
    /// IKM  = ecdhOutput                                   (classical)
    ///      = ecdhOutput || sorted(ML-KEM_secret_1, ML-KEM_secret_2)  (hybrid)
    /// Salt = XOR(peerMaterial, ownPublicKey)
    /// Info = kTransportKeyInfo (classical) / kHybridFSTransportKeyInfo (hybrid)
    /// ```
    ///
    /// The derivation itself is `TransportKeyDerivation.sessionKey`; this picks the label.
    ///
    /// - Parameters:
    ///   - ecdhOutput:   32 bytes of `.ecdhKeyExchangeCofactorX963SHA256`, i.e. ECDH then the X9.63 KDF
    ///                   with SHA-256 and no shared info. Not the raw shared secret.
    ///   - ownPublicKey: x963 public key of the private key used in the ECDH (65 bytes).
    ///   - peerMaterial: x963 public key of the other side (65 bytes).
    static func forwardSecretSessionKey(
        ecdhOutput: Data,
        ownPublicKey: Data,
        peerMaterial: Data,
        quantumMaterial: QuantumKeyMaterial?
    ) -> SymmetricKey? {
        try? TransportKeyDerivation.sessionKey(
            ecdhOutput: ecdhOutput, ownPublicKey: ownPublicKey, peerPublicKey: peerMaterial,
            postQuantumSecrets: quantumMaterial?.sharedSecrets,
            info: quantumMaterial == nil ? SaltInfo.kTransportKeyInfo : SaltInfo.kHybridFSTransportKeyInfo
        )
    }
 
    /// Derive a Diceware verification key from hybrid material with per-session nonces.
    ///
    /// Same IKM and salt as `createHybridSharedSecret`, but the HKDF info field
    /// includes both exchange nonces (sorted) for per-session uniqueness.
    /// This ensures Diceware words differ on every exchange, even between the same key pairs.
    ///
    /// SE operations: one ECDH via SE identity key.
    func createDicewareKey(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial,
        ourNonce: Data,
        peerNonce: Data
    ) -> SymmetricKey? {
        guard let ecdh = self.identityECDH(peerP256Material: peerP256Material) else { return nil }
        guard ourNonce.count == 16, peerNonce.count == 16 else { return nil }

        let sortedNonces = [ourNonce, peerNonce].sorted { $0.lexicographicallyPrecedes($1) }
        var info = SaltInfo.kDicewareKeyInfo
        info.append(contentsOf: sortedNonces[0])
        info.append(contentsOf: sortedNonces[1])

        return try? TransportKeyDerivation.sessionKey(
            ecdhOutput: ecdh.rawECDH, ownPublicKey: ecdh.ownPublicKey, peerPublicKey: peerP256Material,
            postQuantumSecrets: quantumMaterial.sharedSecrets, info: info
        )
    }
 
    // MARK: - 16-byte exchange nonce
 
    /// Generate a 16-byte cryptographic nonce for an exchange session.
    ///
    /// Committed in the discovery message before proximity is confirmed,
    /// preventing a MITM from choosing nonces after seeing identity keys.
    func generateExchangeNonce() -> Data? {
        var bytes = [UInt8](repeating: 0, count: 16)
 
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            return nil
        }
 
        return Data(bytes)
    }
 
    // MARK: - Private
 
    private struct ECDHResult {
        let rawECDH: Data
        let ownPublicKey: Data
    }

    /// Perform ECDH with our SE identity key, and export the identity public key that goes into the salt.
    ///
    /// Factored out to avoid duplicating SE access between hybrid transport and Diceware derivation.
    ///
    /// SE operations: retrievePrivateKey (read), ECDH (compute).
    private func identityECDH(peerP256Material: Data) -> ECDHResult? {
        guard peerP256Material.count == 65 else { return nil }
        
        guard let peerKey = self.convert(material: peerP256Material) else { return nil }
        guard let ourPriv = try? self.retrievePrivateKey() else { return nil }
 
        var error: Unmanaged<CFError>?
        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(ourPriv, .ecdhKeyExchangeCofactorX963SHA256, peerKey, [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error) as? Data
        else { return nil }
 
        guard let ourPubData = self.convert(key: self.retrivePublicKey(using: ourPriv)) else { return nil }

        return ECDHResult(rawECDH: rawECDH, ownPublicKey: ourPubData)
    }
}
