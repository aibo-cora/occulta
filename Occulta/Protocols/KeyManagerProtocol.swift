//
//  KeyManagerProtocol.swift
//  Occulta
//
//

import Foundation
import CryptoKit
import LocalAuthentication
import OccultaCore

// MARK: - Bug 171 key forms

/// A key as `KeyManagerProtocol.legacyKey(_:)` derives it: `HKDF(ECDH(enclave_priv, G) …)`, with G the
/// P-256 generator. ECDH against G is d·G = Q, the key's own public point, so each of these is a function
/// of Q (`bugs.md` Bug 171). They stay derivable for as long as something sealed under them can exist: data
/// the reseal has not moved yet, and what a downgraded build writes.
enum LegacyKey {
    case localDB
    case shardCustody
    case restoreVault
    /// Needs the vault's pre-evaluated `LAContext`, as `deriveVaultKey(context:)` does.
    case vault(LAContext)
}

/// A key as `KeyManagerProtocol.enclaveBoundKey(_:)` derives it: `HKDF(t ‖ r)` with `t = ECDH(enclave_priv, P)`,
/// P a nothing-up-my-sleeve point whose discrete log nobody knows, and `r` the Keychain secret of the key's
/// access tier (`TierSecret`). It needs the Enclave key and the secret, and Q alone gives neither.
///
/// On a tier whose `TierPQRecord` is hybrid (iOS 26+) the Enclave's ML-KEM secret `ss` goes in too:
/// `HKDF(t ‖ ss ‖ r)`, with its own info strings.
enum EnclaveBoundKey {
    case localDB
    case shardCustody
    case restoreVault
    /// The wrap around the Secure Mode PIN verifiers. The inner verifier key stays `deriveSecureModeKey()`.
    case secureModeWrap
    /// Needs the vault's pre-evaluated `LAContext`, for the Enclave key and for the secret `r_B`.
    case vault(LAContext)
}

/// The access tier of a `TierPQRecord`. The record is a plain Keychain item, read without the vault's
/// `LAContext`: its blob opens nothing without this device's Enclave.
enum PostQuantumTier {
    /// Tier U, the local DB, shard custody, restore and PIN wrap keys.
    case deviceUnlock
    /// Tier B, the vault key.
    case vault
}

/// A 32-byte secret held in the Keychain for one access tier, the second input of `EnclaveBoundKey`.
enum TierSecret {
    /// `r_U`: device unlock, app only. The existing `local.db.random.key.occulta` item, which also serves the
    /// legacy hybrid local DB key. Feeds the local DB, shard custody, restore and PIN wrap keys.
    case deviceUnlock
    /// `r_B`: biometry or passcode, read through the vault's pre-evaluated `LAContext`. Feeds the vault key.
    case biometry(LAContext)
}

// MARK: - KeyManagerProtocol

protocol KeyManagerProtocol {
    func retrieveIdentity() throws -> Data
    /// v1 path — ECDH(identity_key, G) → HKDF. Retained for migration decrypt only.
    func createLocalEncryptionKey() throws -> SymmetricKey?
    /// v2 path — HKDF(ECDH(localDB_SE_key, G) || random_keychain). PQ-reinforced.
    func createHybridLocalEncryptionKey() throws -> SymmetricKey?
    /// Transport path — uses `kTransportKeyInfo`.
    func createSharedSecret(using material: Data?) -> SymmetricKey?
    /// Transport path (ephemeral/prekey) — uses `kTransportKeyInfo`.
    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey?
    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)?

    // MARK: - Hybrid PQ (HKDF only — no ML-KEM types)

    func createHybridSharedSecret(peerP256Material: Data, quantumMaterial: QuantumKeyMaterial) -> SymmetricKey?
    func createHybridFSSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data, quantumMaterial: QuantumKeyMaterial) -> SymmetricKey?

    func createDicewareKey(peerP256Material: Data, quantumMaterial: QuantumKeyMaterial, ourNonce: Data, peerNonce: Data) -> SymmetricKey?
    func generateExchangeNonce() -> Data?

    // MARK: - Identity challenge

    /// ECDSA-sign `data` with the long-term SE identity key (or the in-memory
    /// equivalent, in tests).
    ///
    /// Algorithm: `.ecdsaSignatureMessageX962SHA256`. The algorithm hashes
    /// `data` internally with SHA-256 — callers MUST NOT pre-hash.
    /// Double-hashing produces a signature that no verifier will accept,
    /// silently breaking identity verification.
    ///
    /// - Returns: DER-encoded ECDSA signature, raw bytes from `SecKeyCreateSignature`.
    func signIdentityChallenge(_ data: Data) throws -> Data

    // MARK: - Vault

    /// Derive the vault session key: ECDH(vault_SE_priv, G) → HKDF-SHA256.
    ///
    /// The `context` must be a pre-evaluated LAContext. The SE uses it to satisfy
    /// the biometric access control on the vault key without prompting the user.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveVaultKey(context: LAContext) throws -> SymmetricKey?

    /// ECDSA-sign `data` with the SE identity key (used for vault shard signing).
    ///
    /// ⚠️ DO NOT pre-hash — `.ecdsaSignatureMessageX962SHA256` hashes internally.
    ///
    /// ⚠️ **`data` must begin with a domain-separation prefix.** This key also signs
    /// identity challenges (`"occulta-identity-challenge-v1"`) and vault attributes
    /// (`"occulta-signed-attribute-v2"`), and a signature carries no record of which context
    /// produced it — only the bytes decide. Two sites that can produce identical bytes are two
    /// sites whose signatures are interchangeable.
    ///
    /// One caller predates this rule and does not follow it: `wrapRecipient` signs a bare
    /// 65-byte ephemeral public key for `senderEphemeralSignature`. It is safe today only
    /// because it is the sole unprefixed site — an X9.63 point starts `0x04` and both prefixes
    /// start with ASCII `o`, so nothing currently collides with it. That safety is one call
    /// site deep. **Do not add a second site that signs a bare public key** — this app handles
    /// 65-byte P-256 points everywhere (identity keys, prekey publics, peer material), so
    /// signing one for any new purpose would make its signature indistinguishable from a
    /// sender-ephemeral signature, in both directions. Prefixing `wrapRecipient` is the real
    /// fix and is a wire-format change; see §3.6 of `Docs/Audit/SECURITY_CHECKLIST.md`.
    ///
    /// - Returns: DER-encoded ECDSA signature.
    func signData(_ data: Data) throws -> Data

    /// Derive the shard custody key: ECDH(shardCustody_SE_priv, G) → HKDF-SHA256.
    ///
    /// No LAContext needed — the shard custody SE key has device-unlock-level access
    /// (no biometric flag). Enables fully automatic shard operations on bundle receipt.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveShardCustodyKey() throws -> SymmetricKey?

    /// Derive the restore vault key: same SE key as `deriveShardCustodyKey`,
    /// distinct HKDF info — produces a dedicated symmetric key for sealing
    /// PendingShamirSecretRestore rows.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveRestoreVaultKey() throws -> SymmetricKey?

    /// Derive the Secure Mode PIN key: ECDH(secureModePin_SE_priv, G) → HKDF-SHA256.
    ///
    /// No LAContext needed — device-unlock level, no biometric.
    /// Used by PINManager to wrap/unwrap PIN sentinels in AppLayerConfig.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveSecureModeKey() throws -> SymmetricKey?

    // MARK: - Bug 171

    /// Today's derivation of `key`, ECDH against the generator G (`bugs.md` Bug 171).
    /// `createHybridLocalEncryptionKey`, `deriveShardCustodyKey`, `deriveRestoreVaultKey` and
    /// `deriveVaultKey(context:)` are this method under their own names, and compute exactly what they did
    /// before. Kept to open what the reseal has not moved yet and what a downgraded build writes.
    func legacyKey(_ key: LegacyKey) throws -> SymmetricKey?

    /// The Enclave-bound derivation of `key`: `HKDF(ECDH(enclave_priv, P) ‖ r_tier)`, so it needs the Enclave
    /// key and the tier's Keychain secret. The tier U accessors (`createHybridLocalEncryptionKey()`,
    /// `deriveShardCustodyKey()`, `deriveRestoreVaultKey()`) return it once the tier's epoch exists; the key reseal
    /// calls it by name, and so do the PIN verifiers, wrapped under `.secureModeWrap` (Stage 3). The vault and share
    /// staging keys do not use it yet.
    ///
    /// Reads the tier secret and never creates it: nil when it is missing, before the Enclave key is fetched.
    /// Creating it is `createTierSecretIfAbsent(_:)`, called on purpose and not as a side effect of a read.
    /// Throws when the secret or the Enclave key can't be read for a reason other than absence (a locked
    /// device, a failed biometric context).
    func enclaveBoundKey(_ key: EnclaveBoundKey) throws -> SymmetricKey?

    /// Creates the tier's Keychain secret if the Keychain has none, and returns whether this call created it.
    /// An `errSecDuplicateItem` (another process or an earlier launch got there first) re-reads the item
    /// instead of replacing it.
    ///
    /// **Call it only while the tier has never been resealed, or on a fresh install.** Once data is sealed under
    /// a key that includes the secret, a missing secret must mean nil and a loud failure, never a new secret:
    /// a new one leaves every row sealed under the old one unreadable. `KeyReseal.bootstrap` calls it, at launch and
    /// only while the tier has no epoch.
    @discardableResult
    func createTierSecretIfAbsent(_ tier: TierSecret) throws -> Bool

    /// Creates the tier's `TierPQRecord` if the Keychain has none, and returns whether this call created it.
    /// With an ML-KEM provider (iOS 26+) the record holds a real Enclave key and a ciphertext to it; without one it
    /// holds mode = classical and filler of the same size. A provider that exists but can't make the key throws:
    /// a transient failure must not leave a classical record on a device that could have had a hybrid one.
    ///
    /// The same rule as `createTierSecretIfAbsent(_:)`: **only while the tier has never been resealed, or on a
    /// fresh install.** A record recreated afterwards would be a new key, and everything sealed under the old one
    /// would be unreadable. `KeyReseal.bootstrap` calls it, next to the tier secret's.
    @discardableResult
    func createTierPQRecordIfAbsent(_ tier: PostQuantumTier) throws -> Bool

    /// The tier's Keychain secret, or nil when there is none. Reads only, never creates. Throws for anything but
    /// absence: a locked device is not a missing secret, and the key reseal reports the two differently.
    func tierSecret(_ tier: TierSecret) throws -> Data?

    /// The tier's PQ record, or nil when there is none. Reads only, never creates. Throws for anything but absence.
    func tierPQRecord(_ tier: PostQuantumTier) throws -> TierPQRecord?
}

// MARK: - TestKeyManager

#if DEBUG
/// In-memory P-256 key manager for unit tests.
/// No Secure Enclave — safe to run in the test process.
///
/// `#if DEBUG` because this is a fully working key manager that bypasses the Secure Enclave,
/// and it was previously compiled into the shipped binary. Not exploitable — reaching it needs
/// code execution, at which point the process is already lost — but a security product should
/// not ship an Enclave bypass, complete with a switch that forces key derivation to fail, as
/// dead weight in its release build.
///
/// Consequence: the test target must build against a configuration where DEBUG is defined,
/// which is how it is already run. The two SwiftUI previews that construct this are gated the
/// same way.
@MainActor
final class TestKeyManager: KeyManagerProtocol {
    private let identityPrivateKey: SecKey
    private let identityPublicKeyData: Data

    // The four dedicated key pairs below are internal, not private, so a test can rebuild what the Enclave-bound
    // mirror derives from the scalar, as `deriveCustodySEKey` is for the legacy migration tests.

    /// Separate key pair simulating the dedicated local DB SE key.
    let localDBPrivateKey: SecKey
    private let localDBPublicKeyData: Data

    /// Separate key pair simulating the dedicated vault SE key.
    let vaultPrivateKey: SecKey
    private let vaultPublicKeyData: Data

    /// Separate key pair simulating the dedicated shard custody SE key.
    let shardCustodyPrivateKey: SecKey
    private let shardCustodyPublicKeyData: Data

    /// Separate key pair simulating the dedicated Secure Mode PIN SE key.
    let secureModePrivateKey: SecKey
    private let secureModePublicKeyData: Data

    /// Simulates the Keychain tier secret `r_U` (32 bytes), the one item the legacy hybrid local DB key and every
    /// device-unlock `enclaveBoundKey` mix in. nil = the item is missing. The legacy key creates it on a miss, as
    /// production does; `enclaveBoundKey` does not.
    var tierSecretU: Data?

    /// Simulates the Keychain tier secret `r_B` (32 bytes) of the vault tier. nil = the item is missing.
    var tierSecretB: Data?

    /// Makes `enclaveBoundKey(_:)` return nil as production does when it can't read the tier secret, without
    /// touching `tierSecretU` or `tierSecretB`: nothing is written, and the secrets are still there afterwards.
    var simulatesTierSecretMissing = false

    /// Makes `enclaveBoundKey(.secureModeWrap)` return nil and nothing else, so the PIN verifiers can be checked, which
    /// needs the inner key, while the wrap key (`r_U`, the tier U record) is out of reach.
    var simulatesWrapKeyUnavailable = false

    /// Simulates the tier PQ record of tier U (`TierPQRecord`). nil = the item is missing. `init` makes it as
    /// production would on this OS: hybrid with an in-memory ML-KEM key on iOS 26+, classical below.
    var tierPQRecordU: TierPQRecord?

    /// Simulates the tier PQ record of tier B (the vault). nil = the item is missing.
    var tierPQRecordB: TierPQRecord?

    /// Simulates a device below iOS 26: no ML-KEM provider, so a created record is classical, and a hybrid record
    /// can't be decapsulated (`enclaveBoundKey` gives nil for it, never a classical key).
    var simulatesNoPostQuantum = false

    /// Simulates a locked device: reading a tier secret or a tier PQ record throws, and so does `enclaveBoundKey`,
    /// as the real `Manager.Key` does when the Keychain refuses the read. Nothing is lost or changed by it, and the
    /// legacy keys are left alone: the key reseal must stop on the throw without ever reaching them.
    var simulatesLockedDevice = false

    /// What a build from before the fix does: `createHybridLocalEncryptionKey()`, `deriveShardCustodyKey()` and
    /// `deriveRestoreVaultKey()` derive the legacy keys whatever `Manager.Ambient.tierUKeys` says. A test uses it to
    /// seal data the way the previous release did, or the way a downgraded build still does.
    var derivesLegacyKeysOnly = false

    /// How many times `legacyKey(_:)` ran, including through the four protocol methods that delegate to it. A fresh
    /// install must derive none: there is no legacy data to open.
    private(set) var legacyKeyCalls = 0

    /// The in-memory ML-KEM provider; nil below iOS 26.
    private let postQuantum: (any PostQuantumProvider)? = PostQuantumProviderFactory.createForTesting()

    /// Set to true to make deriveVaultKey(context:) throw — tests lock-on-failure behaviour.
    var simulateVaultKeyFailure = false
    /// How many times `deriveVaultKey(context:)` ran, so a test can pin how often a path
    /// derives the vault key (the Vault tab's list, derived once per rebuild).
    private(set) var vaultKeyDerivations = 0

    /// Fixed generator point G for ECDH derivation.
    private let fixedX963 = Data([
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

    /// The nothing-up-my-sleeve point P of the Enclave-bound derivations. Its own copy, as `fixedX963` is:
    /// `Manager.Key().numsX963` would construct a real key manager. `NUMSPointTests` checks it against the seed.
    let numsX963 = Data([
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

    init() {
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var err: Unmanaged<CFError>?

        // Identity key pair
        let identityPriv = SecKeyCreateRandomKey(attrs, &err)!
        let identityPub  = SecKeyCopyPublicKey(identityPriv)!
        self.identityPrivateKey    = identityPriv
        self.identityPublicKeyData = SecKeyCopyExternalRepresentation(identityPub, nil)! as Data

        // Separate local DB key pair (simulates dedicated SE key)
        let localDBPriv = SecKeyCreateRandomKey(attrs, &err)!
        let localDBPub  = SecKeyCopyPublicKey(localDBPriv)!
        self.localDBPrivateKey    = localDBPriv
        self.localDBPublicKeyData = SecKeyCopyExternalRepresentation(localDBPub, nil)! as Data

        // Separate vault key pair (simulates dedicated vault SE key)
        let vaultPriv = SecKeyCreateRandomKey(attrs, &err)!
        let vaultPub  = SecKeyCopyPublicKey(vaultPriv)!
        self.vaultPrivateKey    = vaultPriv
        self.vaultPublicKeyData = SecKeyCopyExternalRepresentation(vaultPub, nil)! as Data

        // Separate shard custody key pair (simulates dedicated shard custody SE key)
        let shardCustodyPriv = SecKeyCreateRandomKey(attrs, &err)!
        let shardCustodyPub  = SecKeyCopyPublicKey(shardCustodyPriv)!
        self.shardCustodyPrivateKey    = shardCustodyPriv
        self.shardCustodyPublicKeyData = SecKeyCopyExternalRepresentation(shardCustodyPub, nil)! as Data

        // Separate Secure Mode PIN key pair (simulates dedicated secureModePin SE key)
        let secureModePriv = SecKeyCreateRandomKey(attrs, &err)!
        let secureModePub  = SecKeyCopyPublicKey(secureModePriv)!
        self.secureModePrivateKey    = secureModePriv
        self.secureModePublicKeyData = SecKeyCopyExternalRepresentation(secureModePub, nil)! as Data

        // Tier secrets (simulate Keychain-stored random bytes)
        self.tierSecretU = Self.randomSecret()
        self.tierSecretB = Self.randomSecret()

        // Tier PQ records (simulate the Keychain items)
        self.tierPQRecordU = self.makeTierPQRecord()
        self.tierPQRecordB = self.makeTierPQRecord()
    }

    /// A key manager whose Enclave keys, tier secrets and tier PQ records are given, so a test can pin the bytes of
    /// every key it derives and notice when a derivation changes. `scalars` are, in order, the identity, local DB,
    /// vault, shard custody and Secure Mode PIN keys: five 32-byte P-256 private scalars.
    init(scalars: [Data], tierSecretU: Data?, tierSecretB: Data?, tierPQRecordU: TierPQRecord?, tierPQRecordB: TierPQRecord?) {
        precondition(scalars.count == 5)

        let identity     = Self.keyPair(scalar: scalars[0])
        let localDB      = Self.keyPair(scalar: scalars[1])
        let vault        = Self.keyPair(scalar: scalars[2])
        let shardCustody = Self.keyPair(scalar: scalars[3])
        let secureMode   = Self.keyPair(scalar: scalars[4])

        self.identityPrivateKey       = identity.privateKey
        self.identityPublicKeyData    = identity.publicKeyData
        self.localDBPrivateKey        = localDB.privateKey
        self.localDBPublicKeyData     = localDB.publicKeyData
        self.vaultPrivateKey          = vault.privateKey
        self.vaultPublicKeyData       = vault.publicKeyData
        self.shardCustodyPrivateKey   = shardCustody.privateKey
        self.shardCustodyPublicKeyData = shardCustody.publicKeyData
        self.secureModePrivateKey     = secureMode.privateKey
        self.secureModePublicKeyData  = secureMode.publicKeyData

        self.tierSecretU   = tierSecretU
        self.tierSecretB   = tierSecretB
        self.tierPQRecordU = tierPQRecordU
        self.tierPQRecordB = tierPQRecordB
    }

    private static func keyPair(scalar: Data) -> (privateKey: SecKey, publicKeyData: Data) {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256
        ]
        var err: Unmanaged<CFError>?
        let key = try! P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        let priv = SecKeyCreateWithData(key.x963Representation as CFData, attrs as CFDictionary, &err)!
        let pub  = SecKeyCopyPublicKey(priv)!
        return (priv, SecKeyCopyExternalRepresentation(pub, nil)! as Data)
    }

    func retrieveIdentity() throws -> Data { self.identityPublicKeyData }

    /// v1 — identity-derived local key. Used only for migration tests.
    func createLocalEncryptionKey() throws -> SymmetricKey? {
        self.deriveKey(
            privateKey: self.identityPrivateKey,
            ourPublicKeyData: self.identityPublicKeyData,
            peerMaterial: self.fixedX963,
            info: SaltInfo.kLocalDBKeyInfo
        )
    }

    /// Forces `deriveSecureModeKey()` to return nil.
    ///
    /// Exists for Bug 86's migration guard. That pass rewrites any element it cannot decrypt
    /// as fresh filler — filler being what changes size — so without a usable key every
    /// element looks like filler and all 32 entries of both blob-metadata arrays would be
    /// destroyed at once. Producing the nil is the only way to test that it aborts instead.
    var simulatesSecureModeKeyUnavailable = false

    /// Forces `createHybridLocalEncryptionKey()` to return nil, as the real key manager does
    /// with no Secure Enclave — so the fail-loud paths for a missing local DB key are testable
    /// on a host that has one.
    var simulatesLocalKeyUnavailable = false

    /// The local key, following the epoch as `Manager.Key` does: the Enclave-bound derivation when
    /// `Manager.Ambient.tierUKeys` says the data is under it, the legacy one otherwise.
    func createHybridLocalEncryptionKey() throws -> SymmetricKey? {
        try self.tierUKey(.localDB, legacy: .localDB)
    }

    /// Tier U's current key: legacy unless the epoch says otherwise, and always legacy under `derivesLegacyKeysOnly`.
    private func tierUKey(_ key: EnclaveBoundKey, legacy: LegacyKey) throws -> SymmetricKey? {
        if self.derivesLegacyKeysOnly { return try self.legacyKey(legacy) }

        switch Manager.Ambient.tierUKeys {
        case .legacy:       return try self.legacyKey(legacy)
        case .enclaveBound: return try self.enclaveBoundKey(key)
        }
    }

    // MARK: - Legacy keys (TestKeyManager)

    /// ECDH against G, as `Manager.Key.legacyKey(_:)`. The four protocol methods of the same names delegate here.
    func legacyKey(_ key: LegacyKey) throws -> SymmetricKey? {
        self.legacyKeyCalls += 1

        switch key {
        case .localDB:
            if self.simulatesLocalKeyUnavailable { return nil }
            guard
                let seComponent = self.deriveRawECDH(
                    privateKey: self.localDBPrivateKey,
                    peerMaterial: self.fixedX963
                )
            else { return nil }

            // Created on a miss, as `retrieveOrCreateRandomComponent` does. `enclaveBoundKey` never does.
            if self.tierSecretU == nil { self.tierSecretU = Self.randomSecret() }

            var ikm = Data(seComponent)
            ikm.append(self.tierSecretU!)

            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: ikm),
                salt: self.localDBPublicKeyData,
                info: SaltInfo.kLocalDBHybridKeyInfo,
                outputByteCount: 32
            )

        case .shardCustody:
            return try self.deriveCustodySEKey(info: SaltInfo.kShardCustodyKeyInfo)

        case .restoreVault:
            return try self.deriveCustodySEKey(info: SaltInfo.kRestoreVaultKeyInfo)

        case .vault:
            // The `context` is ignored in tests — no SE, no biometric evaluation.
            // `simulateVaultKeyFailure = true` makes this throw to test lock-on-failure.
            if self.simulateVaultKeyFailure { throw SimulatedFailure() }
            self.vaultKeyDerivations += 1

            guard let fixedPubKey = self.makePublicKey(from: self.fixedX963) else { return nil }

            var err: Unmanaged<CFError>?
            guard
                let rawSecret = SecKeyCopyKeyExchangeResult(
                    self.vaultPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                    [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                    &err
                ) as? Data
            else { return nil }

            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: rawSecret),
                salt: self.vaultPublicKeyData,
                info: SaltInfo.kVaultKeyInfo,
                outputByteCount: 32
            )
        }
    }

    // MARK: - Enclave-bound keys (TestKeyManager)

    /// ECDH against P, then HKDF over `t ‖ r` (classical record) or `t ‖ ss ‖ r` (hybrid record) — the software
    /// mirror of `Manager.Key.enclaveBoundKey(_:)`.
    /// nil when the tier secret or the tier PQ record is missing (nil) or `simulatesTierSecretMissing` is set,
    /// before anything else is derived, and nil for a hybrid record that won't decapsulate: never a classical key
    /// in its place. The vault and PIN switches apply as they do to the legacy keys.
    func enclaveBoundKey(_ key: EnclaveBoundKey) throws -> SymmetricKey? {
        if self.simulatesLockedDevice { throw SimulatedFailure() }
        if self.simulatesTierSecretMissing { return nil }

        switch key {
        case .localDB:
            if self.simulatesLocalKeyUnavailable { return nil }
            return self.enclaveBound(
                privateKey: self.localDBPrivateKey, publicKeyData: self.localDBPublicKeyData,
                secret: self.tierSecretU, record: self.tierPQRecordU,
                classicalInfo: SaltInfo.kLocalDBEnclaveBoundKeyInfo, hybridInfo: SaltInfo.kLocalDBEnclaveBoundPQKeyInfo
            )
        case .shardCustody:
            return self.enclaveBound(
                privateKey: self.shardCustodyPrivateKey, publicKeyData: self.shardCustodyPublicKeyData,
                secret: self.tierSecretU, record: self.tierPQRecordU,
                classicalInfo: SaltInfo.kShardCustodyEnclaveBoundKeyInfo, hybridInfo: SaltInfo.kShardCustodyEnclaveBoundPQKeyInfo
            )
        case .restoreVault:
            return self.enclaveBound(
                privateKey: self.shardCustodyPrivateKey, publicKeyData: self.shardCustodyPublicKeyData,
                secret: self.tierSecretU, record: self.tierPQRecordU,
                classicalInfo: SaltInfo.kRestoreVaultEnclaveBoundKeyInfo, hybridInfo: SaltInfo.kRestoreVaultEnclaveBoundPQKeyInfo
            )
        case .secureModeWrap:
            if self.simulatesSecureModeKeyUnavailable || self.simulatesWrapKeyUnavailable { return nil }
            return self.enclaveBound(
                privateKey: self.secureModePrivateKey, publicKeyData: self.secureModePublicKeyData,
                secret: self.tierSecretU, record: self.tierPQRecordU,
                classicalInfo: SaltInfo.kSecureModeWrapKeyInfo, hybridInfo: SaltInfo.kSecureModeWrapPQKeyInfo
            )
        case .vault:
            if self.simulateVaultKeyFailure { throw SimulatedFailure() }
            self.vaultKeyDerivations += 1
            return self.enclaveBound(
                privateKey: self.vaultPrivateKey, publicKeyData: self.vaultPublicKeyData,
                secret: self.tierSecretB, record: self.tierPQRecordB,
                classicalInfo: SaltInfo.kVaultEnclaveBoundKeyInfo, hybridInfo: SaltInfo.kVaultEnclaveBoundPQKeyInfo
            )
        }
    }

    /// The in-memory secret, or nil when there is none. Throws on a simulated locked device.
    func tierSecret(_ tier: TierSecret) throws -> Data? {
        if self.simulatesLockedDevice { throw SimulatedFailure() }

        switch tier {
        case .deviceUnlock: return self.tierSecretU
        case .biometry:     return self.tierSecretB
        }
    }

    /// The in-memory record, or nil when there is none. Throws on a simulated locked device.
    func tierPQRecord(_ tier: PostQuantumTier) throws -> TierPQRecord? {
        if self.simulatesLockedDevice { throw SimulatedFailure() }

        switch tier {
        case .deviceUnlock: return self.tierPQRecordU
        case .vault:        return self.tierPQRecordB
        }
    }

    /// Creates the in-memory secret if there is none. Returns whether it did.
    @discardableResult
    func createTierSecretIfAbsent(_ tier: TierSecret) throws -> Bool {
        switch tier {
        case .deviceUnlock:
            guard self.tierSecretU == nil else { return false }
            self.tierSecretU = Self.randomSecret()
        case .biometry:
            guard self.tierSecretB == nil else { return false }
            self.tierSecretB = Self.randomSecret()
        }
        return true
    }

    /// Creates the in-memory record if there is none: hybrid with an in-memory ML-KEM key, or classical when
    /// `simulatesNoPostQuantum` is set or the OS has no ML-KEM. Throws, creating nothing, if a provider exists and
    /// can't make the key. Returns whether it created one.
    @discardableResult
    func createTierPQRecordIfAbsent(_ tier: PostQuantumTier) throws -> Bool {
        switch tier {
        case .deviceUnlock:
            guard self.tierPQRecordU == nil else { return false }
            guard let record = self.makeTierPQRecord() else { throw SimulatedFailure() }
            self.tierPQRecordU = record
        case .vault:
            guard self.tierPQRecordB == nil else { return false }
            guard let record = self.makeTierPQRecord() else { throw SimulatedFailure() }
            self.tierPQRecordB = record
        }
        return true
    }

    func createSharedSecret(using material: Data?) -> SymmetricKey? {
        guard let material else { return nil }
        return self.deriveKey(
            privateKey: self.identityPrivateKey,
            ourPublicKeyData: self.identityPublicKeyData,
            peerMaterial: material,
            info: SaltInfo.kTransportKeyInfo
        )
    }

    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey? {
        guard
            let pub  = SecKeyCopyPublicKey(ephemeralPrivateKey),
            let data = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else { return nil }
        return self.deriveKey(
            privateKey: ephemeralPrivateKey,
            ourPublicKeyData: data,
            peerMaterial: recipientMaterial,
            info: SaltInfo.kTransportKeyInfo
        )
    }

    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)? {
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var err: Unmanaged<CFError>?
        guard
            let priv = SecKeyCreateRandomKey(attrs, &err),
            let pub  = SecKeyCopyPublicKey(priv),
            let data = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else { return nil }
        return (priv, data)
    }

    // MARK: - Vault (TestKeyManager)

    /// ECDH(vaultPrivateKey, G) → HKDF — mirrors Manager.Key.deriveVaultKey(context:).
    ///
    /// The `context` parameter is ignored in tests — no SE, no biometric evaluation.
    /// `simulateVaultKeyFailure = true` makes this throw to test lock-on-failure.
    func deriveVaultKey(context: LAContext) throws -> SymmetricKey? {
        try self.legacyKey(.vault(context))
    }

    // MARK: - Shard custody (TestKeyManager)

    /// ECDH(shardCustodyPrivateKey, G) → HKDF — mirrors Manager.Key.deriveShardCustodyKey().
    ///
    /// The context-free signature mirrors the real key (no biometric needed).
    func deriveShardCustodyKey() throws -> SymmetricKey? {
        try self.tierUKey(.shardCustody, legacy: .shardCustody)
    }

    /// ECDH(shardCustodyPrivateKey, G) → HKDF with restore-vault info.
    /// Mirrors Manager.Key.deriveRestoreVaultKey() — same SE key, distinct HKDF
    /// info, distinct symmetric key.
    func deriveRestoreVaultKey() throws -> SymmetricKey? {
        try self.tierUKey(.restoreVault, legacy: .restoreVault)
    }

    func deriveSecureModeKey() throws -> SymmetricKey? {
        if self.simulatesSecureModeKeyUnavailable { return nil }
        guard let fixedPubKey = makePublicKey(from: fixedX963) else { return nil }
        var err: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                secureModePrivateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
        else { return nil }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: secureModePublicKeyData,
            info: SaltInfo.kSecureModeKeyInfo,
            outputByteCount: 32
        )
    }

    /// Internal, not private, so a test can derive under a literal info string: the migration
    /// tests seal legacy rows exactly as v1.10.3 did (`bugs.md` Bug 137).
    func deriveCustodySEKey(info: Data) throws -> SymmetricKey? {
        guard let fixedPubKey = makePublicKey(from: fixedX963) else { return nil }

        var err: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                shardCustodyPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: shardCustodyPublicKeyData,
            info: info,
            outputByteCount: 32
        )
    }

    // MARK: - Identity challenge

    /// In-memory ECDSA-sign with the test identity private key.
    /// ⚠️ DO NOT PRE-HASH — `.ecdsaSignatureMessageX962SHA256` hashes internally.
    func signIdentityChallenge(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(
                self.identityPrivateKey,
                .ecdsaSignatureMessageX962SHA256,
                data as CFData,
                &error
            ) as Data?
        else { throw error!.takeRetainedValue() as Error }
        return signature
    }

    /// In-memory ECDSA-sign — mirrors Manager.Key.signData(_:).
    /// ⚠️ DO NOT pre-hash — `.ecdsaSignatureMessageX962SHA256` hashes internally.
    func signData(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let sig = SecKeyCreateSignature(
                identityPrivateKey,
                .ecdsaSignatureMessageX962SHA256,
                data as CFData,
                &error
            ) as Data?
        else { throw error!.takeRetainedValue() as Error }
        return sig
    }

    // MARK: - Private

    struct SimulatedFailure: Error {}

    private func makePublicKey(from data: Data) -> SecKey? {
        guard data.count == 65 else { return nil }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &err)
    }

    /// Raw 32-byte ECDH output without HKDF.
    private func deriveRawECDH(privateKey: SecKey, peerMaterial: Data) -> Data? {
        guard let peerKey = makePublicKey(from: peerMaterial) else { return nil }
        var err: Unmanaged<CFError>?
        return SecKeyCopyKeyExchangeResult(
            privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
            [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
            &err
        ) as? Data
    }

    /// The provider while the simulated OS has ML-KEM: nil below iOS 26 or with `simulatesNoPostQuantum`.
    private var activePostQuantum: (any PostQuantumProvider)? {
        self.simulatesNoPostQuantum ? nil : self.postQuantum
    }

    /// The record a device would create now: hybrid with a fresh in-memory key and a ciphertext to it, or classical
    /// when there is no provider. nil if a provider exists and the key can't be made.
    private func makeTierPQRecord() -> TierPQRecord? {
        guard let provider = self.activePostQuantum else { return .classical }

        guard
            let pair         = provider.generatePersistentKeyPair(),
            let encapsulated = provider.encapsulate(peerPublicKeyData: pair.publicKeyData)
        else { return nil }

        return try? TierPQRecord.hybrid(keyBlob: pair.keyBlob, ciphertext: encapsulated.ciphertext)
    }

    /// `HKDF(ECDH(privateKey, P) ‖ [ss ‖] secret, salt: the key's public point, info [‖ SHA-256(c)])`. nil without a
    /// secret or a record, and nil for a hybrid record the provider can't decapsulate.
    private func enclaveBound(
        privateKey: SecKey, publicKeyData: Data, secret: Data?, record: TierPQRecord?,
        classicalInfo: Data, hybridInfo: Data
    ) -> SymmetricKey? {
        guard let secret, let record else { return nil }

        var info        = classicalInfo
        var postQuantum = Data()

        switch record.mode {
        case .classical:
            break
        case .hybrid:
            guard
                let provider = self.activePostQuantum,
                let shared   = provider.decapsulate(ciphertext: record.ciphertext, keyBlob: record.keyBlob),
                shared.count == 32
            else { return nil }

            postQuantum = shared
            info        = hybridInfo + Data(SHA256.hash(data: record.ciphertext))
        }

        guard let exchange = self.deriveRawECDH(privateKey: privateKey, peerMaterial: self.numsX963) else { return nil }

        var ikm = exchange
        ikm.append(postQuantum)
        ikm.append(secret)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: publicKeyData,
            info: info,
            outputByteCount: 32
        )
    }

    private static func randomSecret() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        return Data(bytes)
    }

    private func deriveKey(privateKey: SecKey, ourPublicKeyData: Data, peerMaterial: Data, info: Data) -> SymmetricKey? {
        guard let rawSecret = deriveRawECDH(privateKey: privateKey, peerMaterial: peerMaterial) else { return nil }
        let salt = Data(zip(peerMaterial, ourPublicKeyData).map { $0 ^ $1 })
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }

    /// Raw ECDH + XOR salt without HKDF. Hybrid derivation combines ECDH with
    /// ML-KEM secrets before a single HKDF pass — running HKDF twice would produce the wrong key.
    ///
    /// Uses the identity key pair — same key `retrieveIdentity()` exposes and the same
    /// one `createSharedSecret(using:)` uses for the classical fallback path. Mirrors the
    /// real `Manager.Key.createHybridSharedSecret`, which does one ECDH via the SE identity key.
    private func rawECDHWithSalt(peerP256Material: Data) -> (rawECDH: Data, salt: Data)? {
        guard peerP256Material.count == 65 else { return nil }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var err: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(peerP256Material as CFData, attrs as CFDictionary, &err),
            let rawECDH = SecKeyCopyKeyExchangeResult(
                self.identityPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
        else { return nil }

        let salt = Data(zip(peerP256Material, self.identityPublicKeyData).map { $0 ^ $1 })
        return (rawECDH, salt)
    }
}

extension TestKeyManager {
    func createHybridSharedSecret(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial
    ) -> SymmetricKey? {
        guard let ecdh = self.rawECDHWithSalt(peerP256Material: peerP256Material) else { return nil }
        guard quantumMaterial.isValid else { return nil }

        let sorted = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }
        var ikm = ecdh.rawECDH
        ikm.append(contentsOf: sorted[0])
        ikm.append(contentsOf: sorted[1])

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: ecdh.salt,
            info: SaltInfo.kHybridTransportKeyInfo,
            outputByteCount: 32
        )
    }

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

        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var err: Unmanaged<CFError>?
        guard let peerKey = SecKeyCreateWithData(recipientMaterial as CFData, attrs as CFDictionary, &err) else {
            return nil
        }

        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(
                ephemeralPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &err
            ) as? Data
        else { return nil }

        let sorted = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }

        var ikm = rawECDH
        ikm.append(contentsOf: sorted[0])
        ikm.append(contentsOf: sorted[1])

        let salt = Data(zip(recipientMaterial, ephemeralPublicKeyData).map { $0 ^ $1 })

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: SaltInfo.kHybridFSTransportKeyInfo,
            outputByteCount: 32
        )
    }

    func createDicewareKey(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial,
        ourNonce: Data,
        peerNonce: Data
    ) -> SymmetricKey? {
        guard let ecdh = self.rawECDHWithSalt(peerP256Material: peerP256Material) else { return nil }
        guard quantumMaterial.isValid else { return nil }
        guard ourNonce.count == 16, peerNonce.count == 16 else { return nil }

        let sortedSecrets = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }
        var ikm = ecdh.rawECDH
        ikm.append(contentsOf: sortedSecrets[0])
        ikm.append(contentsOf: sortedSecrets[1])

        let sortedNonces = [ourNonce, peerNonce].sorted { $0.lexicographicallyPrecedes($1) }
        var info = SaltInfo.kDicewareKeyInfo
        info.append(contentsOf: sortedNonces[0])
        info.append(contentsOf: sortedNonces[1])

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: ecdh.salt,
            info: info,
            outputByteCount: 32
        )
    }

    func generateExchangeNonce() -> Data? {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        return Data(bytes)
    }
}
#endif
