//
//  ShareStagingKeyManager.swift
//  Occulta
//
//  SE key in shared access group + HKDF derivation + AES-GCM for share sessions: the
//  files and manifest the extension stages in the App Group for the main app to pick up.
//  Linked by both the main app and the share extension.
//
//  Formerly `ShareIndexKeyManager`. It first encrypted the share index, a mirror of the
//  contact list the extension used to draw its own recipient picker; that index was
//  deleted on 2026-08-16 and the key kept only this job. The key tag and HKDF label below
//  still say "share.index" because both are persisted: renaming the tag would orphan the
//  existing Enclave key, and renaming the label would change the derived key.
//
//  This is the ONLY crypto code the extension links. It never touches the identity key,
//  the local DB key or prekeys. Its one ML-KEM key is its own: the staging tier's, the third term of the
//  Enclave-bound key on iOS 26+ (`bugs.md` Bug 171). It is made and used here and nowhere else, through CryptoKit
//  directly, because the extension doesn't link `OccultaCore`; `StagingPostQuantum` below mirrors the persistent-key
//  methods of `PostQuantumProvider` for that reason.
//

import Foundation
import CryptoKit

final class ShareStagingKeyManager {

    // MARK: - Constants

    /// Unique SE key tag — never shared with any other key in the app. Keeps its original
    /// "share.index" name: the Enclave key is found by this tag, so changing it orphans the key.
    private static let tag = "share.index.se.key.occulta"

    /// App Group that both the main app and extension belong to.
    /// The SE key is created IN this group — not migrated.
    private static let accessGroup = "group.com.occulta.shared"

    /// Domain separator for HKDF. Unique to this key — never reuses an existing info string
    /// (kLocalDBKeyInfo, kTransportKeyInfo, etc.). Keeps its original "share-index" name: it
    /// is an input to the derivation, so changing it changes the key.
    private static let hkdfInfo = "Occulta-v1-share-index-2026".data(using: .utf8)!

    /// P-256 generator base point G (uncompressed x9.63, 65 bytes).
    /// Same constant used by Key+Manager for local DB key derivation.
    /// ECDH(privKey, G) produces a deterministic secret tied to the private key.
    private static let generatorG = Data([
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

    /// A nothing-up-my-sleeve P-256 point P, the peer of `deriveEnclaveBoundKey()`: nobody knows its discrete log,
    /// so ECDH(privKey, P) is a secret only the Enclave holding the key can compute. ECDH(privKey, G) is the key's
    /// public point, which is not (`bugs.md` Bug 171).
    ///
    /// Found by try-and-increment: x = SHA-256("Occulta-NUMS-P256-v1" ‖ be32(ctr)) for ctr = 0, 1, 2, …, taking the
    /// first x for which 0x02 ‖ x decompresses to a point. That is ctr = 1. Its own copy of `Manager.Key.numsX963`,
    /// as `generatorG` is of `fixedX963`: the extension links only this file. `NUMSPointTests` checks both against
    /// the seed. Internal and not private so that test can read it.
    static let numsX963 = Data([
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

    /// Domain separator of the Enclave-bound key: ECDH(privKey, P) ‖ r_S. Differs from `hkdfInfo`, which stays the
    /// legacy derivation's, so the two keys are never equivalent.
    private static let hkdfInfoEnclaveBound = "Occulta-v2-share-staging-2026".data(using: .utf8)!

    /// The same key when the staging tier's PQ record is hybrid (iOS 26+): ECDH(privKey, P) ‖ ss ‖ r_S, with this
    /// string followed by SHA-256(c) as the info.
    private static let hkdfInfoEnclaveBoundPQ = "Occulta-v2-share-staging-pq-2026".data(using: .utf8)!

    /// Keychain account of `r_S`, the staging tier's secret: a 32-byte generic-password item in the shared access
    /// group, `WhenUnlockedThisDeviceOnly`, read by the app and the extension alike.
    static let defaultTierSecretAccount = "share.staging.random.key.occulta"

    /// Keychain account of the staging tier's PQ record: one generic-password item in the shared access group,
    /// `WhenUnlockedThisDeviceOnly`, read by the app and the extension alike.
    static let defaultTierPQRecordAccount = "share.staging.pq.key.occulta"

    private let tierSecretAccount: String
    private let tierPQRecordAccount: String
    private let postQuantum: () -> (any StagingPostQuantum)?

    /// - Parameters:
    ///   - tierSecretAccount: The account of `r_S`. Only a test passes one, to use an item of its own and leave
    ///     the canonical `r_S` alone.
    ///   - tierPQRecordAccount: The account of the PQ record, likewise.
    ///   - postQuantum: The ML-KEM provider, asked for each time it is needed. The default is the Secure Enclave's
    ///     on iOS 26+ and nil below. A test passes an in-memory one, or `{ nil }` for a device below 26.
    init(
        tierSecretAccount: String = ShareStagingKeyManager.defaultTierSecretAccount,
        tierPQRecordAccount: String = ShareStagingKeyManager.defaultTierPQRecordAccount,
        postQuantum: @escaping () -> (any StagingPostQuantum)? = ShareStagingKeyManager.platformPostQuantum
    ) {
        self.tierSecretAccount   = tierSecretAccount
        self.tierPQRecordAccount = tierPQRecordAccount
        self.postQuantum         = postQuantum
    }

    // MARK: - SE Key Retrieval

    /// Retrieve the SE private key, creating it on first access.
    ///
    /// The access group in the query ensures we only find keys
    /// that belong to the shared group — never the identity key.
    private func retrievePrivateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: Self.accessGroup
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return item as! SecKey

        case errSecItemNotFound:
            item = nil
            try self.createKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                throw KeyError.creationFailed
            }
            return item as! SecKey

        default:
            throw KeyError.retrievalFailed
        }
    }

    /// Create a new P-256 key in the Secure Enclave with the shared access group.
    ///
    /// - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: not backed up, not synced
    /// - `.privateKeyUsage`: allows ECDH without additional authentication
    /// - `kSecAttrAccessGroup` in `kSecPrivateKeyAttrs`: places the key in the shared
    ///   group so both the main app and extension can derive the same symmetric key
    private func createKey() throws {
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
                kSecAttrApplicationTag: Self.tag.data(using: .utf8)!,
                kSecAttrAccessControl: access,
                kSecAttrAccessGroup: Self.accessGroup
            ]
        ]

        guard let _ = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }
    }

    // MARK: - SE Key Deletion

    /// Delete the SE key, the tier secret `r_S` and the PQ record. Erase All Data calls this after the staged files
    /// sealed under them.
    ///
    /// The key and its `kSecAttrCreationDate` record when the user first shared a file into
    /// Occulta, so an erased install must not keep them, and neither may `r_S` or the PQ record, which are dated the
    /// same way.
    /// The next access creates a fresh key. Matches the same items `retrievePrivateKey`, `tierSecret()` and `tierPQRecord()` find.
    /// A missing item counts as deleted.
    @discardableResult
    func deleteKey() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: Self.accessGroup
        ]
        let status = SecItemDelete(query as CFDictionary)

        let keyDeleted = status == errSecSuccess || status == errSecItemNotFound

        // Every deletion runs whatever an earlier one returned.
        let secretDeleted = self.deleteTierSecret()
        let recordDeleted = self.deleteTierPQRecord()

        return keyDeleted && secretDeleted && recordDeleted
    }

    /// Delete `r_S` alone. A missing item counts as deleted.
    @discardableResult
    func deleteTierSecret() -> Bool {
        let status = SecItemDelete(self.tierSecretQuery() as CFDictionary)

        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - Symmetric Key Derivation

    /// Derive the symmetric key for encrypting a share session's staged files and manifest.
    ///
    /// The legacy derivation (`bugs.md` Bug 171): ECDH against G is a function of the key's public point alone.
    /// What `encrypt` and `decrypt` use until Stage 5 moves them to `deriveEnclaveBoundKey()`.
    ///
    /// Both the main app and the extension call this and get the same key because
    /// they share access to the same SE private key via the access group.
    ///
    /// ```
    /// ECDH(shareStagingSEKey, G) → 32 bytes raw shared secret
    /// HKDF<SHA256>(
    ///   IKM:  raw ECDH secret (32 bytes)
    ///   Salt: shareStagingSEKey public key x963 (65 bytes)
    ///   Info: "Occulta-v1-share-index-2026"
    /// ) → 32 bytes → SymmetricKey (AES-256)
    /// ```
    ///
    /// Salt is the public key (not XOR) — differs from Key+Manager's local DB pattern
    /// because this key has no peer; the public key alone provides per-key uniqueness.
    func deriveLegacySymmetricKey() throws -> SymmetricKey {
        let privateKey = try self.retrievePrivateKey()

        guard let fixedPubKey = Self.convertToSecKey(Self.generatorG) else {
            throw KeyError.ecdhFailed
        }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { throw KeyError.ecdhFailed }

        guard
            let pubKey = SecKeyCopyPublicKey(privateKey),
            let pubData = SecKeyCopyExternalRepresentation(pubKey, nil) as Data?
        else { throw KeyError.publicKeyExportFailed }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: pubData,
            info: Self.hkdfInfo,
            outputByteCount: 32
        )
    }

    /// The Enclave-bound key: needs the Enclave key, the tier secret `r_S` and, on iOS 26+, the Enclave's ML-KEM
    /// secret, and the key's public point alone gives none of them. No caller uses it yet; Stage 5 moves `encrypt`
    /// to it.
    ///
    /// ```
    /// t = ECDH(shareStagingSEKey, P)                32 bytes
    /// HKDF<SHA256>(
    ///   IKM:  t ‖ r_S                               64 bytes, classical record
    ///         t ‖ ss ‖ r_S                          96 bytes, hybrid record (ss = decapsulate(c, blob))
    ///   Salt: shareStagingSEKey public key x963     65 bytes, as the legacy derivation
    ///   Info: "Occulta-v2-share-staging-2026"       classical
    ///         "Occulta-v2-share-staging-pq-2026" ‖ SHA-256(c)   hybrid
    /// ) → 32 bytes → SymmetricKey (AES-256)
    /// ```
    ///
    /// Reads `r_S` and the PQ record first and never creates either: a missing one throws before any Enclave key is
    /// fetched, let alone created. A hybrid record whose blob won't decapsulate throws `postQuantumFailed`, and so
    /// does one on a device with no ML-KEM; it is never read as classical.
    func deriveEnclaveBoundKey() throws -> SymmetricKey {
        guard let secret = try self.tierSecret() else { throw KeyError.tierSecretMissing }
        guard let record = try self.tierPQRecord() else { throw KeyError.tierPQRecordMissing }

        var hybridInput: (secret: Data, ciphertext: Data)?

        if record.mode == .hybrid {
            guard let provider = self.postQuantum() else { throw KeyError.postQuantumFailed }
            guard
                let shared = provider.decapsulate(ciphertext: record.ciphertext, keyBlob: record.keyBlob),
                shared.count == 32
            else { throw KeyError.postQuantumFailed }

            hybridInput = (shared, record.ciphertext)
        }

        let privateKey = try self.retrievePrivateKey()

        return try Self.enclaveBoundKey(exchangingWith: privateKey, secret: secret, postQuantum: hybridInput)
    }

    /// The derivation itself, for any P-256 private key reference: the Enclave key in production, a software key
    /// in a test that rebuilds it. `postQuantum` is the hybrid form's ML-KEM shared secret and the ciphertext it came
    /// from; nil derives the classical form.
    static func enclaveBoundKey(
        exchangingWith privateKey: SecKey,
        secret: Data,
        postQuantum: (secret: Data, ciphertext: Data)? = nil
    ) throws -> SymmetricKey {
        guard let peer = Self.convertToSecKey(Self.numsX963) else { throw KeyError.ecdhFailed }

        var error: Unmanaged<CFError>?
        guard
            let exchange = SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, peer,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { throw KeyError.ecdhFailed }

        guard
            let pubKey = SecKeyCopyPublicKey(privateKey),
            let pubData = SecKeyCopyExternalRepresentation(pubKey, nil) as Data?
        else { throw KeyError.publicKeyExportFailed }

        var ikm  = exchange
        var info = Self.hkdfInfoEnclaveBound

        if let postQuantum {
            ikm.append(postQuantum.secret)
            info = Self.hkdfInfoEnclaveBoundPQ
            info.append(Data(SHA256.hash(data: postQuantum.ciphertext)))
        }
        ikm.append(secret)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: pubData,
            info: info,
            outputByteCount: 32
        )
    }

    // MARK: - Tier secret r_S

    private func tierSecretQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: self.tierSecretAccount,
            kSecAttrAccessGroup as String: Self.accessGroup
        ]
    }

    /// `r_S`, or nil when the Keychain has no item for it, or one that isn't 32 bytes. Reads only. Throws for any
    /// other failure, such as a locked device: that is not a missing secret.
    func tierSecret() throws -> Data? {
        var query = self.tierSecretQuery()
        query[kSecReturnData as String] = true
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else { return nil }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeyError.retrievalFailed
        }
    }

    /// Creates `r_S` in the shared access group if there is none, and returns whether this call created it. Adds
    /// first and reads on `errSecDuplicateItem`, so the app and the extension racing to create it end with one
    /// secret. Never replaces an existing item.
    ///
    /// **Call it only while the tier has never been resealed, or on a fresh install**, with one exception the
    /// plan allows: staging holds nothing for longer than an hour, so a lost `r_S` costs only the sessions
    /// staged under it. Stage 5 decides who calls it.
    @discardableResult
    func createTierSecretIfAbsent() throws -> Bool {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw KeyError.creationFailed
        }

        var attributes = self.tierSecretQuery()
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecValueData as String] = Data(bytes)

        switch SecItemAdd(attributes as CFDictionary, nil) {
        case errSecSuccess:
            return true
        case errSecDuplicateItem:
            guard try self.tierSecret() != nil else { throw KeyError.retrievalFailed }
            return false
        default:
            throw KeyError.creationFailed
        }
    }

    // MARK: - Tier PQ record

    private func tierPQRecordQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: self.tierPQRecordAccount,
            kSecAttrAccessGroup as String: Self.accessGroup
        ]
    }

    /// The staging tier's PQ record, or nil when the Keychain has no item for it. Reads only. Throws for anything
    /// else: a locked device, and an item that isn't a record (one that won't read is not a missing one).
    func tierPQRecord() throws -> PQRecord? {
        var query = self.tierPQRecordQuery()
        query[kSecReturnData as String] = true
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data, let record = PQRecord(decoding: data) else {
                throw KeyError.tierPQRecordUnreadable
            }
            return record
        case errSecItemNotFound:
            return nil
        default:
            throw KeyError.retrievalFailed
        }
    }

    /// Creates the PQ record in the shared access group if there is none, and returns whether this call created it.
    /// Reads first, so an existing record costs no Enclave key; adds, and on `errSecDuplicateItem` reads what the
    /// other process added instead of replacing it, so the app and the extension racing end with one record.
    ///
    /// With an ML-KEM provider (iOS 26+) the record holds a real Enclave key and a ciphertext to it; without one it
    /// holds mode = classical and filler of the same size. A provider that can't make the key, or whose blob won't
    /// fit, throws and stores nothing: a classical record in its place would lower a device that could be hybrid.
    ///
    /// Unlike the U and B records, this one may be created if absent at any time, not only before a reseal: staging
    /// holds nothing for longer than an hour (`ShareSession.staleAfter`), so a record lost and recreated costs only
    /// the sessions staged under the old one, which can be shared again. Stage 5 decides who calls it.
    @discardableResult
    func createTierPQRecordIfAbsent() throws -> Bool {
        if try self.tierPQRecord() != nil { return false }

        let record: PQRecord
        if let provider = self.postQuantum() {
            guard
                let pair         = provider.generatePersistentKeyPair(),
                let encapsulated = provider.encapsulate(peerPublicKeyData: pair.publicKeyData),
                let hybrid       = PQRecord.hybrid(keyBlob: pair.keyBlob, ciphertext: encapsulated.ciphertext)
            else { throw KeyError.postQuantumUnavailable }
            record = hybrid
        } else {
            record = .classical
        }

        return try self.addTierPQRecord(record)
    }

    /// Adds `record`, or on `errSecDuplicateItem` leaves what is there and reads it. Returns whether this call added it.
    @discardableResult
    func addTierPQRecord(_ record: PQRecord) throws -> Bool {
        var attributes = self.tierPQRecordQuery()
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecValueData as String] = try record.encoded()

        switch SecItemAdd(attributes as CFDictionary, nil) {
        case errSecSuccess:
            return true
        case errSecDuplicateItem:
            guard try self.tierPQRecord() != nil else { throw KeyError.tierPQRecordUnreadable }
            return false
        default:
            throw KeyError.creationFailed
        }
    }

    /// Delete the PQ record alone. A missing item counts as deleted.
    @discardableResult
    func deleteTierPQRecord() -> Bool {
        let status = SecItemDelete(self.tierPQRecordQuery() as CFDictionary)

        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - AES-GCM Encrypt / Decrypt

    /// AES-256-GCM encrypt. Random 96-bit nonce per call.
    /// Output format: nonce ∥ ciphertext ∥ tag (CryptoKit `.combined`).
    func encrypt(data: Data) throws -> Data {
        let key = try self.deriveLegacySymmetricKey()
        let sealed = try AES.GCM.seal(data, using: key, nonce: AES.GCM.Nonce())
        guard let combined = sealed.combined else { throw KeyError.encryptionFailed }
        return combined
    }

    /// AES-256-GCM decrypt. Authenticates tag before returning plaintext.
    func decrypt(data: Data) throws -> Data {
        let key = try self.deriveLegacySymmetricKey()
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: key)
    }

    // MARK: - Helpers

    /// Convert 65-byte x9.63 public key data to a SecKey reference.
    /// Rejects any input that isn't exactly 65 bytes (uncompressed P-256).
    private static func convertToSecKey(_ data: Data) -> SecKey? {
        guard data.count == 65 else { return nil }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
    }

    enum KeyError: Error {
        case creationFailed
        case retrievalFailed
        case ecdhFailed
        case publicKeyExportFailed
        case encryptionFailed
        /// `deriveEnclaveBoundKey()` found no `r_S`.
        case tierSecretMissing
        /// `deriveEnclaveBoundKey()` found no PQ record.
        case tierPQRecordMissing
        /// The PQ record's item isn't a `PQRecord`: wrong size, an unknown mode, or an impossible blob length.
        case tierPQRecordUnreadable
        /// An ML-KEM provider exists but couldn't make the key, encapsulate to it, or fit its blob. Nothing was stored.
        case postQuantumUnavailable
        /// A hybrid record that can't be decapsulated: a corrupt blob or ciphertext, or no ML-KEM on this device.
        case postQuantumFailed
    }
}

// MARK: - Tier PQ record

extension ShareStagingKeyManager {

    /// The staging tier's PQ record: its own copy of `TierPQRecord`'s codec, byte for byte, because the extension
    /// links only this file. See `TierPQRecord.swift` for the layout and the sizes; `TierPQRecordTests` checks the
    /// two copies encode the same size and decode each other's records.
    nonisolated struct PQRecord: Equatable {

        enum Mode: UInt8 {
            case classical = 0
            case hybrid    = 1
        }

        /// Room for the Enclave key's `dataRepresentation`: 4,788 bytes measured on the Simulator, 8,192 reserved.
        static let blobCapacity = 8192
        static let ciphertextSize = 1568
        static let size = 1 + 2 + Self.blobCapacity + Self.ciphertextSize

        let mode: Mode
        let keyBlob: Data
        let ciphertext: Data

        static let classical = PQRecord(mode: .classical, keyBlob: Data(), ciphertext: Data())

        private init(mode: Mode, keyBlob: Data, ciphertext: Data) {
            self.mode       = mode
            self.keyBlob    = keyBlob
            self.ciphertext = ciphertext
        }

        /// nil if the blob is empty or doesn't fit, or the ciphertext isn't an ML-KEM-1024 one.
        static func hybrid(keyBlob: Data, ciphertext: Data) -> PQRecord? {
            guard !keyBlob.isEmpty, keyBlob.count <= Self.blobCapacity, ciphertext.count == Self.ciphertextSize else { return nil }

            return PQRecord(mode: .hybrid, keyBlob: keyBlob, ciphertext: ciphertext)
        }

        func encoded() throws -> Data {
            var out = Data(capacity: Self.size)
            out.append(self.mode.rawValue)

            switch self.mode {
            case .classical:
                out.append(try Self.randomBytes(Self.size - 1))
            case .hybrid:
                var length = UInt16(self.keyBlob.count).bigEndian
                withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
                out.append(self.keyBlob)
                out.append(try Self.randomBytes(Self.blobCapacity - self.keyBlob.count))
                out.append(self.ciphertext)
            }

            return out
        }

        init?(decoding data: Data) {
            guard data.count == Self.size, let first = data.first, let mode = Mode(rawValue: first) else { return nil }

            switch mode {
            case .classical:
                self.init(mode: .classical, keyBlob: Data(), ciphertext: Data())
            case .hybrid:
                let bytes  = [UInt8](data)
                let length = Int(bytes[1]) << 8 | Int(bytes[2])
                guard length > 0, length <= Self.blobCapacity else { return nil }

                self.init(
                    mode:       .hybrid,
                    keyBlob:    Data(bytes[3..<(3 + length)]),
                    ciphertext: Data(bytes[(Self.size - Self.ciphertextSize)...])
                )
            }
        }

        private static func randomBytes(_ count: Int) throws -> Data {
            var bytes = [UInt8](repeating: 0, count: count)
            guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
                throw KeyError.creationFailed
            }
            return Data(bytes)
        }
    }
}

// MARK: - ML-KEM for the staging tier

/// The ML-KEM-1024 operations the staging tier's record needs: `PostQuantumProvider`'s persistent-key methods, restated
/// here because the extension doesn't link `OccultaCore`. The Secure Enclave one is `platformPostQuantum`; a test
/// passes an in-memory one.
nonisolated protocol StagingPostQuantum {

    /// A key pair whose private key can be stored as bytes and used later, in another process lifetime. The blob is
    /// the Enclave key's `dataRepresentation`, usable only by this device's Enclave.
    func generatePersistentKeyPair() -> (publicKeyData: Data, keyBlob: Data)?

    /// Encapsulates to `peerPublicKeyData`. No Enclave involved.
    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)?

    /// The 32-byte shared secret, or nil if the blob or ciphertext is invalid.
    func decapsulate(ciphertext: Data, keyBlob: Data) -> Data?
}

extension ShareStagingKeyManager {

    /// The Secure Enclave's ML-KEM on iOS 26+, nil below.
    nonisolated static func platformPostQuantum() -> (any StagingPostQuantum)? {
        if #available(iOS 26, *) {
            return SecureEnclaveStagingPostQuantum()
        }
        return nil
    }
}

/// `SecureEnclave.MLKEM1024`, as `PostQuantumProvider` uses it for a key that outlives the call: `.privateKeyUsage`,
/// `WhenUnlockedThisDeviceOnly`, held only as its `dataRepresentation`.
@available(iOS 26, *)
private nonisolated final class SecureEnclaveStagingPostQuantum: StagingPostQuantum {

    func generatePersistentKeyPair() -> (publicKeyData: Data, keyBlob: Data)? {
        var error: Unmanaged<CFError>?
        guard
            let accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .privateKeyUsage,
                &error
            ),
            let privateKey = try? SecureEnclave.MLKEM1024.PrivateKey(accessControl: accessControl)
        else { return nil }

        return (privateKey.publicKey.rawRepresentation, privateKey.dataRepresentation)
    }

    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)? {
        guard
            let peerPublicKey = try? MLKEM1024.PublicKey(rawRepresentation: peerPublicKeyData),
            let result = try? peerPublicKey.encapsulate()
        else { return nil }

        return (result.sharedSecret.withUnsafeBytes { Data($0) }, result.encapsulated)
    }

    func decapsulate(ciphertext: Data, keyBlob: Data) -> Data? {
        guard
            let privateKey = try? SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: keyBlob),
            let sharedSecret = try? privateKey.decapsulate(ciphertext)
        else { return nil }

        return sharedSecret.withUnsafeBytes { Data($0) }
    }
}
