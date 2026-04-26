//
//  Vault+Manager.swift
//  Occulta
//
//  @Observable vault lifecycle and AES-256-GCM CRUD.
//
//  Key design decisions:
//  - authContext (LAContext) is held in memory; no key material is ever stored.
//  - The vault key is derived on the fly per-operation via ECDH(vault_SE_priv, G).
//    It exists only as a local SymmetricKey for the duration of each encrypt/decrypt call.
//  - Five lock triggers are wired in init — see Lock triggers section below.
//  - Plaintext never touches SwiftData. Every write encrypts first; every
//    read decrypts on demand.
//  - AAD = entry.aad() — see VaultEntry.aad() for the locked wire encoding.
//

import Foundation
import SwiftData
import CryptoKit
import UIKit
import LocalAuthentication

// MARK: - VaultManager

@Observable
final class VaultManager {

    // MARK: - Dependencies

    private let modelExecutor: any ModelExecutor
    private let modelContainer: ModelContainer
    // Internal (not private) so extensions in separate files (Vault+Manager+Shards.swift)
    // can call modelContext.save() and currentKey(). Swift private is file-scoped.
    var modelContext: ModelContext { modelExecutor.modelContext }

    let keyManager: any KeyManagerProtocol

    // MARK: - Auth context

    /// Evaluated LAContext from the most recent unlock(context:) call.
    /// Nil when locked. Passed to deriveVaultKey(context:) on every vault operation —
    /// the vault key is derived on the fly and never stored.
    private var authContext: LAContext?

    var isUnlocked: Bool { authContext != nil }

    // MARK: - Inactivity timer

    /// Inactivity timeout before automatic lock. Injected so tests can use short values.
    private let inactivityTimeout: TimeInterval

    @ObservationIgnored
    private var inactivityTimer: Timer?

    // MARK: - Errors

    enum VaultError: Error {
        case locked
        case keyDerivationFailed
        case entryNotFound
        case encryptionFailed
        case decryptionFailed
        case metadataCorrupted
    }

    // MARK: - Init

    init(
        modelContainer: ModelContainer,
        keyManager: any KeyManagerProtocol = Manager.Key(),
        inactivityTimeout: TimeInterval = 5 * 60
    ) {
        self.modelExecutor     = DefaultSerialModelExecutor(modelContext: ModelContext(modelContainer))
        self.modelContainer    = modelContainer
        self.keyManager        = keyManager
        self.inactivityTimeout = inactivityTimeout

        // ── Lock triggers (conditions 1–3) ───────────────────────────────────
        // Condition 1: app goes to background
        // Condition 2: device locks (OS about to encrypt protected data)
        // Condition 3: app loses active focus (incoming call, Control Center, banner)
        // Condition 4: inactivity — handled by inactivityTimer (resetInactivityTimer)
        // Condition 5: derivation failure — handled inside currentKey()
        let lockNames: [Notification.Name] = [
            UIApplication.didEnterBackgroundNotification,
            UIApplication.protectedDataWillBecomeUnavailableNotification,
            UIApplication.willResignActiveNotification
        ]
        for name in lockNames {
            NotificationCenter.default.addObserver(
                forName: name, object: nil, queue: .main
            ) { [weak self] _ in
                self?.lock()
            }
        }
    }

    // MARK: - Unlock / lock

    /// Store a pre-evaluated LAContext for the vault session.
    ///
    /// The caller (a view or coordinator) evaluates the biometric policy via
    /// LAContext.evaluatePolicy before calling unlock. VaultManager stores only
    /// the context reference — no key material is held.
    func unlock(context: LAContext) {
        self.authContext = context
        self.resetInactivityTimer()
        // Drain reconstruction buffer entries that crossed threshold while locked.
        self.tryFinalizeAllReconstructions()
    }

    /// Invalidate the auth context and cancel the inactivity timer.
    ///
    /// Called automatically on background, device lock, resign active, inactivity
    /// timeout, and vault key derivation failure. Safe to call when already locked.
    func lock() {
        self.inactivityTimer?.invalidate()
        self.inactivityTimer = nil
        self.authContext?.invalidate()
        self.authContext = nil
    }

    // MARK: - Create

    /// Encrypt `label` and `content` under a fresh per-entry key (PEK), then persist.
    ///
    /// Encryption model:
    ///   vault key → seal(PEK) → encryptedEntryKey
    ///   PEK       → seal(label)   → encryptedLabel
    ///   PEK       → seal(content) → encryptedContent
    ///
    /// The PEK is 32 cryptographically random bytes generated per entry.
    /// It never leaves this function in plaintext — zeroed in the defer block.
    ///
    /// - Returns: The persisted VaultEntry (all fields are ciphertext).
    @discardableResult
    func addEntry(label: String, content: Data, type: VaultEntryType) throws -> VaultEntry {
        let vaultKey = try self.currentKey()

        // Build entry first — id and createdAt must be fixed before AAD is computed.
        let entry = VaultEntry(type: type, encryptedLabel: Data(), encryptedContent: Data())
        let aad   = entry.aad()

        guard let labelData = label.data(using: .utf8) else { throw VaultError.encryptionFailed }

        // ── Generate PEK ─────────────────────────────────────────────────────
        var pekBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &pekBytes) == errSecSuccess else {
            throw VaultError.encryptionFailed
        }
        defer { for i in pekBytes.indices { pekBytes[i] = 0 } }

        let pek = SymmetricKey(data: Data(pekBytes))

        // ── Seal PEK under vault key ──────────────────────────────────────────
        let sealedKey = try AES.GCM.seal(Data(pekBytes), using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combinedKey = sealedKey.combined else { throw VaultError.encryptionFailed }

        // ── Encrypt label and content with PEK ────────────────────────────────
        let sealedLabel   = try AES.GCM.seal(labelData, using: pek, nonce: AES.GCM.Nonce(), authenticating: aad)
        let sealedContent = try AES.GCM.seal(content,   using: pek, nonce: AES.GCM.Nonce(), authenticating: aad)

        guard
            let combinedLabel   = sealedLabel.combined,
            let combinedContent = sealedContent.combined
        else { throw VaultError.encryptionFailed }

        entry.encryptedEntryKey = combinedKey
        entry.encryptedLabel    = combinedLabel
        entry.encryptedContent  = combinedContent

        self.modelContext.insert(entry)
        try self.modelContext.save()

        return entry
    }

    // MARK: - Read

    func fetchAllEntries() throws -> [VaultEntry] {
        let descriptor = FetchDescriptor<VaultEntry>(sortBy: [SortDescriptor(\.createdAt)])
        return try self.modelContext.fetch(descriptor)
    }

    func fetchEntry(by id: UUID) throws -> VaultEntry? {
        let predicate = #Predicate<VaultEntry> { $0.id == id }
        return try self.modelContext.fetch(FetchDescriptor<VaultEntry>(predicate: predicate)).first
    }

    /// Decrypt and return the plaintext label for one entry.
    ///
    /// ⚠️ The returned String is plaintext. Do not persist or log it.
    func decryptLabel(for entry: VaultEntry) throws -> String {
        let vaultKey  = try self.currentKey()
        let pek       = try self.unwrapPEK(for: entry, vaultKey: vaultKey)
        let plaintext = try self.openField(entry.encryptedLabel, key: pek, aad: entry.aad())
        guard let label = String(data: plaintext, encoding: .utf8) else {
            throw VaultError.decryptionFailed
        }
        return label
    }

    /// Decrypt and return the plaintext content for one entry.
    ///
    /// ⚠️ Caller must zero this buffer after use — it contains the raw secret.
    func decryptContent(for entry: VaultEntry) throws -> Data {
        let vaultKey = try self.currentKey()
        let pek      = try self.unwrapPEK(for: entry, vaultKey: vaultKey)
        return try self.openField(entry.encryptedContent, key: pek, aad: entry.aad())
    }

    // MARK: - Delete

    /// Delete a vault entry and return its shard distribution metadata, if any.
    ///
    /// The metadata is read before deletion so the caller can queue `.revoke`
    /// operations for each trustee. Returns `nil` when the entry had no
    /// distributed shards (no action needed from `ShardCustodyManager`).
    @discardableResult
    func deleteEntry(id: UUID) throws -> ShardDistributionMetadata? {
        guard let entry = try self.fetchEntry(by: id) else { throw VaultError.entryNotFound }

        let metadata = try? self.shardDistributionMetadata(for: id)

        self.modelContext.delete(entry)
        try self.modelContext.save()

        return metadata
    }

    // MARK: - Key access

    /// Derive the vault key on the fly using the cached LAContext.
    ///
    /// Resets the inactivity timer on success. On any derivation failure —
    /// covering invalidated context, biometric set change, device restart —
    /// calls lock() and throws .locked. This is lock condition 5.
    ///
    /// Internal (not private) so Vault+Manager+Shards.swift can access it.
    func currentKey() throws -> SymmetricKey {
        guard let ctx = self.authContext else { throw VaultError.locked }
        do {
            guard let key = try self.keyManager.deriveVaultKey(context: ctx) else {
                self.lock()
                
                throw VaultError.keyDerivationFailed
            }
            self.resetInactivityTimer()
            return key
        } catch let error as VaultError {
            throw error
        } catch {
            // SE refused — context invalidated, biometric set changed, device restarted.
            self.lock()
            throw VaultError.locked
        }
    }

    // MARK: - PEK unwrap

    /// Return the per-entry key (PEK) for `entry`, migrating legacy entries on first access.
    ///
    /// **PEK path (encryptedEntryKey non-empty):**
    ///   AES-GCM open(encryptedEntryKey, using: vaultKey, authenticating: entry.aad()) → PEK
    ///
    /// **Legacy path (encryptedEntryKey empty):**
    ///   Entry was written before the PEK layer existed. Decrypt label + content
    ///   with the vault key, generate a fresh PEK, re-encrypt both fields, seal
    ///   the PEK, and save — all transparently. Returns the new PEK so the caller
    ///   can complete its original operation without a second round-trip.
    ///
    ///   If the save fails, the entry remains in the legacy state and migration
    ///   retries on the next read. There is no half-migrated state.
    ///
    /// Internal (not private) so Vault+Manager+Shards.swift can call it.
    func unwrapPEK(for entry: VaultEntry, vaultKey: SymmetricKey) throws -> SymmetricKey {
        let aad = entry.aad()

        if !entry.encryptedEntryKey.isEmpty {
            // ── PEK path ─────────────────────────────────────────────────────
            let pekData = try self.openField(entry.encryptedEntryKey, key: vaultKey, aad: aad)
            guard pekData.count == 32 else { throw VaultError.decryptionFailed }
            return SymmetricKey(data: pekData)
        }

        // ── Legacy migration path ─────────────────────────────────────────────
        // 1. Decrypt both fields with the vault key (old path).
        let plainLabel   = try self.openField(entry.encryptedLabel,   key: vaultKey, aad: aad)
        let plainContent = try self.openField(entry.encryptedContent, key: vaultKey, aad: aad)

        // 2. Generate new PEK.
        var pekBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &pekBytes) == errSecSuccess else {
            throw VaultError.encryptionFailed
        }
        defer { for i in pekBytes.indices { pekBytes[i] = 0 } }

        let pek = SymmetricKey(data: Data(pekBytes))

        // 3. Re-encrypt under PEK.
        let sealedLabel   = try AES.GCM.seal(plainLabel,   using: pek, nonce: AES.GCM.Nonce(), authenticating: aad)
        let sealedContent = try AES.GCM.seal(plainContent, using: pek, nonce: AES.GCM.Nonce(), authenticating: aad)
        let sealedKey     = try AES.GCM.seal(Data(pekBytes), using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: aad)

        guard
            let combinedLabel   = sealedLabel.combined,
            let combinedContent = sealedContent.combined,
            let combinedKey     = sealedKey.combined
        else { throw VaultError.encryptionFailed }

        // 4. Persist — if save throws the entry stays legacy; retry on next read.
        entry.encryptedLabel    = combinedLabel
        entry.encryptedContent  = combinedContent
        entry.encryptedEntryKey = combinedKey
        try? self.modelContext.save()

        return pek
    }

    // MARK: - Private

    private func openField(_ combined: Data, key: SymmetricKey, aad: Data) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        do {
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw VaultError.decryptionFailed
        }
    }

    private func resetInactivityTimer() {
        self.inactivityTimer?.invalidate()
        self.inactivityTimer = Timer.scheduledTimer(
            withTimeInterval: self.inactivityTimeout,
            repeats: false
        ) { [weak self] _ in
            self?.lock()
        }
    }
}
