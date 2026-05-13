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
import Combine
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

    /// `true` when a pre-evaluated `LAContext` is held in memory (vault unlocked).
    /// Becomes `false` as soon as `lock()` clears `authContext`.
    var isUnlocked: Bool { authContext != nil }

    // MARK: - Recovery health

    /// Aggregate shard coverage across all distributed entries.
    /// `nil` when the vault is locked. Updated automatically on unlock and
    /// after every shard status mutation.
    var recoveryHealth: RecoveryHealthSummary? = nil

    /// BEK erosion state: non-nil when a BEK distribution exists and
    /// active (pending + confirmed) shards fall below threshold.
    /// `nil` when the vault is locked, no BEK is distributed, or coverage is met.
    var bekErosion: (active: Int, threshold: Int)? = nil

    // MARK: - Pending restore

    /// `true` while a `.occbak` file is stored locally awaiting BEK shard collection.
    /// Seeded from the filesystem on every unlock so it survives app restarts.
    var pendingRestoreActive: Bool = false

    /// Number of BEK restore shards collected so far. Updated on each shard arrival
    /// and on vault unlock. Drives the progress counter in the vault list.
    var pendingRestoreShardCount: Int = 0

    // MARK: - Backup staleness

    /// Non-nil when an export has been done on this device and the vault state has
    /// drifted from what was exported. `nil` when locked, or no export exists yet.
    /// Updated on every unlock and immediately after a successful export.
    var backupStaleness: BackupStalenessReport? = nil

    // MARK: - Inactivity timer

    /// Inactivity timeout before automatic lock. Injected so tests can use short values.
    private let inactivityTimeout: TimeInterval

    @ObservationIgnored
    private var inactivityTimer: Timer?

    @ObservationIgnored
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Errors

    enum VaultError: Error {
        /// Vault not unlocked — call `unlock(context:)` first.
        case locked
        /// SE returned `nil` during key derivation — device may have been restarted
        /// or the enrolled biometric set changed. `lock()` is called as a side effect.
        case keyDerivationFailed
        /// No `VaultEntry` with the requested UUID exists in the store.
        case entryNotFound
        /// `AES.GCM.seal` or `SecRandomCopyBytes` failed (device in a bad state).
        case encryptionFailed
        /// `AES.GCM.open` rejected the authentication tag — wrong key, corrupt
        /// ciphertext, or mismatched AAD.
        case decryptionFailed
        /// `ShardDistributionMetadata` could not be JSON-decoded after a successful
        /// `AES.GCM.open` — the plaintext is structurally invalid.
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
        for name in [
            UIApplication.didEnterBackgroundNotification,
            UIApplication.protectedDataWillBecomeUnavailableNotification,
            UIApplication.willResignActiveNotification
        ] {
            NotificationCenter.default.publisher(for: name)
                .receive(on: DispatchQueue.main)
                .sink { [weak self] _ in self?.lock() }
                .store(in: &self.cancellables)
        }

        // ── Auto-recompute on any ModelContext save ───────────────────────────
        // We don't discriminate which ModelContext caused the notification —
        // saves from other managers (ContactManager, ExchangeManager) may also
        // fire it while the vault is unlocked, but extra recomputes are harmless
        // since recomputeRecoveryHealth() exits cheaply when no shard data exists.
        // The guard on isUnlocked is for correctness: currentKey() would throw
        // when locked, and recoveryHealth/bekErosion are already nil from lock().
        NotificationCenter.default.publisher(for: ModelContext.didSave)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self, self.isUnlocked else { return }
                self.recomputeRecoveryHealth()
            }
            .store(in: &self.cancellables)
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
        // Replay shard status updates that arrived while locked, then check for losses.
        self.drainPendingShardStatusUpdates()
        self.drainPotentiallyLostShards()
        self.recomputeRecoveryHealth()
        self.refreshBackupStaleness()
        // Sync pending-restore state from filesystem and attempt reconstruction
        // if enough shards have arrived since the last unlock.
        self.refreshPendingRestoreState()
        self.attemptBEKRestore()
    }

    /// Invalidate the auth context and cancel the inactivity timer.
    ///
    /// Called automatically on background, device lock, resign active, inactivity
    /// timeout, and vault key derivation failure. Safe to call when already locked.
    func lock() {
        self.inactivityTimer?.invalidate()
        self.inactivityTimer = nil
        self.authContext?.invalidate()
        self.authContext     = nil
        self.recoveryHealth  = nil
        self.bekErosion      = nil
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
        let entry = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())

        // ── Generate PEK ─────────────────────────────────────────────────────
        var pekBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &pekBytes) == errSecSuccess else {
            throw VaultError.encryptionFailed
        }
        defer { for i in pekBytes.indices { pekBytes[i] = 0 } }

        let pek = SymmetricKey(data: Data(pekBytes))

        // ── Seal PEK under vault key ──────────────────────────────────────────
        let sealedKey = try AES.GCM.seal(
            Data(pekBytes), using: vaultKey, nonce: AES.GCM.Nonce(),
            authenticating: entry.aad(for: .entryKey)
        )
        guard let combinedKey = sealedKey.combined else { throw VaultError.encryptionFailed }

        // ── Encrypt label payload (type + label) and content with PEK ─────────
        let labelPayload = SealedLabelPayload(type: type, label: label)
        let labelData    = try JSONEncoder().encode(labelPayload)

        let sealedLabel   = try AES.GCM.seal(labelData, using: pek, nonce: AES.GCM.Nonce(),
                                              authenticating: entry.aad(for: .label))
        let sealedContent = try AES.GCM.seal(content,    using: pek, nonce: AES.GCM.Nonce(),
                                              authenticating: entry.aad(for: .content))

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

    /// Return all vault entries sorted by creation date (oldest first).
    ///
    /// All fields on the returned entries are ciphertext — no decryption occurs here.
    func fetchAllEntries() throws -> [VaultEntry] {
        let descriptor = FetchDescriptor<VaultEntry>(sortBy: [SortDescriptor(\.createdAt)])
        return try self.modelContext.fetch(descriptor)
    }

    func deleteAllEntries() throws {
        let entries = try fetchAllEntries()
        for entry in entries { modelContext.delete(entry) }
        try modelContext.save()
    }

    /// Find a single vault entry by its UUID.
    ///
    /// - Returns: The matching `VaultEntry`, or `nil` if none exists.
    func fetchEntry(by id: UUID) throws -> VaultEntry? {
        let predicate = #Predicate<VaultEntry> { $0.id == id }
        return try self.modelContext.fetch(FetchDescriptor<VaultEntry>(predicate: predicate)).first
    }

    /// Decrypt the sealed label payload (type + label string) for one entry.
    ///
    /// Internal visibility so `Vault+Manager+Shards.swift` can call it from
    /// `recomputeRecoveryHealth` without double-decrypting.
    ///
    /// ⚠️ The returned payload is plaintext. Do not persist or log it.
    func decryptLabelPayload(for entry: VaultEntry) throws -> SealedLabelPayload {
        let vaultKey  = try self.currentKey()
        let pek       = try self.unwrapPEK(for: entry, vaultKey: vaultKey)
        let plaintext = try self.openField(entry.encryptedLabel, key: pek, aad: entry.aad(for: .label))
        do {
            return try JSONDecoder().decode(SealedLabelPayload.self, from: plaintext)
        } catch {
            throw VaultError.decryptionFailed
        }
    }

    /// Decrypt and return the plaintext label for one entry.
    ///
    /// ⚠️ The returned String is plaintext. Do not persist or log it.
    func decryptLabel(for entry: VaultEntry) throws -> String {
        try self.decryptLabelPayload(for: entry).label
    }

    /// Decrypt and return the entry type for one entry.
    func decryptEntryType(for entry: VaultEntry) throws -> VaultEntryType {
        try self.decryptLabelPayload(for: entry).type
    }

    /// Decrypt and return the plaintext content for one entry.
    ///
    /// ⚠️ Caller must zero this buffer after use — it contains the raw secret.
    func decryptContent(for entry: VaultEntry) throws -> Data {
        let vaultKey = try self.currentKey()
        let pek      = try self.unwrapPEK(for: entry, vaultKey: vaultKey)
        return try self.openField(entry.encryptedContent, key: pek, aad: entry.aad(for: .content))
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

    /// Return the per-entry key (PEK) for `entry`.
    ///
    /// AES-GCM open(encryptedEntryKey, using: vaultKey, authenticating: entry.aad(for: .entryKey)) → PEK
    ///
    /// Internal (not private) so Vault+Manager+Shards.swift can call it.
    func unwrapPEK(for entry: VaultEntry, vaultKey: SymmetricKey) throws -> SymmetricKey {
        let pekData = try self.openField(entry.encryptedEntryKey, key: vaultKey,
                                         aad: entry.aad(for: .entryKey))
        guard pekData.count == 32 else { throw VaultError.decryptionFailed }
        return SymmetricKey(data: pekData)
    }

    // MARK: - Private

    /// AES-GCM open a combined-format ciphertext (`nonce ∥ ciphertext ∥ tag`).
    ///
    /// Wraps any `AES.GCM.open` failure in `.decryptionFailed` so callers receive
    /// a uniform vault error regardless of the underlying `CryptoKit` error type.
    private func openField(_ combined: Data, key: SymmetricKey, aad: Data) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        do {
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw VaultError.decryptionFailed
        }
    }

    /// Reset the inactivity timer, extending the session by `inactivityTimeout` from now.
    ///
    /// Called on every successful vault key derivation so idle time is measured from
    /// the last cryptographic operation, not from the initial `unlock(context:)` call.
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
