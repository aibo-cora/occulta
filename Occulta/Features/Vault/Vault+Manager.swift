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

    /// Encrypt `label` and `content` with the vault key, then persist the entry.
    ///
    /// - Returns: The persisted VaultEntry (fields are ciphertext).
    @discardableResult
    func addEntry(label: String, content: Data, type: VaultEntryType) throws -> VaultEntry {
        let key   = try self.currentKey()

        // Build entry first to fix id and createdAt, which are required for AAD.
        let entry = VaultEntry(type: type, encryptedLabel: Data(), encryptedContent: Data())
        let aad   = entry.aad()

        guard let labelData = label.data(using: .utf8) else { throw VaultError.encryptionFailed }

        let sealedLabel   = try AES.GCM.seal(labelData, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
        let sealedContent = try AES.GCM.seal(content,   using: key, nonce: AES.GCM.Nonce(), authenticating: aad)

        guard
            let combinedLabel   = sealedLabel.combined,
            let combinedContent = sealedContent.combined
        else { throw VaultError.encryptionFailed }

        entry.encryptedLabel   = combinedLabel
        entry.encryptedContent = combinedContent

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
        let key       = try self.currentKey()
        let plaintext = try self.openField(entry.encryptedLabel, key: key, aad: entry.aad())
        guard let label = String(data: plaintext, encoding: .utf8) else {
            throw VaultError.decryptionFailed
        }
        return label
    }

    /// Decrypt and return the plaintext content for one entry.
    ///
    /// ⚠️ Caller must zero this buffer after use — it contains the raw secret.
    func decryptContent(for entry: VaultEntry) throws -> Data {
        let key = try self.currentKey()
        return try self.openField(entry.encryptedContent, key: key, aad: entry.aad())
    }

    // MARK: - Delete

    func deleteEntry(id: UUID) throws {
        guard let entry = try self.fetchEntry(by: id) else { throw VaultError.entryNotFound }
        
        self.modelContext.delete(entry)
        try self.modelContext.save()
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
