//
//  Vault+Manager.swift
//  Occulta
//
//  @Observable vault lifecycle and AES-256-GCM CRUD.
//
//  Key design decisions:
//  - vaultKey is held in memory only; never stored to disk or Keychain.
//  - lock() is wired to UIApplication.didEnterBackgroundNotification here,
//    not in any view, so locking is guaranteed regardless of which view is
//    on screen when the app backgrounds.
//  - Plaintext never touches SwiftData. Every write encrypts first; every
//    read decrypts on demand.
//  - AAD = entry.aad() — see VaultEntry.aad() for the locked wire encoding.
//

import Foundation
import SwiftData
import CryptoKit
import UIKit

// MARK: - VaultManager

@Observable
final class VaultManager {

    // MARK: - Dependencies

    private let modelExecutor: any ModelExecutor
    private let modelContainer: ModelContainer
    private var modelContext: ModelContext { modelExecutor.modelContext }

    let keyManager: any KeyManagerProtocol

    // MARK: - Vault key

    /// Session vault key. Held in memory during an unlocked session.
    ///
    /// Zeroed on lock() by first overwriting with a zero-filled SymmetricKey,
    /// then setting to nil. SymmetricKey internals are not directly addressable
    /// in Swift, so the overwrite-then-nil pattern is best-effort: it ensures
    /// the property slot no longer holds a live reference before ARC can defer
    /// deallocation of the old storage to an arbitrary future point.
    private(set) var vaultKey: SymmetricKey?

    var isUnlocked: Bool { vaultKey != nil }

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
        keyManager: any KeyManagerProtocol = Manager.Key()
    ) {
        self.modelExecutor  = DefaultSerialModelExecutor(modelContext: ModelContext(modelContainer))
        self.modelContainer = modelContainer
        self.keyManager     = keyManager

        // Wire background lock at the manager level so no view needs to handle it.
        NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.lock()
        }
    }

    // MARK: - Unlock / lock

    /// Derive the vault key from the SE identity key and hold it in memory.
    ///
    /// Must be called before any encrypt or decrypt operation.
    /// On success, isUnlocked becomes true.
    func unlock() throws {
        guard let key = try keyManager.deriveVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        vaultKey = key
    }

    /// Zero the vault key and discard it.
    ///
    /// Called automatically on app background. Safe to call when already locked.
    func lock() {
        // Overwrite with zero-key before nil — see vaultKey documentation above.
        vaultKey = SymmetricKey(data: Data(repeating: 0, count: 32))
        vaultKey = nil
    }

    // MARK: - Create

    /// Encrypt `label` and `content` with the vault key, then persist the entry.
    ///
    /// The caller passes plaintext. This method encrypts before any write to
    /// SwiftData. Plaintext label is never stored or logged.
    ///
    /// - Returns: The persisted VaultEntry (fields are ciphertext).
    @discardableResult
    func addEntry(label: String, content: Data, type: VaultEntryType) throws -> VaultEntry {
        guard let key = vaultKey else { throw VaultError.locked }

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

        modelContext.insert(entry)
        try modelContext.save()

        return entry
    }

    // MARK: - Read

    func fetchAllEntries() throws -> [VaultEntry] {
        let descriptor = FetchDescriptor<VaultEntry>(sortBy: [SortDescriptor(\.createdAt)])
        return try modelContext.fetch(descriptor)
    }

    func fetchEntry(by id: UUID) throws -> VaultEntry? {
        let predicate = #Predicate<VaultEntry> { $0.id == id }
        return try modelContext.fetch(FetchDescriptor<VaultEntry>(predicate: predicate)).first
    }

    /// Decrypt and return the plaintext label for one entry.
    ///
    /// ⚠️ The returned String is plaintext. Do not persist or log it.
    /// Swift String is a value type; retain it only for the duration of display.
    func decryptLabel(for entry: VaultEntry) throws -> String {
        guard let key = vaultKey else { throw VaultError.locked }
        let plaintext = try openField(entry.encryptedLabel, key: key, aad: entry.aad())
        guard let label = String(data: plaintext, encoding: .utf8) else {
            throw VaultError.decryptionFailed
        }
        return label
    }

    /// Decrypt and return the plaintext content for one entry.
    ///
    /// ⚠️ Caller must zero this buffer after use — it contains the raw secret.
    func decryptContent(for entry: VaultEntry) throws -> Data {
        guard let key = vaultKey else { throw VaultError.locked }
        return try openField(entry.encryptedContent, key: key, aad: entry.aad())
    }

    // MARK: - Delete

    func deleteEntry(id: UUID) throws {
        guard let entry = try fetchEntry(by: id) else { throw VaultError.entryNotFound }
        modelContext.delete(entry)
        try modelContext.save()
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
}
