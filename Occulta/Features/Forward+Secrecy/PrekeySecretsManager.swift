//
//  PrekeySecretsManager.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation
import CryptoKit

extension Manager {
    /// Manages the full lifecycle of our own prekeys — the private side.
    ///
    /// All private keys are stored in the Secure Enclave tagged
    /// `"prekey.<contactID>.<uuid>"`.
    class PrekeySecretsManager {

        // MARK: - Constants

        static let defaultBatchSize   = 15

        // MARK: - Generation

        /// Generate prekeys as Enclave keys held by their wrapped blobs (`dataRepresentation`), for
        /// `PrekeyBookkeeper.install` to put into the contact's record (prekey continuity D9).
        ///
        /// CryptoKit creates no keychain item: the blob returned is the only copy, so the record holds the key
        /// and deleting it from the record deletes the key (`PrekeyGenerationMeasurementTests` asserts no item
        /// appears). Same access control as the keychain prekeys before them.
        ///
        /// Returns the blobs only: a public key is derived from its blob when needed (`publicKey(ofBlob:)`).
        ///
        /// - Throws: If the Enclave can't create a key. All or nothing, as with `generateBatch`.
        func generateEnclaveKeys(count: Int = PrekeySecretsManager.defaultBatchSize) throws -> [Data] {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error
            ) else {
                throw error!.takeRetainedValue() as Error
            }
            return try (0..<count).map { _ in
                try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access).dataRepresentation
            }
        }

        /// The X9.63 public key of a prekey held as an Enclave blob, or `nil` if the blob can't be loaded.
        nonisolated static func publicKey(ofBlob blob: Data) -> Data? {
            (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob))?.publicKey.x963Representation
        }

        /// Generate a batch of prekey pairs for a specific contact, as keychain items.
        ///
        /// How prekeys were stored before stage 1. Production now generates through `generateEnclaveKeys`;
        /// this stays so tests can create the legacy keychain prekeys that existing installs still hold and
        /// the receive path must still open until they retire.
        ///
        /// - Parameters:
        ///   - contactID:       Identifier of the contact this batch is for.
        ///                      Embedded in SE tags to isolate this contact's pool.
        ///   - count:           Number of prekeys to generate. Defaults to 15.
        /// - Returns:
        ///   - `prekeys`:      Generated ``Prekey`` structs (public side only).
        /// - Throws: If SE key creation fails.
        func generateBatch(contactID: String, count: Int = PrekeySecretsManager.defaultBatchSize) throws -> [Prekey] {
            var prekeys: [Prekey] = []

            for _ in 0..<count {
                let id  = UUID().uuidString
                let tag = Prekey.seTag(for: id, contactID: contactID)

                var error: Unmanaged<CFError>?

                guard
                    let access = SecAccessControlCreateWithFlags(
                        kCFAllocatorDefault,
                        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                        [.privateKeyUsage],
                        &error
                    )
                else {
                    throw error!.takeRetainedValue() as Error
                }

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

                guard
                    let privateKey    = SecKeyCreateRandomKey(attributes, &error),
                    let publicKey     = SecKeyCopyPublicKey(privateKey),
                    let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
                else {
                    // SE key creation failed for this iteration.
                    // Throw immediately — do not silently truncate the batch.
                    // A partial batch would prune old SE keys and increment the sequence
                    // while only providing the contact a fraction of the expected prekeys,
                    // potentially leaving them with zero keys after their existing store
                    // is replaced.
                    throw PrekeyError.seKeyCreationFailed
                }

                prekeys.append(Prekey(id: id, contactID: contactID, publicKey: publicKeyData))
            }

            return prekeys
        }

        // MARK: - Retrieval

        /// Retrieve a prekey private key from the SE by its full ``Prekey`` struct.
        ///
        /// Matches on the full `"prekey.<contactID>.<uuid>"` tag, not just the `uuid` —
        /// a prekey belonging to one contact must never resolve for a lookup claiming
        /// a different `contactID`, even if the `uuid` happens to be presented correctly.
        ///
        /// Returns `nil` if the key was already consumed, pruned, or never existed.
        func retrievePrivateKey(for prekey: Prekey) -> SecKey? {
            self.retrieveKey(tag: prekey.seTag)
        }

        // MARK: - Consumption

        /// Delete a prekey private key from the SE immediately after use.
        ///
        /// This is the exact moment forward secrecy is established for a message.
        /// Matches on the full `"prekey.<contactID>.<uuid>"` tag — see ``retrievePrivateKey(for:)``.
        ///
        /// The status is inspected here rather than at the call sites, which both discard the
        /// return value. A non-success means the private key is still in the Enclave and the
        /// message that just opened has no forward secrecy — the one thing this function exists
        /// to provide — so it must not pass unremarked.
        ///
        /// It stays best-effort in release, deliberately. By the time this runs the message is
        /// already decrypted, so throwing would discard a legitimate message to report a
        /// condition the user cannot act on, and a distinct user-visible error would be a new
        /// surface for no gain. There is nothing to retry either: the failure modes are the
        /// keychain being unavailable, which a second immediate call will not fix, and
        /// `errSecItemNotFound`, which means the key is already gone.
        @discardableResult
        func consume(prekey: Prekey) -> Int {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: prekey.seTag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
            let status = SecItemDelete(query as CFDictionary)

            #if DEBUG
            if status != errSecSuccess {
                debugPrint("⚠️ Prekey \(prekey.id) survived consume (OSStatus \(status)) — forward secrecy NOT established for this message")
            }
            #endif

            return status == errSecSuccess ? 1 : 0
        }

        /// Delete ALL SE private keys for a contact, regardless of sequence.
        ///
        /// Called when a contact is removed from the app.
        func deleteAllKeys(for contactID: String) {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]

            var items: CFTypeRef?
            guard
                SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess,
                let allItems = items as? [[String: Any]]
            else { return }

            let prefix = "prekey.\(contactID)."

            for item in allItems {
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tag     = String(data: tagData, encoding: .utf8),
                    tag.hasPrefix(prefix)
                else { continue }

                self.deleteKey(tag: tag)
            }
        }

        // MARK: - Stock

        /// Count remaining unconsumed prekey private keys in the SE for a contact.
        func remainingCount(for contactID: String) -> Int {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]

            var items: CFTypeRef?
            guard
                SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess,
                let allItems = items as? [[String: Any]]
            else { return 0 }

            let prefix = "prekey.\(contactID)."
            
            return allItems.filter { item in
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tag     = String(data: tagData, encoding: .utf8)
                else { return false }
                
                return tag.hasPrefix(prefix)
            }.count
        }
        
        private func findAllTags() -> [String] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]

            var items: CFTypeRef?
            guard
                SecItemCopyMatching(query as CFDictionary, &items) == errSecSuccess,
                let allItems = items as? [[String: Any]]
            else { return [] }

            let prefix = "prekey."
            let tags = allItems.compactMap { item -> String? in
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tag     = String(data: tagData, encoding: .utf8)
                else { return nil }
                
                return tag.contains(prefix) ? tag : nil
            }
            
            return tags
        }

        /// Delete ALL prekey private keys from the SE, across all contacts.
        func deleteAllKeys() {
            for tag in self.findAllTags() {
                self.deleteKey(tag: tag)
            }
        }

        // MARK: - Private helpers

        private func retrieveKey(tag: String) -> SecKey? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]

            var item: CFTypeRef?
            
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            let resultSuccess = status == errSecSuccess
            
            if resultSuccess == false {
                debugPrint("Could not retrieve private key to decrypt message.")
            }
            
            guard
                resultSuccess
            else {
                return nil
            }
            
            return (item as! SecKey)
        }

        @discardableResult
        private func deleteKey(tag: String) -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
            
            let status = SecItemDelete(query as CFDictionary)
            let result = status == errSecSuccess || status == errSecItemNotFound
            
            #if DEBUG
            debugPrint("Deleted key with tag = \(tag), result = \(result)")
            #endif
            
            return result
        }
        
    }
}

// MARK: - Finding and destroying a prekey's private half

/// One of our prekeys' private halves, as the receive path uses it.
enum PrekeyPrivateKey {
    /// A keychain item: every prekey from before stage 1.
    case keychain(SecKey)
    /// An Enclave key rebuilt from its blob in the contact's record (prekey continuity D9).
    case enclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
}

/// Where the receive path finds the private half of the prekey a bundle names, and destroys it once the bundle
/// opens. `Manager.Crypto` holds no database, so the caller supplies this: `ContactManager` passes one that reads
/// the sender's record first and the keychain second, and saves at once when a key is used.
protocol PrekeyPrivateKeys {
    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey?
    /// The last-resort key a derived `prekeyID` names, with its own ID (prekey continuity §3.1). It isn't consumed.
    func lastResortKey(forPrekeyID prekeyID: String, ephemeralPublicKey: Data) -> (keyID: String, key: PrekeyPrivateKey)?
    /// Destroys it. Called the moment the slot opens, before anything can still reject the bundle (§2.2 of
    /// `SECURITY_CHECKLIST.md`), so it doesn't throw: by then the key has done its work either way.
    func consume(prekeyID: String, contactID: String)
}

/// The keychain alone: what tests pass, and what holds every legacy prekey.
extension Manager.PrekeySecretsManager: PrekeyPrivateKeys {
    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey? {
        self.retrievePrivateKey(for: Prekey(id: prekeyID, contactID: contactID, publicKey: Data())).map(PrekeyPrivateKey.keychain)
    }

    func consume(prekeyID: String, contactID: String) {
        self.consume(prekey: Prekey(id: prekeyID, contactID: contactID, publicKey: Data()))
    }

    /// Last-resort keys live only in the record, never in the keychain.
    func lastResortKey(forPrekeyID prekeyID: String, ephemeralPublicKey: Data) -> (keyID: String, key: PrekeyPrivateKey)? {
        nil
    }
}

// MARK: - Errors

extension Manager.PrekeySecretsManager {
    enum PrekeyError: Error {
        /// `SecKeyCreateRandomKey` returned nil during batch generation.
        /// The SE may be temporarily unavailable or under resource pressure.
        case seKeyCreationFailed
    }
}
