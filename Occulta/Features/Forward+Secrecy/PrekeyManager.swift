//
//  Prekey+Manager.swift
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
    class PrekeyManager {

        // MARK: - Constants

        static let defaultBatchSize   = 15
        static let replenishThreshold = 5

        // MARK: - Generation

        /// Generate a batch of prekey pairs for a specific contact.
        ///
        ///
        ///
        /// - Parameters:
        ///   - contactID:       Identifier of the contact this batch is for.
        ///                      Embedded in SE tags to isolate this contact's pool.
        ///   - count:           Number of prekeys to generate. Defaults to 15.
        /// - Returns:
        ///   - `prekeys`:      Generated ``Prekey`` structs (public side only).
        /// - Throws: If SE key creation fails.
        func generateBatch(contactID: String, count: Int = PrekeyManager.defaultBatchSize) throws -> [Prekey] {
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
        /// Returns `nil` if the key was already consumed, pruned, or never existed.
        func retrievePrivateKey(for prekey: Prekey) -> SecKey? {
            self.retrieveSecKeysInSE(matching: prekey.id)
        }

        // MARK: - Consumption

        /// Delete a prekey private key from the SE immediately after use.
        ///
        /// This is the exact moment forward secrecy is established for a message.
        func consume(prekey: Prekey) {
            self.deleteSecKeysInSE(matchingTagSubstring: prekey.id)
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
        
        /// Returns all SecKey objects from the Secure Enclave whose Application Tag
        /// contains the given substring (case-insensitive).
        func retrieveSecKeysInSE(matching substring: String) -> SecKey? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecReturnAttributes as String: true,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll
            ]
            
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            
            guard
                status == errSecSuccess,
                let items = result as? [[String: Any]]
            else {
                if status != errSecItemNotFound {
                    print("SecItemCopyMatching failed: \(status)")
                }
                return nil
            }
            
            let filtered =  items.compactMap { item -> SecKey? in
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tagString = String(data: tagData, encoding: .utf8), tagString.hasSuffix(substring)
                else {
                    return nil
                }
                
                let key = item[kSecValueRef as String] as! SecKey
                
                return key
            }
            
            return filtered.first
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

        /// Whether a fresh batch should be generated for this contact.
        func needsReplenishment(for contactID: String) -> Bool {
            self.remainingCount(for: contactID) < Self.replenishThreshold
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
        
        /// Deletes all Secure Enclave SecKeys whose Application Tag contains the given substring.
        /// Returns the number of keys successfully deleted.
        @discardableResult
        private func deleteSecKeysInSE(matchingTagSubstring substring: String) -> Int {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll
            ]
            
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            
            guard status == errSecSuccess,
                  let items = result as? [[String: Any]] else {
                if status != errSecItemNotFound {
                    print("SecItemCopyMatching failed: \(status)")
                }
                return 0
            }
            
            var deletedCount = 0
            
            // Step 2: Filter + delete one by one
            
            for item in items {
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tagString = String(data: tagData, encoding: .utf8), tagString.hasSuffix(substring)
                else {
                    continue
                }
                
                // Step 3: Delete using the *exact* full tag (this is what makes deletion work)
                
                let deleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                    kSecAttrApplicationTag as String: tagData
                ]
                
                let delStatus = SecItemDelete(deleteQuery as CFDictionary)
                
                if delStatus == errSecSuccess {
                    deletedCount += 1
                    print("✅ Deleted key with tag: \(tagString)")
                } else {
                    print("⚠️ Failed to delete key '\(tagString)': \(delStatus)")
                }
            }
            
            return deletedCount
        }
    }
}

// MARK: - Errors

extension Manager.PrekeyManager {
    enum PrekeyError: Error {
        /// `SecKeyCreateRandomKey` returned nil during batch generation.
        /// The SE may be temporarily unavailable or under resource pressure.
        case seKeyCreationFailed
    }
}
