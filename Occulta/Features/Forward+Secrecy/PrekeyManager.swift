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
    /// `"prekey.<contactID>.<sequence>.<uuid>"`.
    ///
    /// This manager has no knowledge of SwiftData, Contact.Profile, or any
    /// persistent store. All inputs and outputs are raw primitives.
    /// The caller (ContactManager) is responsible for reading and writing
    /// model state before and after calling these methods.
    class PrekeyManager {

        // MARK: - Constants

        static let defaultBatchSize   = 15
        static let replenishThreshold = 5

        // MARK: - Generation

        /// Generate a batch of prekey pairs for a specific contact.
        ///
        /// The caller provides the contact's current sequence number and receives
        /// the incremented value back. The caller is responsible for persisting
        /// the new sequence on `Contact.Profile.outboundPrekeySequence`.
        ///
        /// After generation, SE private keys for this contact from sequences older
        /// than `currentSequence - 1` are pruned automatically.
        ///
        /// - Parameters:
        ///   - contactID:       Identifier of the contact this batch is for.
        ///                      Embedded in SE tags to isolate this contact's pool.
        ///   - currentSequence: The contact's current `outboundPrekeySequence`.
        ///   - count:           Number of prekeys to generate. Defaults to 15.
        /// - Returns:
        ///   - `prekeys`:      Generated ``Prekey`` structs (public side only).
        ///   - `nextSequence`: The incremented sequence. Caller writes this back
        ///                     to `Contact.Profile.outboundPrekeySequence`.
        /// - Throws: If SE key creation fails.
        func generateBatch(
            contactID: String,
            currentSequence: Int,
            count: Int = defaultBatchSize
        ) throws -> (prekeys: [Prekey], nextSequence: Int) {

            var prekeys: [Prekey] = []

            for _ in 0..<count {
                let id  = UUID().uuidString
                let tag = Prekey.seTag(for: id, contactID: contactID, sequence: currentSequence)

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

                prekeys.append(Prekey(
                    id:        id,
                    contactID: contactID,
                    sequence:  currentSequence,
                    publicKey: publicKeyData
                ))
            }

            // Prune SE keys for this contact from sequences older than currentSequence - 1.
            if currentSequence > 1 {
                self.pruneSequences(olderThan: currentSequence - 1, contactID: contactID)
            }

            return (prekeys, currentSequence + 1)
        }

        // MARK: - Retrieval

        /// Retrieve a prekey private key from the SE by its full ``Prekey`` struct.
        ///
        /// Returns `nil` if the key was already consumed, pruned, or never existed.
        func retrievePrivateKey(for prekey: Prekey) -> SecKey? {
            self.retrieveKey(tag: prekey.seTag)
        }

        // MARK: - Consumption

        /// Delete a prekey private key from the SE immediately after use.
        ///
        /// This is the exact moment forward secrecy is established for a message.
        @discardableResult
        func consume(prekey: Prekey) -> Bool {
            self.deleteKey(tag: prekey.seTag)
        }

        // MARK: - Pruning

        /// Delete all SE private keys for a contact from sequences strictly older than `threshold`.
        ///
        /// Scoped strictly to `contactID` — never touches other contacts' SE keys.
        ///
        /// - Parameters:
        ///   - threshold: Delete SE keys with sequence < threshold.
        ///   - contactID: Only delete keys belonging to this contact.
        func pruneSequences(olderThan threshold: Int, contactID: String) {
            guard threshold > 0 else { return }

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
                    let tagData   = item[kSecAttrApplicationTag as String] as? Data,
                    let tag       = String(data: tagData, encoding: .utf8),
                    tag.hasPrefix(prefix)
                else { continue }

                // Tag: "prekey.<contactID>.<sequence>.<uuid>"
                // Drop "prekey.<contactID>." prefix, parse sequence from remainder.
                let remainder  = String(tag.dropFirst(prefix.count))
                let components = remainder.split(separator: ".", maxSplits: 1)

                guard
                    components.count == 2,
                    let seq = Int(components[0]),
                    seq < threshold
                else { continue }

                self.deleteKey(tag: tag)
            }
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
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                return nil
            }
            return (item as! SecKey)
        }

        @discardableResult
        private func deleteKey(tag: String) -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!
            ]
            let status = SecItemDelete(query as CFDictionary)
            return status == errSecSuccess || status == errSecItemNotFound
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
