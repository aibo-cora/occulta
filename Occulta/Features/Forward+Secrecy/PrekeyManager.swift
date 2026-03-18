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
    /// All private keys are stored in the Secure Enclave tagged `"prekey.<uuid>"`.
    /// Public keys are handed back as ``Prekey`` structs for inclusion in outbound
    /// message bundles. The manager never holds private key material in memory beyond
    /// the scope of a single method call.
    ///
    /// ## Responsibilities
    /// - **Generation**: create batches of prekey pairs, SE private + public struct
    /// - **Retrieval**: look up a prekey private key by ID for decryption
    /// - **Consumption**: delete a prekey private key immediately after use
    /// - **Stock**: count remaining prekeys to trigger proactive replenishment
    class PrekeyManager {

        // MARK: - Constants

        /// Default number of prekeys to generate in a single batch.
        static let defaultBatchSize = 15

        /// Low-water mark — generate a new batch when stock falls below this.
        static let replenishThreshold = 5

        // MARK: - Generation

        /// Generate a batch of prekey pairs.
        ///
        /// Each pair: private key stored in SE (`kSecAttrIsPermanent: true`),
        /// public key returned in the ``Prekey`` struct for transmission.
        ///
        /// - Parameter count: Number of prekeys to generate. Defaults to 15.
        /// - Returns: Array of ``Prekey`` structs (public side only).
        /// - Throws: If SE key creation fails for any pair.
        func generateBatch(count: Int = defaultBatchSize) throws -> [Prekey] {
            var prekeys: [Prekey] = []

            for _ in 0..<count {
                // 1. Generate a temporary UUID — becomes the SE tag and Prekey.id.
                let id = UUID().uuidString
                let tag = Prekey.seTag(for: id)

                // 2. Create P-256 key pair in SE — permanent, device-only.
                var error: Unmanaged<CFError>?

                guard
                    let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error)
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
                    let privateKey = SecKeyCreateRandomKey(attributes, &error)
                else {
                    throw error!.takeRetainedValue() as Error
                }

                // 3. Extract the public key in x963 format.
                guard
                    let publicKey     = SecKeyCopyPublicKey(privateKey),
                    let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
                else {
                    continue
                }
                
                let prekey = Prekey(id: id, publicKey: publicKeyData)

                prekeys.append(prekey)
            }

            return prekeys
        }

        // MARK: - Retrieval

        /// Retrieve a prekey private key from the SE by its ID.
        ///
        /// Returns `nil` — not an error — if the key was already consumed or
        /// never existed. Callers should handle nil by attempting a long-term
        /// key fallback decrypt.
        ///
        /// - Parameter id: The prekey UUID matching `OccultaBundle.prekeyID`.
        /// - Returns: The SE `SecKey`, or `nil` if not found.
        func retrievePrivateKey(for id: String) -> SecKey? {
            let tag = Prekey.seTag(for: id)

            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            guard status == errSecSuccess else { return nil }

            return (item as! SecKey)
        }

        // MARK: - Consumption

        /// Delete a prekey private key from the SE immediately after use.
        ///
        /// This is the exact moment forward secrecy is established for a message.
        /// Once this call returns `true`, the session key used to encrypt that
        /// message can never be reconstructed — even if the identity key is later
        /// compromised — because the prekey private key no longer exists anywhere.
        ///
        /// Returning `false` is not an error — the key may have already been
        /// consumed (e.g. duplicate delivery). Callers can safely ignore `false`.
        ///
        /// - Parameter id: The prekey UUID to delete.
        /// - Returns: `true` if deleted, `false` if already absent.
        @discardableResult
        func consume(prekeyID id: String) -> Bool {
            let tag = Prekey.seTag(for: id)

            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!
            ]

            let status = SecItemDelete(query as CFDictionary)

            return status == errSecSuccess || status == errSecItemNotFound
        }

        // MARK: - Stock

        /// Count remaining unconsumed prekey private keys in the SE.
        ///
        /// Used before encryption to decide whether to generate a fresh batch.
        /// If the count is below ``replenishThreshold``, generate a new batch
        /// and include it in the outbound bundle.
        ///
        /// - Returns: Number of prekey entries currently in the SE.
        func remainingCount() -> Int {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]

            var items: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &items)

            guard
                status == errSecSuccess,
                let allItems = items as? [[String: Any]]
            else {
                return 0
            }

            // Filter to only prekey entries by tag prefix.
            return allItems.filter { item in
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tag = String(data: tagData, encoding: .utf8)
                else { return false }

                return tag.hasPrefix("prekey.")
            }.count
        }

        /// Whether a fresh batch should be generated before the next outbound message.
        var needsReplenishment: Bool {
            self.remainingCount() < Self.replenishThreshold
        }
    }
}

// MARK: - Prekey init with explicit id (internal)

fileprivate extension Prekey {
    init(id: String, publicKey: Data) {
        self.id = id
        self.publicKey = publicKey
    }
}
