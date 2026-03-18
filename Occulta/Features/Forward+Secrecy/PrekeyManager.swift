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
    /// `"prekey.<sequence>.<uuid>"`. Public keys are returned as ``Prekey``
    /// structs (carrying their sequence number) for inclusion in outbound
    /// `PrekeySyncBatch` payloads.
    ///
    /// ## Sequence number
    /// A monotonically increasing integer, persisted in `UserDefaults`, that
    /// groups each generated batch. It serves two purposes:
    ///
    /// 1. **Replacement signal** — the recipient replaces their stored prekeys
    ///    when a batch with a higher sequence arrives, rather than appending.
    ///
    /// 2. **Pruning signal** — when sequence N is generated, all SE private keys
    ///    from sequences older than N-1 can be safely deleted. The recipient
    ///    either has batch N already (so N-1 is their fallback) or hasn't
    ///    received N yet (so N-1 is still current). Anything older is orphaned.
    ///
    /// ## Responsibilities
    /// - **Generation**: create batches, store private keys in SE, return public structs
    /// - **Retrieval**: look up a prekey private key by its full `Prekey` struct
    /// - **Consumption**: delete a used prekey private key immediately after decrypt
    /// - **Pruning**: delete SE keys from sequences older than current - 1
    /// - **Stock**: count remaining keys to trigger proactive replenishment
    class PrekeyManager {

        // MARK: - Constants

        static let defaultBatchSize      = 15
        static let replenishThreshold    = 5
        private static let sequenceKey   = "occulta.prekey.sequence"

        // MARK: - Sequence

        /// Current outbound sequence number, persisted across launches.
        ///
        /// Read before generating a batch. Incremented and saved after.
        var currentSequence: Int {
            get { UserDefaults.standard.integer(forKey: Self.sequenceKey) }
            set { UserDefaults.standard.set(newValue, forKey: Self.sequenceKey) }
        }

        // MARK: - Generation

        /// Generate a batch of prekey pairs for the current sequence.
        ///
        /// Each pair: private key stored in SE tagged `"prekey.<sequence>.<uuid>"`,
        /// public key returned in the ``Prekey`` struct.
        ///
        /// After generation, the sequence is incremented. Old SE keys from
        /// sequences older than `newSequence - 1` are pruned automatically.
        ///
        /// - Parameter count: Number of prekeys to generate. Defaults to 15.
        /// - Returns: Array of ``Prekey`` structs (public side + sequence).
        /// - Throws: If SE key creation fails.
        func generateBatch(count: Int = defaultBatchSize) throws -> [Prekey] {
            let seq = self.currentSequence
            var prekeys: [Prekey] = []

            for _ in 0..<count {
                let id  = UUID().uuidString
                let tag = Prekey.seTag(for: id, sequence: seq)

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
                    continue
                }

                prekeys.append(Prekey(id: id, sequence: seq, publicKey: publicKeyData))
            }

            // Increment sequence for the next batch.
            self.currentSequence = seq + 1

            // Prune SE keys from sequences older than seq - 1.
            // seq - 1 is kept as a safety buffer in case the recipient
            // hasn't received the new batch yet.
            if seq > 1 {
                self.pruneSequences(olderThan: seq - 1)
            }

            return prekeys
        }

        // MARK: - Retrieval

        /// Retrieve a prekey private key from the SE by its full ``Prekey`` struct.
        ///
        /// Returns `nil` — not an error — if the key was already consumed,
        /// pruned, or never existed. Callers should handle nil gracefully.
        ///
        /// - Parameter prekey: The ``Prekey`` whose private half to retrieve.
        /// - Returns: The SE `SecKey`, or `nil` if not found.
        func retrievePrivateKey(for prekey: Prekey) -> SecKey? {
            self.retrievePrivateKey(tag: prekey.seTag)
        }

        // MARK: - Consumption

        /// Delete a prekey private key from the SE immediately after use.
        ///
        /// This is the exact moment forward secrecy is established for a message.
        /// Once this returns, the session key used to encrypt that message can
        /// never be reconstructed — the private half no longer exists anywhere.
        ///
        /// - Parameter prekey: The ``Prekey`` whose private half to delete.
        /// - Returns: `true` if deleted or already absent.
        @discardableResult
        func consume(prekey: Prekey) -> Bool {
            self.deleteKey(tag: prekey.seTag)
        }

        // MARK: - Pruning

        /// Delete all SE private keys belonging to sequences strictly older than `threshold`.
        ///
        /// Called automatically after `generateBatch()` with `threshold = newSequence - 1`.
        /// Can also be called manually during identity reset or contact removal.
        ///
        /// - Parameter threshold: Delete keys with sequence < threshold.
        func pruneSequences(olderThan threshold: Int) {
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

            for item in allItems {
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tag     = String(data: tagData, encoding: .utf8),
                    tag.hasPrefix("prekey.")
                else { continue }

                // Tag format: "prekey.<sequence>.<uuid>"
                // Extract the sequence component.
                let components = tag.split(separator: ".", maxSplits: 2)
                guard
                    components.count == 3,
                    let seq = Int(components[1]),
                    seq < threshold
                else { continue }

                self.deleteKey(tag: tag)
            }
        }

        /// Delete all SE private keys for a specific sequence.
        ///
        /// Used during contact removal or identity reset.
        ///
        /// - Parameter sequence: The sequence whose keys to delete entirely.
        func deleteAllKeys(forSequence sequence: Int) {
            self.pruneSequences(olderThan: sequence + 1)
        }

        // MARK: - Stock

        /// Count remaining unconsumed prekey private keys in the SE.
        var remainingCount: Int {
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

            return allItems.filter { item in
                guard
                    let tagData = item[kSecAttrApplicationTag as String] as? Data,
                    let tag     = String(data: tagData, encoding: .utf8)
                else { return false }
                return tag.hasPrefix("prekey.")
            }.count
        }

        /// Whether a fresh batch should be generated before the next outbound message.
        var needsReplenishment: Bool {
            self.remainingCount < Self.replenishThreshold
        }

        // MARK: - Private helpers

        private func retrievePrivateKey(tag: String) -> SecKey? {
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
