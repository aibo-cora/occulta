//
//  Contact+Model+Prekeys.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation
import SwiftData
import CryptoKit

// MARK: - Prekey storage and sender identification on Contact.Profile

extension Contact.Profile {
    /// Init an empty object that we can change as we start using Forward Secrecy.
    func configureForwardSecrecy() throws {
        if let _ = self.forwardSecrecyEncrypted {
            return
        } else {
            let secrecy = ForwardSecrecy()
            
            try self.update(secrecy: secrecy)
        }
    }
    /// Decrypting forward secrecy struct.
    var plainTextForwardSecrecy: ForwardSecrecy? {
        get throws {
            guard
                let forwardSecrecyEncrypted,
                let decrypted = forwardSecrecyEncrypted.decrypt()
            else {
                return nil
            }
            
            let secrecy = try JSONDecoder().decode(ForwardSecrecy.self, from: decrypted)
            
            return secrecy
        }
    }
    /// Encrypting forward secrecy and updating it for a contact.
    private func update(secrecy: ForwardSecrecy) throws {
        let encoded = try JSONEncoder().encode(secrecy)
        let encrypted = try encoded.encrypt()
        
        self.forwardSecrecyEncrypted = encrypted
    }
    
    // MARK: - Inbound prekeys (their keys, for encrypting TO them)

    /// Remove and return the oldest inbound prekey blob (FIFO).
    ///
    /// Returns nil when exhausted — caller falls back to long-term path
    /// and should have a pending batch ready to attach.
    func popOldestPrekeyData() throws -> Data? {
        guard
            var secrecy = try self.plainTextForwardSecrecy,
            var current = secrecy.encodedPrekeys, !current.isEmpty
        else {
            debugPrint("popping error: no prekeys available")
            
            return nil
        }
        
        let oldest = current.removeFirst()
        
        secrecy.encodedPrekeys = current.isEmpty ? nil : current
        
        debugPrint("popping success: popped one, remaining: \(current.count)")
        
        try self.update(secrecy: secrecy)
        
        return oldest
    }

    /// Replace the inbound prekey store with a new batch.
    ///
    /// Accepted only when `date > latestPrekeysGeneratedAt` — rejects duplicate
    /// and stale deliveries. A new batch legitimately arrives only after the sender
    /// exhausted the previous one, so the store is empty by then. Direct replace
    /// is always correct; append would accumulate stale keys from prior batches.
    ///
    /// - Parameters:
    ///   - blobs: JSON-encoded `Prekey` blobs from the incoming batch.
    ///   - date:  `PrekeySyncBatch.generatedAt` — when the sender created this batch.
    func syncInboundPrekeys(_ blobs: [Data], date: Date) throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        debugPrint("Synching incoming prekeys...")
        debugPrint("Current prekeys count: \(secrecy.encodedPrekeys?.count ?? 0)")
        
        guard
            date > (secrecy.latestPrekeysGeneratedAt ?? .distantPast)
        else {
            debugPrint("Received an older batch of prekeys, exiting sync...")
            
            return
        }

        secrecy.encodedPrekeys = blobs
        secrecy.latestPrekeysGeneratedAt = date
        
        try self.update(secrecy: secrecy)
    }

    // MARK: - Pending outbound batch

    /// Called when a new batch is generated. The batch rides every subsequent
    /// outbound message until `clearPendingBatch` is called.
    /// - Parameters:
    ///   - batch:Ppending outbound batch for this contact.
    ///   - sequence: New sequence #.
    func store(batch: OccultaBundle.SealedPayload.PrekeySyncBatch) throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        
        let encoded = try JSONEncoder().encode(batch)
        
        secrecy.pendingOutboundBatch = encoded
        
        try self.update(secrecy: secrecy)
        
        debugPrint("Stored new batch of prekeys: \(batch.prekeys.count), date: \(String(describing: batch.generatedAt))")
    }

    /// Return the pending outbound batch, or nil if none is waiting.
    func loadPendingBatch() throws -> OccultaBundle.SealedPayload.PrekeySyncBatch? {
        guard
            let secrecy = try self.plainTextForwardSecrecy,
            let encoded = secrecy.pendingOutboundBatch
        else {
            return nil
        }
        
        let batch = try JSONDecoder().decode(OccultaBundle.SealedPayload.PrekeySyncBatch.self, from: encoded)
        
        return batch
    }

    /// Clear the pending outbound batch.
    ///
    /// Called when we receive cryptographic proof that the contact received
    /// our batch — i.e., when `removeOwnPrekeyData` fires (they used one of
    /// our prekeys to encrypt a message back to us).
    func clearPendingBatch() throws {
        guard
            var secrecy = try self.plainTextForwardSecrecy
        else {
            return
        }
        
        secrecy.pendingOutboundBatch = nil
        
        try self.update(secrecy: secrecy)
    }

    /// Whether a batch is currently waiting for delivery confirmation.
    var hasPendingBatch: Bool {
        let secrecy = try? self.plainTextForwardSecrecy
        
        return secrecy?.pendingOutboundBatch != nil
    }

    // MARK: - Stock

    var availableInboundPrekeyCount: Int  {
        let secrecy = try? self.plainTextForwardSecrecy
        
        return secrecy?.encodedPrekeys?.count ?? 0
    }
    
    var hasPrekeyAvailable: Bool {
        self.availableInboundPrekeyCount > 0
    }

    // MARK: - Sender identification

    /// SHA-256(contactPublicKey || bundle.fingerprintNonce) == bundle.senderFingerprint.
    /// O(1) per contact — no trial ECDH.
    func isLikelySender(of bundle: OccultaBundle, contactPublicKey: Data) -> Bool {
        let candidate = OccultaBundle.SecrecyContext.fingerprint(for: contactPublicKey, nonce: bundle.fingerprintNonce)
        
        return candidate == bundle.senderFingerprint
    }
}
