//
//  Contact+Manager+Prekeys.swift
//  Occulta
//
//  ContactManager's side of prekey continuity stage 1: the only code that reads or writes a contact's
//  PrekeyRecord (`Docs/Features/Prekey Continuity/DESIGN.md` §8). The record's format is PrekeyRecordCodec's,
//  its rules PrekeyBookkeeper's, the Enclave work PrekeySecretsManager's; this file loads, stores and saves.
//

import Foundation
import CryptoKit
import SwiftData
import OccultaCore

extension ContactManager {

    // MARK: - Load and store

    /// The prekey record between us and `contact`.
    ///
    /// Every row has one, written at creation or by `DatabaseMigration.migratePrekeyRecords`; nil reads as empty.
    ///
    /// An unreadable record starts over, as it did before stage 1: the keys we held for them and the
    /// batch we were delivering are lost, and the next long-term message from them restores both. Legacy keys
    /// may still exist for them, so the fresh record says so.
    func prekeyRecord(for contact: Contact.Profile) throws -> PrekeyRecord {
        guard let sealed = contact.prekeyRecordEncrypted else { return .empty }
        guard let plaintext = sealed.decrypt() else {
            var fresh = PrekeyRecord.empty
            fresh.legacyKeys = .inUse
            return fresh
        }
        return try PrekeyRecordCodec().decode(plaintext)
    }

    /// Seals `record` into `contact`. Doesn't save; the caller does.
    func store(_ record: PrekeyRecord, for contact: Contact.Profile) throws {
        guard let sealed = try PrekeyRecordCodec().encode(record).encrypt() else {
            throw ForwardSecrecyError.encryptionFailed
        }
        contact.prekeyRecordEncrypted = sealed
    }

    // MARK: - Sending

    /// Whether the next message to `contact` can be forward secret. Read by the compose indicator.
    func hasPrekeyAvailable(for contact: Contact.Profile) -> Bool {
        (try? self.prekeyRecord(for: contact))?.inboundBatches.isEmpty == false
    }

    /// The batch to attach to every message to the contact until they use a key from it, in wire form.
    func pendingBatchForWire(in record: PrekeyRecord) -> OccultaBundle.SealedPayload.PrekeySyncBatch? {
        PrekeyBookkeeper().pendingBatch(in: record).map {
            OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: $0.generatedAt, prekeys: $0.prekeys, id: $0.id)
        }
    }

    // MARK: - Receiving

    /// The sender's prekeys for opening one inbound bundle, swept first. Using a key saves the record at once.
    func senderPrekeys(for sender: Contact.Profile) throws -> SenderPrekeys {
        // The sweep on receipt (D1). What it deletes is past its grace period, so it's saved and flushed at once,
        // as a used key is.
        if try self.sweepPrekeys(of: sender) { try self.saveAndFlush() }
        return SenderPrekeys(record: try self.prekeyRecord(for: sender)) { [weak self] record in
            guard let self else { return }
            do {
                try self.store(record, for: sender)
                try self.saveAndFlush()
            } catch {
                #if DEBUG
                debugPrint("⚠️ A used prekey couldn't be saved out of the record — forward secrecy NOT established for this message: \(error)")
                #endif
            }
        }
    }

    /// Accepts a batch the sender attached, through the bookkeeper's rules (Bug 158).
    func acceptInboundBatch(_ batch: OccultaBundle.SealedPayload.PrekeySyncBatch?, into prekeys: SenderPrekeys) throws {
        guard let batch else { return }
        do {
            _ = try PrekeyBookkeeper().accept(
                id: batch.id, generatedAt: batch.generatedAt, prekeys: batch.prekeys, into: &prekeys.record
            )
        } catch PrekeyBookkeeper.BookkeeperError.malformedBatch {
            throw Errors.invalidPrekeySyncBatch
        }
    }

    /// Generates a batch in the Enclave and makes it the pending one: the answer to a long-term bundle from a
    /// sender who has no batch of ours waiting. CryptoKit leaves no keychain item, so if anything later fails,
    /// nothing is left behind.
    func installFreshBatch(into prekeys: SenderPrekeys) throws {
        let keys = try Manager.PrekeySecretsManager().generateEnclaveKeys()
        PrekeyBookkeeper().install(keys, into: &prekeys.record, now: Date())
    }

    // MARK: - Sweep

    /// Deletes what the grace period no longer protects from `contact`'s record, and the contact's legacy keychain
    /// keys once they're due (D1, Bug 156). Doesn't save.
    ///
    /// - Returns: whether the record changed.
    @discardableResult
    func sweepPrekeys(of contact: Contact.Profile, now: Date = Date()) throws -> Bool {
        var record = try self.prekeyRecord(for: contact)
        let before = record
        if PrekeyBookkeeper().sweep(&record, now: now) {
            Manager.PrekeySecretsManager().deleteAllKeys(for: contact.identifier)
        }
        guard record != before else { return false }
        try self.store(record, for: contact)
        return true
    }

    /// The sweep at unlock, over the contacts visible at `depth`: the ones that depth can read once records are
    /// sealed per depth. Saves if anything changed; the caller flushes the log, as it does on every unlock.
    func sweepPrekeys(visibleAtDepth depth: Int, now: Date = Date()) throws {
        guard let key = try Manager.Ambient.keyManager.createHybridLocalEncryptionKey() else { return }
        var changed = false
        for contact in try self.fetchAllContacts() where contact.isVisible(atDepth: depth, usingKey: key) {
            changed = try self.sweepPrekeys(of: contact, now: now) || changed
        }
        if changed { try self.modelContext.save() }
    }

    /// `secure_delete` scrubs the freed page, but the write-ahead log still holds the previous record, deleted keys
    /// and all, until a checkpoint.
    private func saveAndFlush() throws {
        try self.modelContext.save()
        self.security.checkpointStore()
    }
}

/// A sender's prekeys while one inbound bundle is opened: the record first, then the keychain for legacy keys.
///
/// Holds the record for the whole open, so the inbound batch and any new batch land in the same record that
/// `ContactManager` stores at the end. Using a key applies the bookkeeper's rules (delivery of the pending batch,
/// Bug 157; retirement of older batches and legacy keys) and saves immediately, before anything can still reject
/// the bundle (§2.2 of `SECURITY_CHECKLIST.md`). Applying those rules on a bundle later rejected is the same
/// fail-secure trade `findAndOpenRecipientSlot` makes for consumption: only someone holding our batch can open
/// a slot, and what they can do with it is retire keys early.
final class SenderPrekeys: PrekeyPrivateKeys {

    var record: PrekeyRecord

    private let keychain   = Manager.PrekeySecretsManager()
    private let bookkeeper = PrekeyBookkeeper()
    private let persist: (PrekeyRecord) -> Void

    init(record: PrekeyRecord, persist: @escaping (PrekeyRecord) -> Void) {
        self.record  = record
        self.persist = persist
    }

    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey? {
        if let blob = self.bookkeeper.blob(forPrekeyID: prekeyID, in: self.record) {
            return (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)).map(PrekeyPrivateKey.enclave)
        }
        return self.keychain.privateKey(forPrekeyID: prekeyID, contactID: contactID)
    }

    func consume(prekeyID: String, contactID: String) {
        // A key the record holds no blob for is a legacy keychain key, deleted from the keychain as before.
        if self.bookkeeper.blob(forPrekeyID: prekeyID, in: self.record) == nil {
            self.keychain.consume(prekeyID: prekeyID, contactID: contactID)
        }
        self.bookkeeper.consume(prekeyID: prekeyID, in: &self.record, now: Date())
        self.persist(self.record)
    }
}
