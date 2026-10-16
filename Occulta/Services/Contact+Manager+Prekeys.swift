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
import OccultaFormats

/// How the next message to a contact will be sealed (prekey continuity D2).
enum NextSendSecrecy: Equatable {
    /// One of their one-time keys: opens once, then can't be opened from saved copies.
    case forwardSecret
    /// Only their last-resort key: opens again until it expires, 30 days or more after they move on.
    case temporaryKey
    /// The long-term keys of both sides, with no time limit.
    case longTerm
}

extension ContactManager {

    // MARK: - Load and store

    /// The prekey record between us and `contact`.
    ///
    /// Every row has one, written at creation or by `DatabaseMigration.migratePrekeyRecords`. A row without one is a
    /// row that pass hasn't reached, because it failed at launch, so its record is carried over from the retired
    /// field here, the same way. Reading it as empty would lose it: the first store would write a fresh record, and
    /// the pass, which leaves a row's new field alone, would then clear the old one. A row with neither is empty.
    ///
    /// An unreadable record starts over, as it did before stage 1: the keys we held for them and the
    /// batch we were delivering are lost, and the next long-term message from them restores both. Legacy keys
    /// may still exist for them, so the fresh record says so.
    func prekeyRecord(for contact: Contact.Profile) throws -> PrekeyRecord {
        guard let sealed = contact.prekeyRecordEncrypted else {
            return DatabaseMigration.carriedOverPrekeyRecord(from: contact.retiredForwardSecrecyEncrypted)
        }
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

    /// How the next message to `contact` will be sealed, as `encryptBundle` chooses: one of their one-time keys if
    /// we hold one; else their last-resort key, used only in the group format; else the long-term keys. Read by the
    /// compose indicator (D2). Per contact and never per depth, so a coerced duress session sees what any depth would.
    func nextSendSecrecy(for contact: Contact.Profile) -> NextSendSecrecy {
        guard let record = try? self.prekeyRecord(for: contact) else { return .longTerm }
        if !record.inboundBatches.isEmpty { return .forwardSecret }
        if record.inboundLastResort != nil,
           Self.resolveTargetVersion(for: contact, using: Manager.Crypto()).supportsGroups {
            return .temporaryKey
        }
        return .longTerm
    }

    /// The batch to attach to every message to the contact until they use a key from it, in wire form.
    func pendingBatchForWire(in record: PrekeyRecord) -> OccultaBundle.SealedPayload.PrekeySyncBatch? {
        PrekeyBookkeeper().pendingBatch(in: record, publicKeyOfBlob: Manager.PrekeySecretsManager.publicKey(ofBlob:)).map {
            OccultaBundle.SealedPayload.PrekeySyncBatch(
                generatedAt: $0.generatedAt, prekeys: $0.prekeys, id: $0.id, lastResort: $0.lastResort
            )
        }
    }

    // MARK: - Receiving

    /// The sender's prekeys for opening one inbound bundle, swept first, in memory. Writes nothing: what an
    /// unauthenticated file can reach by naming a contact must not cost a save and a flush. Using a key saves the
    /// record at once; a bundle that opens no one-time slot saves it at the end of the open (`save(_:for:)`).
    func senderPrekeys(for sender: Contact.Profile) throws -> SenderPrekeys {
        // The sweep on receipt (D1). Expired keys can't open this bundle, since the open uses the swept record.
        var record = try self.prekeyRecord(for: sender)
        let legacyKeysDue = PrekeyBookkeeper().sweep(&record, now: Date())
        return SenderPrekeys(record: record, legacyKeysDue: legacyKeysDue) { [weak self] prekeys in
            guard let self else { return }
            do {
                try self.save(prekeys, for: sender)
            } catch {
                // The change stays pending in the context, so the next save writes it. The open's own save at
                // the end retries, and throws if it fails again.
                #if DEBUG
                debugPrint("⚠️ A used prekey couldn't be saved out of the record — forward secrecy NOT established for this message: \(error)")
                #endif
            }
        }
    }

    /// Writes `prekeys`' record, with the sweep applied, and flushes the log. Legacy keychain keys that were due
    /// go first, so a failed save leaves the record saying they're retired and the unlock sweep deletes again.
    func save(_ prekeys: SenderPrekeys, for sender: Contact.Profile) throws {
        if prekeys.legacyKeysDue {
            Manager.PrekeySecretsManager().deleteAllKeys(for: sender.identifier)
            prekeys.legacyKeysDue = false
        }
        try self.store(prekeys.record, for: sender)
        try self.saveAndFlush()
    }

    /// Accepts a batch the sender attached, through the bookkeeper's rules (Bug 158). `used` is the key the bundle
    /// opened with: on the long-term keys or a last-resort key it can be opened again, so an old one replayed must
    /// not bring back a batch already used up (`PrekeyBookkeeper.accept`).
    func acceptInboundBatch(
        _ batch: OccultaBundle.SealedPayload.PrekeySyncBatch?, openedWith used: InboundPrekeyUse, into prekeys: SenderPrekeys
    ) throws {
        guard let batch else { return }
        do {
            _ = try PrekeyBookkeeper().accept(
                id: batch.id, generatedAt: batch.generatedAt, prekeys: batch.prekeys, lastResort: batch.lastResort,
                onReopenableSlot: used.consumable == nil, into: &prekeys.record
            )
        } catch PrekeyBookkeeper.BookkeeperError.malformedBatch {
            throw Errors.invalidPrekeySyncBatch
        }
    }

    /// A new batch if the bundle just opened shows the sender is out of our keys. Called after every check that can
    /// reject the bundle (Bug 159), so a rejected one never makes us issue keys.
    /// - Long-term: a sender holding no key of ours, when nothing is pending, as before stage 2.
    /// - A last-resort key: as `PrekeyBookkeeper.useLastResort` decides (§3.1's table; a repeat generates nothing).
    /// - A one-time key: once it leaves the sender holding `PrekeyBookkeeper.refillThreshold` of ours or fewer, with
    ///   nothing pending (§3.3, stage 4). Consuming it already applied its bookkeeping.
    func replenish(after used: InboundPrekeyUse, into prekeys: SenderPrekeys) throws {
        switch used {
        case .oneTime:
            guard PrekeyBookkeeper().needsRefill(prekeys.record) else { return }
        case .longTerm:
            guard !PrekeyBookkeeper().hasPendingBatch(prekeys.record) else { return }
        case .lastResort(let keyID):
            guard PrekeyBookkeeper().useLastResort(keyID: keyID, in: &prekeys.record, now: Date()) else { return }
        }
        try self.installFreshBatch(into: prekeys)
    }

    /// Generates a batch in the Enclave and makes it the pending one: the answer to a long-term bundle from a
    /// sender who has no batch of ours waiting. CryptoKit leaves no keychain item, so if anything later fails,
    /// nothing is left behind.
    func installFreshBatch(into prekeys: SenderPrekeys) throws {
        let batchSize = Manager.PrekeySecretsManager.defaultBatchSize
        // One more than the batch: the last-resort key (prekey continuity §3.1), the same kind of Enclave key.
        let blobs = try Manager.PrekeySecretsManager().generateEnclaveKeys(count: batchSize + 1)
        PrekeyBookkeeper().install(Array(blobs.prefix(batchSize)), lastResort: blobs[batchSize],
                                   into: &prekeys.record, now: Date())
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
/// `ContactManager` stores at the end. The sweep on receipt is applied to it in memory and saved with it. Using a
/// key applies the bookkeeper's rules (delivery of the pending batch, Bug 157; retirement of older batches and
/// legacy keys) and saves immediately, before anything can still reject the bundle (§2.2 of
/// `SECURITY_CHECKLIST.md`). Applying those rules on a bundle later rejected is the same fail-secure trade
/// `findAndOpenRecipientSlot` makes for consumption: only someone holding our batch can open a slot, and what
/// they can do with it is retire keys early.
final class SenderPrekeys: PrekeyPrivateKeys {

    var record: PrekeyRecord

    private let keychain   = Manager.PrekeySecretsManager()
    private let bookkeeper = PrekeyBookkeeper()
    private let persist: (SenderPrekeys) -> Void

    /// The sweep on receipt found the contact's legacy keychain keys past their grace period. They open nothing,
    /// and are deleted when the record is next saved.
    var legacyKeysDue: Bool

    init(record: PrekeyRecord, legacyKeysDue: Bool, persist: @escaping (SenderPrekeys) -> Void) {
        self.record        = record
        self.legacyKeysDue = legacyKeysDue
        self.persist       = persist
    }

    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey? {
        if let blob = self.bookkeeper.blob(forPrekeyID: prekeyID, in: self.record) {
            return (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)).map(PrekeyPrivateKey.enclave)
        }
        guard !self.legacyKeysDue else { return nil }
        return self.keychain.privateKey(forPrekeyID: prekeyID, contactID: contactID)
    }

    func lastResortKey(forPrekeyID prekeyID: String, ephemeralPublicKey: Data) -> (keyID: String, key: PrekeyPrivateKey)? {
        guard let (keyID, blob) = self.bookkeeper.lastResort(
                  matchingPrekeyID: prekeyID, ephemeralPublicKey: ephemeralPublicKey, in: self.record
              ),
              let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        else { return nil }
        return (keyID, .enclave(key))
    }

    func consume(prekeyID: String, contactID: String) {
        // A key the record holds no blob for is a legacy keychain key, deleted from the keychain as before.
        if self.bookkeeper.blob(forPrekeyID: prekeyID, in: self.record) == nil {
            self.keychain.consume(prekeyID: prekeyID, contactID: contactID)
        }
        self.bookkeeper.consume(prekeyID: prekeyID, in: &self.record, now: Date())
        self.persist(self)
    }
}
