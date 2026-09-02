//
//  PrekeyConsumptionOnRejectionTests.swift
//  OccultaTests
//
//  §2.2 — a prekey must not survive a bundle that opened and was then rejected.
//
//  These need a real Secure Enclave: prekey private keys are SE-backed and
//  `findAndOpenRecipientSlot` takes the concrete `Manager.PrekeyManager`, so there is no
//  injection seam to prefer over gating (see CLAUDE.md's note on the two).
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

/// True when this host can derive the real hybrid local DB key. False on GitHub-hosted CI
/// runners, which are VMs with no Secure Enclave. Tests gated on this report as *skipped*
/// rather than silently passing, so the size of the untested surface stays visible.
///
/// Declared per file, matching the twenty-odd other copies in this target.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@Suite("findAndOpenRecipientSlot — prekey consumption")
@MainActor struct PrekeyConsumptionOnRejectionTests {

    /// One sender, one recipient, one real SE-backed prekey, sealed FS-mode.
    private struct Fixture {
        let senderKM: TestKeyManager
        let recipientCrypto: Manager.Crypto
        let prekeyManager: Manager.PrekeyManager
        let prekey: Prekey
        let contactID: String
        let bundle: OccultaBundle
        let senderPub: Data

        @MainActor
        init(prefixed: Bool = false) throws {
            self.senderKM        = TestKeyManager()
            self.recipientCrypto = Manager.Crypto(keyManager: TestKeyManager())
            self.prekeyManager   = Manager.PrekeyManager()
            self.contactID       = "consume-" + UUID().uuidString

            self.prekey = try #require(
                self.prekeyManager.generateBatch(contactID: self.contactID, count: 1).first
            )
            let recipient = GroupRecipient(
                publicKey:       try TestKeyManager().retrieveIdentity(),
                quantumMaterial: nil,
                contactPrekey:   self.prekey,
                pendingBatch:    nil,
                prefixesEphemeralSignature: prefixed
            )
            self.bundle = try Manager.Crypto(keyManager: self.senderKM).seal(
                message: Data("consumption".utf8), groupID: UUID(), recipients: [recipient]
            )
            self.senderPub = try self.senderKM.retrieveIdentity()
        }

        /// True while the prekey's private half is still in the Enclave.
        var privateKeyStillPresent: Bool {
            self.prekeyManager.retrievePrivateKey(for: self.prekey) != nil
        }

        func open(senderPublicKey: Data) throws
        -> (payload: OccultaBundle.RecipientPayload, consumable: Prekey?, mode: OccultaBundle.Mode) {
            try self.recipientCrypto.findAndOpenRecipientSlot(
                in: self.bundle,
                blind: self.bundle.group!.blind,
                senderContactID: self.contactID,
                senderPublicKey: senderPublicKey,
                quantumMaterial: nil,
                prekeyManager: self.prekeyManager
            )
        }

        func cleanUp() {
            self.prekeyManager.deleteAllKeys(for: self.contactID)
        }
    }

    /// The regression this whole item is about. A bundle whose slot opens and whose signature
    /// then fails must still destroy the prekey — the private key already derived the wrapping
    /// key, so forward secrecy for anything sealed to it is spent whether or not we accept the
    /// message. Verifying against a different identity is the rotation scenario: the signature
    /// is real, it just wasn't made by the key we now resolve for this sender.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func rejectedSignature_stillConsumesPrekey() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        #expect(f.privateKeyStillPresent, "precondition: prekey exists before the open")

        let impostorPub = try TestKeyManager().retrieveIdentity()
        #expect(throws: GroupDecryptError.senderEphemeralSignatureMismatch) {
            _ = try f.open(senderPublicKey: impostorPub)
        }

        #expect(!f.privateKeyStillPresent,
                "prekey survived a rejected open — forward secrecy is lost for anything sealed to it")
    }

    /// The success path must behave identically. Before this change the caller consumed after
    /// the fact; now the function does, and the outcome from the outside is the same.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func acceptedBundle_consumesPrekey() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        #expect(f.privateKeyStillPresent)
        let (_, consumable, mode) = try f.open(senderPublicKey: f.senderPub)

        #expect(mode == .forwardSecretNoPQ)
        #expect(consumable != nil, "the returned prekey reports what was consumed")
        #expect(!f.privateKeyStillPresent)
    }

    /// Consumption is scoped to the slot that actually opened. A device that is not a recipient
    /// derives no wrapping key, so it must not destroy anything on the way out — otherwise a
    /// crafted bundle would let a stranger burn prekeys they never held.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func nonRecipient_consumesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        let stranger = Manager.Crypto(keyManager: TestKeyManager())
        #expect(throws: GroupDecryptError.recipientSlotNotFound) {
            _ = try stranger.findAndOpenRecipientSlot(
                in: f.bundle,
                blind: f.bundle.group!.blind,
                senderContactID: "someone-else",
                senderPublicKey: f.senderPub,
                quantumMaterial: nil,
                prekeyManager: f.prekeyManager
            )
        }

        #expect(f.privateKeyStillPresent, "a non-recipient must not consume our prekey")
    }

    /// Idempotence, because the defer now runs on paths the caller cannot see. Re-opening the
    /// same bundle finds no private key, fails to derive, and reports the slot as not found
    /// rather than consuming a second time or misreporting success.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func replayAfterConsumption_findsNoSlot() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.open(senderPublicKey: f.senderPub)
        #expect(!f.privateKeyStillPresent)

        #expect(throws: GroupDecryptError.recipientSlotNotFound) {
            _ = try f.open(senderPublicKey: f.senderPub)
        }
    }

    /// The domain-separated form must consume on rejection too — the prefix changed what is
    /// signed, not when the key is spent.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func prefixedSignature_rejected_stillConsumesPrekey() throws {
        let f = try Fixture(prefixed: true)
        defer { f.cleanUp() }

        let impostorPub = try TestKeyManager().retrieveIdentity()
        #expect(throws: GroupDecryptError.senderEphemeralSignatureMismatch) {
            _ = try f.open(senderPublicKey: impostorPub)
        }
        #expect(!f.privateKeyStillPresent)
    }
}
