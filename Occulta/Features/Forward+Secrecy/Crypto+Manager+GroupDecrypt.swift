//
//  Crypto+Manager+GroupDecrypt.swift
//  Occulta
//

import Foundation
import CryptoKit

// MARK: - Group decrypt errors

enum GroupDecryptError: Error {
    case noGroupEnvelope
    case recipientSlotNotFound
    /// The `senderProof` inside the decrypted payload does not match
    /// HMAC(sessionKey, senderPublicKey). The cleartext sender routing fields
    /// were tampered with after the bundle was sealed.
    case senderProofMismatch
    /// GroupEnvelope.version is not recognised by this build.
    case unknownEnvelopeVersion
    /// SealedPayload.groupID is nil — required for group message routing.
    case missingGroupID
    /// `recipients.count` exceeds `Group.slotCount`. No legitimately-created group can
    /// exceed this cap, so a larger count means a malformed or maliciously crafted
    /// envelope — reject before trial-decrypting any entry.
    case tooManyRecipients
}

// MARK: - Group-decrypt crypto helpers

extension Manager.Crypto {

    /// Find our recipient slot by trial-decryption and return the decoded RecipientPayload.
    ///
    /// For each slot, derives the inbound wrapping key from the slot's `secrecyContext`,
    /// then attempts AES-GCM open with `blind` as AAD. The first slot that opens is ours.
    /// No cleartext identity hint is consulted — an observer cannot confirm membership
    /// without holding a valid wrapping key.
    func findAndOpenRecipientSlot(
        in bundle: OccultaBundle,
        blind: Data,
        senderContactID: String,
        senderPublicKey: Data,
        quantumMaterial: QuantumKeyMaterial?,
        prekeyManager: Manager.PrekeyManager
    ) throws -> (payload: OccultaBundle.RecipientPayload, consumable: Prekey?, mode: OccultaBundle.Mode) {
        guard let recipients = bundle.group?.recipients else {
            throw GroupDecryptError.noGroupEnvelope
        }
        // No legitimately-created group ever exceeds Group.slotCount members. Reject an
        // oversized envelope before spending any ECDH/AEAD work on it — otherwise a
        // crafted bundle with an arbitrarily large recipient list forces every receiving
        // device through one expensive trial decryption per entry.
        guard recipients.count <= Group.slotCount else {
            throw GroupDecryptError.tooManyRecipients
        }
        for entry in recipients {
            guard let (wrappingKey, consumable) = try? self.deriveInboundKey(
                secrecy: entry.secrecyContext,
                senderContactID: senderContactID,
                senderPublicKey: senderPublicKey,
                quantumMaterial: quantumMaterial,
                prekeyManager: prekeyManager
            ) else { continue }
            guard let box   = try? AES.GCM.SealedBox(combined: entry.wrappedPayload),
                  let plain = try? AES.GCM.open(box, using: wrappingKey, authenticating: blind),
                  let payload = try? JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: plain)
            else { continue }
            return (payload, consumable, entry.secrecyContext.mode)
        }
        throw GroupDecryptError.recipientSlotNotFound
    }

    /// Open a per-recipient wrappedPayload and decode the RecipientPayload.
    ///
    /// AAD = `blind` — mirrors `wrapRecipient`. Used by tests that supply the
    /// wrapping key directly; production code uses `findAndOpenRecipientSlot`.
    func openWrappedPayload(
        _ entry: OccultaBundle.Recipient,
        blind: Data,
        using wrappingKey: SymmetricKey
    ) throws -> OccultaBundle.RecipientPayload {
        let box = try AES.GCM.SealedBox(combined: entry.wrappedPayload)
        let plain = try AES.GCM.open(box, using: wrappingKey, authenticating: blind)
        return try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: plain)
    }

    /// Open the shared outer ciphertext of a group bundle with the extracted session key.
    ///
    /// AAD = computeAdditionalAuthentication(version: .v4, outerSecrecy) ‖ group.blind
    func openGroupCiphertext(_ bundle: OccultaBundle, using sessionKey: SymmetricKey) throws -> Data {
        guard let group = bundle.group else { throw GroupDecryptError.noGroupEnvelope }
        var aad = try OccultaBundle.computeAdditionalAuthentication(version: bundle.version, secrecy: bundle.secrecy)
        aad.append(group.blind)
        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        return try AES.GCM.open(box, using: sessionKey, authenticating: aad)
    }

    /// Verify that `signature` is a valid ECDSA signature over `ephemeralPublicKey`,
    /// produced by the holder of `senderPublicKey`'s private key.
    ///
    /// Authenticates FS-mode group messages: `deriveInboundKey`'s `.forwardSecret`
    /// branch never involves the sender's long-term identity, so `senderProof` alone
    /// doesn't prove who sent the message for that mode (see finding #8,
    /// SecurityReview2026-07-24) — this signature is the actual binding. Mirrors
    /// `SignedAttribute.verify(against:)`'s verification pattern.
    func verifySenderEphemeralSignature(_ signature: Data, ephemeralPublicKey: Data, senderPublicKey: Data) -> Bool {
        guard senderPublicKey.count == 65 else { return false }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let pubKey = SecKeyCreateWithData(senderPublicKey as CFData, attrs as CFDictionary, &error)
        else { return false }
        return SecKeyVerifySignature(
            pubKey, .ecdsaSignatureMessageX962SHA256,
            ephemeralPublicKey as CFData, signature as CFData, &error
        )
    }
}
