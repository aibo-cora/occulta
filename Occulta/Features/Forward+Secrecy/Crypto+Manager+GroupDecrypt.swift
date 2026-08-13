//
//  Crypto+Manager+GroupDecrypt.swift
//  Occulta
//

import Foundation
import CryptoKit

// MARK: - Group decrypt errors

/// `Equatable` is explicit rather than implicit: Swift synthesises it for enums with no
/// associated values, and adding `senderID` to two cases silently removed it — breaking the
/// `#expect(throws:)` assertions in `GroupDecryptTests` that compare error values.
enum GroupDecryptError: Error, Equatable {
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
    /// `RecipientPayload.senderEphemeralSignature` is present but does not verify
    /// against the entry's ephemeral key and the resolved sender's public key. FS
    /// mode's session key never involves the sender's long-term identity (finding #8,
    /// SecurityReview2026-07-24), so a bad signature here is a genuine forgery signal,
    /// not slot ambiguity — the wrapping key already decrypted correctly.
    case senderEphemeralSignatureMismatch
    /// A FS-mode recipient's signature is missing, but the sender has previously
    /// demonstrated (via `appVersion`) that their build produces one — so its absence
    /// here means it was stripped, not that the sender can't produce it.
    /// FS-mode bundle carried no `senderEphemeralSignature` from a sender this device has
    /// recorded as *able* to produce one. That is a forgery signal, not a compatibility
    /// problem: their build signs, and this bundle did not. Kept distinct from the case below
    /// so the UI can say something true about each — see `processInboundFile`.
    case missingSenderEphemeralSignature
    /// FS-mode bundle carried no `senderEphemeralSignature` and this device cannot establish
    /// whether the sender's build can produce one — their recorded capability was stranded by
    /// a pre-1.10.2 key rotation (Bug 77). Rejected because incapability cannot be proven, but
    /// the overwhelmingly likely cause is an older contact rather than an attack, so it is kept
    /// distinct from the case above. Conflating the two would tell a genuine impersonation
    /// victim to go ask their friend to update. See Bug 81.
    case senderSignatureCapabilityUnknown
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
            // The wrapping key already decrypted correctly, so this is genuinely our
            // slot — a signature mismatch here is forgery, not slot ambiguity, and
            // must not be treated as "try the next entry". Only FS-mode entries carry
            // a real signature — fallback-mode entries carry random filler of the same
            // size (see wrapRecipient) purely to keep RecipientPayload's size uniform
            // across modes, so it must never be checked here.
            let isFSMode = entry.secrecyContext.mode == .forwardSecret
                        || entry.secrecyContext.mode == .forwardSecretNoPQ
            if isFSMode, let signature = payload.senderEphemeralSignature {
                guard self.verifySenderEphemeralSignature(
                    signature,
                    ephemeralPublicKey: entry.secrecyContext.ephemeralPublicKey,
                    senderPublicKey: senderPublicKey
                ) else { throw GroupDecryptError.senderEphemeralSignatureMismatch }
            }
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
