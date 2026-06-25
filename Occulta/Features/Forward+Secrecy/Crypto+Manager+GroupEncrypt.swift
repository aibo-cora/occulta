//
//  Crypto+Manager+GroupEncrypt.swift
//  Occulta
//

import Foundation
import CryptoKit

// MARK: - GroupRecipient

/// Value type carrying exactly what sealGroup needs per recipient.
/// Caller (GroupManager) builds this from Contact.Profile before crossing into crypto,
/// keeping SwiftData entirely out of the crypto layer.
struct GroupRecipient {
    /// Long-term P-256 identity public key (65-byte x963).
    /// Used for fingerprinting and ECDH on the fallback path.
    let publicKey: Data
    let quantumMaterial: QuantumKeyMaterial?
    /// Contact's oldest stored inbound prekey, popped by the caller before this call.
    /// Non-nil → FS path; nil → fallback path.
    let contactPrekey: Prekey?
    /// Outbound prekey batch to include in this recipient's RecipientPayload, or nil.
    let pendingBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?
}

// MARK: - Group encryption

extension Manager.Crypto {

    /// Encrypt a group message for all recipients.
    ///
    /// One shared ciphertext sealed with a random session key; the session key is
    /// wrapped individually for each recipient inside `GroupEnvelope.recipients`.
    ///
    /// ## Outer AAD
    /// `computeAdditionalAuthentication(version: .v4, secrecy: outerSecrecy)` ‖ `groupID.uuidString`
    ///
    /// ## Per-recipient AAD
    /// `groupID.uuidString` ‖ `recipientFingerprint`
    ///
    /// ## Per-recipient key path
    /// `contactPrekey != nil` → FS: ECDH(senderEphemeral, contactPrekey.publicKey) [+ ML-KEM]
    /// `contactPrekey == nil` → fallback: ECDH(senderLongTerm, r.publicKey) [+ ML-KEM]
    func sealGroup(
        message: Data,
        groupID: UUID,
        recipients: [GroupRecipient]
    ) throws -> OccultaBundle {
        guard !recipients.isEmpty else { throw EncryptionError.noRecipients }

        let sessionKey = SymmetricKey(size: .bits256)
        let sessionKeyData = sessionKey.withUnsafeBytes { Data($0) }

        let outerSecrecy = OccultaBundle.SecrecyContext(
            mode: .group, ephemeralPublicKey: Data(), prekeyID: nil
        )

        var outerAAD = try OccultaBundle.computeAdditionalAuthentication(version: .v4, secrecy: outerSecrecy)
        outerAAD.append(Data(groupID.uuidString.utf8))

        let sealedPayload = OccultaBundle.SealedPayload(message: message, appVersion: Bundle.main.appVersion)
        let payloadData = try WireHandle.encode(payload: sealedPayload)

        guard let ciphertext = try AES.GCM.seal(
            payloadData, using: sessionKey, nonce: AES.GCM.Nonce(), authenticating: outerAAD
        ).combined else { throw EncryptionError.sealFailed }

        let senderPub = try self.keyManager.retrieveIdentity()
        let outerNonce = try OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(for: senderPub, nonce: outerNonce)

        let recipientEntries = try recipients.map { r in
            try self.wrapRecipient(r, sessionKeyData: sessionKeyData, groupID: groupID)
        }

        let envelope = OccultaBundle.GroupEnvelope(id: groupID, recipients: recipientEntries)
        return OccultaBundle(
            version: .v4,
            secrecy: outerSecrecy,
            ciphertext: ciphertext,
            fingerprintNonce: outerNonce,
            senderFingerprint: senderFingerprint,
            group: envelope
        )
    }

    private func wrapRecipient(
        _ r: GroupRecipient,
        sessionKeyData: Data,
        groupID: UUID
    ) throws -> OccultaBundle.Recipient {
        guard r.publicKey.count == 65 else { throw EncryptionError.invalidRecipientMaterial }

        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        let fingerprint = OccultaBundle.SecrecyContext.fingerprint(for: r.publicKey, nonce: nonce)

        var aad = Data(groupID.uuidString.utf8)
        aad.append(fingerprint)

        let wrappingKey: SymmetricKey
        let secrecyContext: OccultaBundle.SecrecyContext

        if let prekey = r.contactPrekey {
            guard prekey.publicKey.count == 65 else { throw EncryptionError.invalidPrekeyMaterial }
            guard let (ephemeralPriv, ephemeralPub) = self.keyManager.generateEphemeralKeyPair() else {
                throw EncryptionError.ephemeralKeyGenerationFailed
            }
            guard let key = self.deriveSessionKey(
                ephemeralPrivateKey: ephemeralPriv,
                recipientMaterial: prekey.publicKey,
                quantumMaterial: r.quantumMaterial
            ) else { throw EncryptionError.keyDerivationFailed }
            wrappingKey = key
            let mode: OccultaBundle.Mode = r.quantumMaterial != nil ? .forwardSecret : .forwardSecretNoPQ
            secrecyContext = OccultaBundle.SecrecyContext(
                mode: mode, ephemeralPublicKey: ephemeralPub, prekeyID: prekey.id
            )
        } else {
            guard let key = self.deriveSessionKey(using: r.publicKey, quantumMaterial: r.quantumMaterial) else {
                throw EncryptionError.keyDerivationFailed
            }
            wrappingKey = key
            let mode: OccultaBundle.Mode = r.quantumMaterial != nil ? .longTermFallback : .longTermNoPQ
            secrecyContext = OccultaBundle.SecrecyContext(
                mode: mode, ephemeralPublicKey: Data(), prekeyID: nil
            )
        }

        let payload = OccultaBundle.RecipientPayload(sessionKey: sessionKeyData, prekeyBatch: r.pendingBatch)
        let encodedPayload = try JSONEncoder().encode(payload)

        guard let wrappedPayload = try AES.GCM.seal(
            encodedPayload, using: wrappingKey, nonce: AES.GCM.Nonce(), authenticating: aad
        ).combined else { throw EncryptionError.sealFailed }

        return OccultaBundle.Recipient(
            fingerprint: fingerprint,
            fingerprintNonce: nonce,
            secrecyContext: secrecyContext,
            wrappedPayload: wrappedPayload
        )
    }
}
