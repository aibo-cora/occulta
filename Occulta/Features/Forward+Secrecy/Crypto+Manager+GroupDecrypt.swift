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
}

// MARK: - Group-decrypt crypto helpers

extension Manager.Crypto {

    /// Find our Recipient slot in a group bundle by matching our identity key fingerprint.
    func findRecipientSlot(in bundle: OccultaBundle) throws -> OccultaBundle.Recipient {
        guard let recipients = bundle.group?.recipients else {
            throw GroupDecryptError.noGroupEnvelope
        }
        let ourPub = try self.keyManager.retrieveIdentity()
        for entry in recipients {
            let computed = OccultaBundle.SecrecyContext.fingerprint(for: ourPub, nonce: entry.fingerprintNonce)
            if computed == entry.fingerprint { return entry }
        }
        throw GroupDecryptError.recipientSlotNotFound
    }

    /// Open a per-recipient wrappedPayload and decode the RecipientPayload.
    ///
    /// AAD = groupID.uuidString ‖ entry.fingerprint — mirrors wrapRecipient.
    func openWrappedPayload(
        _ entry: OccultaBundle.Recipient,
        groupID: UUID,
        using wrappingKey: SymmetricKey
    ) throws -> OccultaBundle.RecipientPayload {
        var aad = Data(groupID.uuidString.utf8)
        aad.append(entry.fingerprint)
        let box = try AES.GCM.SealedBox(combined: entry.wrappedPayload)
        let plain = try AES.GCM.open(box, using: wrappingKey, authenticating: aad)
        return try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: plain)
    }

    /// Open the shared outer ciphertext of a group bundle with the extracted session key.
    ///
    /// AAD = computeAdditionalAuthentication(version: .v4, outerSecrecy) ‖ groupID.uuidString
    func openGroupCiphertext(_ bundle: OccultaBundle, using sessionKey: SymmetricKey) throws -> Data {
        guard let group = bundle.group else { throw GroupDecryptError.noGroupEnvelope }
        var aad = try OccultaBundle.computeAdditionalAuthentication(version: bundle.version, secrecy: bundle.secrecy)
        aad.append(Data(group.id.uuidString.utf8))
        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        return try AES.GCM.open(box, using: sessionKey, authenticating: aad)
    }
}
