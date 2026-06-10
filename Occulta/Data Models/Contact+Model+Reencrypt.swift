//
//  Contact+Model+Reencrypt.swift
//  Occulta
//
//  Instance methods for re-encrypting a Contact.Profile from one local DB key to
//  another. Used during Secure Mode activation and deactivation, always called
//  before commitStagedLocalDBKey() so the canonical key is still the old one.
//

import Foundation
import SwiftData
import CryptoKit

// MARK: - Key-rotation re-encryption

extension Contact.Profile {

    /// Re-encrypt every encrypted field on this profile to `newKey`.
    ///
    /// Fields that cannot be decrypted with the current canonical key (corrupted
    /// or already under a different key) are cleared to nil. They reinitialise
    /// transparently on next use — e.g. `configureForwardSecrecy()` for FS state,
    /// or the next contact save for text fields.
    func reencryptAllFields(to newKey: SymmetricKey, aad: Data) throws {
        // ── Scalar String fields ─────────────────────────────────────────────────
        self.givenName          = try reencrypt(string: self.givenName,          to: newKey, aad: aad)
        self.familyName         = try reencrypt(string: self.familyName,         to: newKey, aad: aad)
        self.middleName         = try reencrypt(string: self.middleName,         to: newKey, aad: aad)
        self.namePrefix         = try reencrypt(string: self.namePrefix,         to: newKey, aad: aad)
        self.nameSuffix         = try reencrypt(string: self.nameSuffix,         to: newKey, aad: aad)
        self.nickname           = try reencrypt(string: self.nickname,           to: newKey, aad: aad)
        self.organizationName   = try reencrypt(string: self.organizationName,   to: newKey, aad: aad)
        self.departmentName     = try reencrypt(string: self.departmentName,     to: newKey, aad: aad)
        self.jobTitle           = try reencrypt(string: self.jobTitle,           to: newKey, aad: aad)
        self.phoneticGivenName  = try reencrypt(string: self.phoneticGivenName,  to: newKey, aad: aad)
        self.phoneticMiddleName = try reencrypt(string: self.phoneticMiddleName, to: newKey, aad: aad)
        self.phoneticFamilyName = try reencrypt(string: self.phoneticFamilyName, to: newKey, aad: aad)
        self.note               = try reencrypt(string: self.note,               to: newKey, aad: aad)
        self.birthday           = try self.birthday.map { try reencrypt(string: $0, to: newKey, aad: aad) }

        // ── Data fields ──────────────────────────────────────────────────────────
        self.imageData               = try reencrypt(data: self.imageData,               to: newKey, aad: aad)
        self.thumbnailImageData      = try reencrypt(data: self.thumbnailImageData,      to: newKey, aad: aad)
        self.forwardSecrecyEncrypted = try reencrypt(data: self.forwardSecrecyEncrypted, to: newKey, aad: aad)
        self.signedAttributes        = try reencrypt(data: self.signedAttributes,        to: newKey, aad: aad)
        self.visibleThroughDepth     = try reencrypt(data: self.visibleThroughDepth,     to: newKey, aad: aad)

        // ── Relationship fields ──────────────────────────────────────────────────
        for phone in (self.phoneNumbers ?? []) {
            phone.label = try reencrypt(string: phone.label, to: newKey, aad: aad)
            phone.value = try reencrypt(string: phone.value, to: newKey, aad: aad)
        }
        for email in (self.emailAddresses ?? []) {
            email.label = try reencrypt(string: email.label, to: newKey, aad: aad)
            email.value = try reencrypt(string: email.value, to: newKey, aad: aad)
        }
        for postal in (self.postalAddresses ?? []) {
            postal.label          = try reencrypt(string: postal.label,          to: newKey, aad: aad)
            postal.street         = try reencrypt(string: postal.street,         to: newKey, aad: aad)
            postal.city           = try reencrypt(string: postal.city,           to: newKey, aad: aad)
            postal.state          = try reencrypt(string: postal.state,          to: newKey, aad: aad)
            postal.postalCode     = try reencrypt(string: postal.postalCode,     to: newKey, aad: aad)
            postal.country        = try reencrypt(string: postal.country,        to: newKey, aad: aad)
            postal.isoCountryCode = try reencrypt(string: postal.isoCountryCode, to: newKey, aad: aad)
        }
        for url in (self.urlAddresses ?? []) {
            url.label = try reencrypt(string: url.label, to: newKey, aad: aad)
            url.value = try reencrypt(string: url.value, to: newKey, aad: aad)
        }
    }

    /// Re-encrypt all key-record fields (material, owner, dates, quantum blob).
    ///
    /// Kept separate from `reencryptAllFields` because key records have their own
    /// storage shape (raw `Data`, not base64 strings) and are already handled
    /// independently in the existing rotation flow.
    func reencryptKeyRecords(to newKey: SymmetricKey, aad: Data) throws {
        for keyRecord in (self.contactPublicKeys ?? []) {
            if let plain = keyRecord.material?.decrypt() {
                keyRecord.material = try AES.GCM.seal(plain, using: newKey, authenticating: aad).combined
            }
            if !keyRecord.owner.isEmpty, let plain = keyRecord.owner.decrypt() {
                keyRecord.owner = try AES.GCM.seal(plain, using: newKey, authenticating: aad).combined ?? keyRecord.owner
            }
            if let plain = keyRecord.acquiredAt?.decrypt() {
                keyRecord.acquiredAt = try AES.GCM.seal(plain, using: newKey, authenticating: aad).combined
            }
            if let plain = keyRecord.expiredOn?.decrypt() {
                keyRecord.expiredOn = try AES.GCM.seal(plain, using: newKey, authenticating: aad).combined
            }
            if let plain = keyRecord.quantumKeyMaterialEncrypted?.decrypt() {
                keyRecord.quantumKeyMaterialEncrypted = try AES.GCM.seal(plain, using: newKey, authenticating: aad).combined
            }
        }
    }

    // MARK: - Private helpers

    /// Re-encrypt a base64-encoded ciphertext string.
    /// Returns the original value unchanged if the string is empty or unreadable.
    private func reencrypt(string: String, to newKey: SymmetricKey, aad: Data) throws -> String {
        guard
            !string.isEmpty,
            let ciphertext = Data(base64Encoded: string),
            !ciphertext.isEmpty,
            let plain = ciphertext.decrypt()
        else { return string }
        return try AES.GCM.seal(plain, using: newKey, authenticating: aad).combined?
            .base64EncodedString() ?? string
    }

    /// Re-encrypt a raw Data ciphertext.
    /// Returns nil if the field is nil or unreadable — callers reinitialise on next use.
    private func reencrypt(data: Data?, to newKey: SymmetricKey, aad: Data) throws -> Data? {
        guard let data, let plain = data.decrypt() else { return nil }
        return try AES.GCM.seal(plain, using: newKey, authenticating: aad).combined
    }
}
