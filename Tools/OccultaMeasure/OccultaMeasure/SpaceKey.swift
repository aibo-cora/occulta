//
//  SpaceKey.swift
//  OccultaMeasure
//
//  The space-key derivation, as `ContactRecordCryptoMeasurementTests` times it: one ECDH between a transient
//  Secure Enclave key and a point derived from the PBKDF2 output, on iOS 26 one decapsulation by a transient
//  Enclave ML-KEM-1024 key, and HKDF. Nothing is stored: the keys are never permanent and no keychain item is made.
//

import CryptoKit
import Foundation
import Security

struct SpaceKeyDerivation {
    private let enclaveKey: SecKey
    private let enclavePublicKey: Data
    private let tierSecret = Random.bytes(32)
    private let decapsulate: (() throws -> Data)?

    var postQuantum: Bool { self.decapsulate != nil }

    init() throws {
        self.enclaveKey = try Self.transientEnclaveKey()
        guard let publicKey = SecKeyCopyPublicKey(self.enclaveKey),
              let external = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else { throw MeasureError("the Enclave key has no public key") }
        self.enclavePublicKey = external

        if #available(iOS 26, *) {
            self.decapsulate = try Self.transientDecapsulation()
        } else {
            self.decapsulate = nil
        }
    }

    /// The point P for a PBKDF2 output: the public key of the scalar the output hashes to.
    func point(from output: [UInt8]) throws -> SecKey {
        for counter in UInt8.min...UInt8.max {
            let scalar = Data(SHA256.hash(data: Data(output) + Data("Occulta-measurement-point".utf8) + [counter]))
            guard let privateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: scalar) else { continue }

            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 256
            ]
            guard let point = SecKeyCreateWithData(privateKey.publicKey.x963Representation as CFData,
                                                   attributes as CFDictionary, nil)
            else { throw MeasureError("the derived point is not a P-256 key") }
            return point
        }
        throw MeasureError("no scalar in 256 tries")
    }

    func exchange(with point: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let secret = SecKeyCopyKeyExchangeResult(
            self.enclaveKey, .ecdhKeyExchangeCofactorX963SHA256, point,
            [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
        ) as Data? else { throw MeasureError("Enclave ECDH failed: \(error?.takeRetainedValue().localizedDescription ?? "?")") }
        return secret
    }

    func decapsulation() throws -> Data {
        guard let decapsulate = self.decapsulate else { throw MeasureError("no ML-KEM below iOS 26") }
        return try decapsulate()
    }

    func derive(from output: [UInt8]) throws -> SymmetricKey {
        var material = try self.exchange(with: try self.point(from: output))
        if self.decapsulate != nil {
            material.append(try self.decapsulation())
        }
        material.append(self.tierSecret)

        return HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: material), salt: self.enclavePublicKey,
                                      info: Data("Occulta-measurement-space-key".utf8), outputByteCount: 32)
    }

    /// A P-256 Enclave key with the access control production gives its keys, not stored in the keychain.
    private static func transientEnclaveKey() throws -> SecKey {
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil
        ) else { throw MeasureError("no access control for the Enclave key") }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access
            ] as [String: Any]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw MeasureError("no Secure Enclave key: \(error?.takeRetainedValue().localizedDescription ?? "?")")
        }
        return key
    }

    /// An Enclave ML-KEM-1024 key, and a decapsulation of a ciphertext made to its public key.
    @available(iOS 26, *)
    private static func transientDecapsulation() throws -> () throws -> Data {
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil
        ) else { throw MeasureError("no access control for the Enclave ML-KEM key") }

        let key = try SecureEnclave.MLKEM1024.PrivateKey(accessControl: access)
        let ciphertext = try key.publicKey.encapsulate().encapsulated
        return { try key.decapsulate(ciphertext).withUnsafeBytes { Data($0) } }
    }
}
