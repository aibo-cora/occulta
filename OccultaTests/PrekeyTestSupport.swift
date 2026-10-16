//
//  PrekeyTestSupport.swift
//  OccultaTests
//
//  Helpers the prekey tests share, so each isn't copied into every file that needs it. Older test files keep
//  their own file-private `secureEnclaveAvailable()` and `makeContactManager()`, which predate this file. Those two
//  live in `TestSupport`: at module scope they would clash with those private copies as invalid redeclarations.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

func randomBytes(_ count: Int) -> Data {
    Data((0..<count).map { _ in .random(in: .min ... .max) })
}

/// SplitMix64, so a failing random run can be replayed from its seed.
struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        self.state &+= 0x9E37_79B9_7F4A_7C15
        var z = self.state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// A contact's last-resort private half as a software key: the recipient holds an Enclave blob, but these tests run
/// without an Enclave. Found as the receive path finds it, by the prekey ID derived from it.
struct SoftwareLastResort: PrekeyPrivateKeys {
    let keyID = UUID().uuidString
    let privateKey: SecKey
    let publicKey: Data

    init() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try #require(SecKeyCopyPublicKey(key))
        self.privateKey = key
        self.publicKey  = try #require(SecKeyCopyExternalRepresentation(publicKey, &error) as Data?)
    }

    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey? { nil }
    func consume(prekeyID: String, contactID: String) {}
    func lastResortKey(forPrekeyID prekeyID: String, ephemeralPublicKey: Data) -> (keyID: String, key: PrekeyPrivateKey)? {
        OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: self.keyID, ephemeralPublicKey: ephemeralPublicKey) == prekeyID
            ? (self.keyID, .keychain(self.privateKey))
            : nil
    }
}

enum TestSupport {

    static func secureEnclaveAvailable() -> Bool {
        (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
    }

    @MainActor
    static func makeContactManager() throws -> ContactManager {
        let schema = Schema([
            Group.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return ContactManager(modelContainer: container, security: security)
    }
}
