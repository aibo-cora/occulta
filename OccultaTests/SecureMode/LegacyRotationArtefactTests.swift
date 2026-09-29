//
//  LegacyRotationArtefactTests.swift
//  OccultaTests
//
//  Bug 139 — an interrupted v1.10.3 key rotation could leave SE keys tagged
//  `local.db.se.key.occulta.staged` / `.superseded` and the keychain item
//  `local.db.random.key.occulta.staged`. This branch removed rotation and the wipe's sweep of
//  them, so on an upgraded device they outlived "Erase all data". `Manager.Key.deleteAllKeys()`
//  now deletes them through `deleteLegacyRotationArtefacts()`, which is what's tested here:
//  calling `deleteAllKeys()` itself would delete the canonical keys other tests are using.
//
//  The names are written out, not read from `Manager.Key`, since they are what v1.10.3 left on
//  disk. SE key creation needs an Enclave, so that test is gated.
//

import Testing
import Foundation
import Security
@testable import Occulta

private let stagedSETag      = "local.db.se.key.occulta.staged"
private let supersededSETag  = "local.db.se.key.occulta.superseded"
private let stagedRandomItem = "local.db.random.key.occulta.staged"

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

/// Creates a permanent SE key under `tag`, as v1.10.3's `createLocalDBSEKey(tag:)` did.
private func createSEKey(tag: String) throws {
    var error: Unmanaged<CFError>?
    let access = try #require(SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error
    ))
    let attributes: [String: Any] = [
        kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String:       kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String:    true,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrAccessControl as String:  access,
        ] as [String: Any],
    ]
    _ = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
}

private func seKeyExists(tag: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String:              kSecClassKey,
        kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
        kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave,
    ]
    return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
}

private func addRandomItem(account: String) {
    let query: [String: Any] = [
        kSecClass as String:          kSecClassGenericPassword,
        kSecAttrAccount as String:    account,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData as String:      Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
    ]
    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
}

private func randomItemExists(account: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String:       kSecClassGenericPassword,
        kSecAttrAccount as String: account,
    ]
    return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
}

@Suite("Bug 139 — keys left by an interrupted v1.10.3 rotation", .serialized)
struct LegacyRotationArtefactTests {

    @Test("All three leftovers are deleted", .enabled(if: secureEnclaveAvailable()))
    func deletesAllThree() throws {
        try createSEKey(tag: stagedSETag)
        try createSEKey(tag: supersededSETag)
        addRandomItem(account: stagedRandomItem)
        #expect(seKeyExists(tag: stagedSETag) && seKeyExists(tag: supersededSETag) && randomItemExists(account: stagedRandomItem),
                "precondition: the leftovers exist")

        #expect(Manager.Key().deleteLegacyRotationArtefacts())

        #expect(!seKeyExists(tag: stagedSETag))
        #expect(!seKeyExists(tag: supersededSETag))
        #expect(!randomItemExists(account: stagedRandomItem))
    }

    /// Most devices never had a rotation interrupted, so absent items must not make the wipe
    /// report failure.
    @Test("With no leftovers, deletion still reports success")
    func noLeftoversIsSuccess() {
        _ = Manager.Key().deleteLegacyRotationArtefacts()

        #expect(Manager.Key().deleteLegacyRotationArtefacts())
    }
}
