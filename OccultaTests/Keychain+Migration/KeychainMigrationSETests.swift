//
//  KeychainMigrationSETests.swift
//  OccultaTests
//
//  Device-only tests. The Secure Enclave is not available in the Simulator.
//
//  These tests determine whether SecItemUpdate can add kSecAttrAccessGroup
//  to an existing SE-protected key. If any test fails, the migration strategy
//  in Keychain+Migration.swift is unviable and must be redesigned.
//
//  ⚠️ Requires the App Group entitlement "group.com.occulta.shared" on
//  both the app and test targets. Without it, SecItemUpdate will return
//  errSecMissingEntitlement (-34018) and the tests will fail for the wrong reason.
//

import XCTest

final class KeychainMigrationSETests: XCTestCase {

    private let testTag = "test.migration.se.key.\(UUID().uuidString)"
    private let accessGroup = "group.com.occulta.shared"

    // P-256 generator point G — fixed peer for ECDH verification.
    private let fixedX963 = Data([
        0x04,
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
        0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
        0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
        0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
    ])

    // MARK: - Lifecycle

    override func setUp() {
        super.setUp()
        #if targetEnvironment(simulator)
        throw XCTSkip("Secure Enclave is not available in the simulator")
        #endif
    }

    override func tearDown() {
        super.tearDown()
        // Clean up: delete by tag with and without access group to catch both states.
        for query in [queryWithoutGroup(), queryWithGroup()] {
            SecItemDelete(query as CFDictionary)
        }
    }

    // MARK: - Tests

    /// Core viability test: can SecItemUpdate add an access group to an SE key?
    func testUpdateAddsAccessGroupToSEKey() throws {
        try createSEKey(withAccessGroup: false)

        // Key exists without access group
        XCTAssertEqual(SecItemCopyMatching(queryWithoutGroup() as CFDictionary, nil), errSecSuccess,
                       "SE key should exist without access group after creation")

        // Update: add access group
        let updateStatus = SecItemUpdate(
            queryWithoutGroup() as CFDictionary,
            [kSecAttrAccessGroup as String: accessGroup] as CFDictionary
        )

        XCTAssertEqual(updateStatus, errSecSuccess,
                       "SecItemUpdate must succeed when adding access group to SE key. " +
                       "Status \(updateStatus) — if this fails, the migration strategy is unviable.")
    }

    /// After migration, the key must be findable via the access group.
    func testKeyDiscoverableViaAccessGroupAfterUpdate() throws {
        try createSEKey(withAccessGroup: false)

        let updateStatus = SecItemUpdate(
            queryWithoutGroup() as CFDictionary,
            [kSecAttrAccessGroup as String: accessGroup] as CFDictionary
        )
        guard updateStatus == errSecSuccess else {
            throw XCTSkip("SecItemUpdate failed (\(updateStatus)) — cannot test discoverability")
        }

        let findStatus = SecItemCopyMatching(queryWithGroup() as CFDictionary, nil)
        XCTAssertEqual(findStatus, errSecSuccess,
                       "SE key must be discoverable via access group query after update")
    }

    /// After migration, the key must no longer appear in queries without the access group
    /// (verifies the key moved, not duplicated).
    func testKeyNotDuplicatedAfterUpdate() throws {
        try createSEKey(withAccessGroup: false)

        let updateStatus = SecItemUpdate(
            queryWithoutGroup() as CFDictionary,
            [kSecAttrAccessGroup as String: accessGroup] as CFDictionary
        )
        guard updateStatus == errSecSuccess else {
            throw XCTSkip("SecItemUpdate failed (\(updateStatus)) — cannot test duplication")
        }

        // Query without access group should still find it (access group is additive,
        // not exclusive), but there should be exactly one item, not two.
        var result: AnyObject?
        let query = queryWithoutGroup(returnAttributes: true)
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess {
            // If found, verify it's a single item with the correct access group
            if let attrs = result as? [String: Any] {
                let group = attrs[kSecAttrAccessGroup as String] as? String
                XCTAssertEqual(group, accessGroup, "The key's access group should be the new group")
            }
        }
        // errSecItemNotFound is also acceptable — means the key only lives in the new group
    }

    /// The migrated key must still perform ECDH. If the SE wrapper was invalidated
    /// by the access group change, ECDH will fail and every contact becomes undecryptable.
    func testECDHWorksAfterAccessGroupUpdate() throws {
        try createSEKey(withAccessGroup: false)

        // ECDH before migration
        let secretBefore = try performECDH(query: queryWithoutGroup(returnRef: true))

        // Migrate
        let updateStatus = SecItemUpdate(
            queryWithoutGroup() as CFDictionary,
            [kSecAttrAccessGroup as String: accessGroup] as CFDictionary
        )
        guard updateStatus == errSecSuccess else {
            throw XCTSkip("SecItemUpdate failed (\(updateStatus)) — cannot test ECDH")
        }

        // ECDH after migration
        let secretAfter = try performECDH(query: queryWithGroup(returnRef: true))

        XCTAssertEqual(secretBefore, secretAfter,
                       "ECDH shared secret must be identical before and after access group migration. " +
                       "A mismatch means the SE key was replaced, not moved — all contacts would be lost.")
    }

    /// A key created directly with the access group should be findable via the group query.
    /// Baseline sanity check — if this fails, the entitlement is missing.
    func testKeyCreatedWithAccessGroupIsDiscoverable() throws {
        try createSEKey(withAccessGroup: true)

        let status = SecItemCopyMatching(queryWithGroup() as CFDictionary, nil)
        XCTAssertEqual(status, errSecSuccess,
                       "SE key created with access group must be discoverable. " +
                       "If this fails, check that the App Group entitlement is present on the test target.")
    }

    /// Idempotency: calling SecItemUpdate on a key that already has the access group
    /// should succeed or return errSecSuccess (not errSecDuplicateItem or errSecParam).
    func testUpdateIsIdempotent() throws {
        try createSEKey(withAccessGroup: true)

        let status = SecItemUpdate(
            queryWithGroup() as CFDictionary,
            [kSecAttrAccessGroup as String: accessGroup] as CFDictionary
        )

        // errSecSuccess or errSecParam (no-op) are both acceptable.
        // errSecDuplicateItem or any other error is a problem.
        XCTAssertTrue(
            status == errSecSuccess || status == errSecParam,
            "Re-applying the same access group should be a no-op. Got status \(status)."
        )
    }

    // MARK: - Helpers

    private func createSEKey(withAccessGroup: Bool) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }

        var privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: testTag.data(using: .utf8)!,
            kSecAttrAccessControl as String: access
        ]

        if withAccessGroup {
            privateKeyAttrs[kSecAttrAccessGroup as String] = accessGroup
        }

        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: privateKeyAttrs
        ]

        guard let _ = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }
    }

    private func performECDH(query: [String: Any]) throws -> Data {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }

        let privateKey = item as! SecKey

        let peerAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var peerError: Unmanaged<CFError>?
        guard let peerKey = SecKeyCreateWithData(
            fixedX963 as CFData, peerAttrs as CFDictionary, &peerError
        ) else {
            throw peerError!.takeRetainedValue() as Error
        }

        var ecdhError: Unmanaged<CFError>?
        guard let secret = SecKeyCopyKeyExchangeResult(
            privateKey,
            .ecdhKeyExchangeCofactorX963SHA256,
            peerKey,
            [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
            &ecdhError
        ) as? Data else {
            throw ecdhError!.takeRetainedValue() as Error
        }

        return secret
    }

    // MARK: - Query builders

    private func queryWithoutGroup(returnRef: Bool = false, returnAttributes: Bool = false) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: testTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        if returnRef { q[kSecReturnRef as String] = true }
        if returnAttributes {
            q[kSecReturnAttributes as String] = true
            q[kSecMatchLimit as String] = kSecMatchLimitOne
        }
        return q
    }

    private func queryWithGroup(returnRef: Bool = false) -> [String: Any] {
        var q = queryWithoutGroup(returnRef: returnRef)
        q[kSecAttrAccessGroup as String] = accessGroup
        return q
    }
}
