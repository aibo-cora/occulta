//
//  DataProtectionEntitlementTests.swift
//  OccultaTests
//
//  Bug 214: with no `com.apple.developer.default-data-protection` entitlement, a file the app creates without naming a
//  protection class (the store's sidecars, recreated after a checkpoint, and the Drafts directory) sits at the default class
//  until something stamps it. Both targets that write files declare `NSFileProtectionComplete`, and the explicit stamps stay.
//
//  The entitlement files are read from the source tree, as `OSTraceTests` reads its sources. What class a file ends up in can
//  only be seen on a device; this pins that the request is made.
//

import Testing
import Foundation

@Suite("Bug 214 — default data protection is requested by the app and the share extension")
struct DataProtectionEntitlementTests {

    private static let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()

    private static func entitlements(_ path: String) throws -> [String: Any] {
        let data = try Data(contentsOf: Self.repoRoot.appendingPathComponent(path))
        return try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    @Test("Each target's entitlements name NSFileProtectionComplete as the default", arguments: ["Occulta/Occulta.entitlements", "ShareExtension/ShareExtension.entitlements"])
    func defaultIsComplete(path: String) throws {
        let entitlements = try Self.entitlements(path)

        #expect(entitlements["com.apple.developer.default-data-protection"] as? String == "NSFileProtectionComplete", "\(path)")
        #expect((entitlements["com.apple.security.application-groups"] as? [String])?.isEmpty == false, "the App Group entitlement stays")
    }
}
