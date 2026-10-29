//
//  BundleContentsTests.swift
//  OccultaTests
//
//  Bug 154 — `Occulta/` is a file-system-synchronized root group, so every non-source
//  file under it is copied into the app bundle unless it is listed in the Occulta
//  target's `membershipExceptions`. Six design docs added after the 1.10.2 fix
//  (SECURITY_CHECKLIST.md §6) were never listed, and v1.11.1 shipped them. The list
//  regresses silently every time a doc is added next to the code.
//
//  This suite runs hosted in `Occulta.app` (TEST_HOST), so `Bundle.main` is the built
//  app, appexes included. Membership exceptions do not vary by configuration, so the
//  Debug bundle under test carries the same resources as the Release archive.
//

import Testing
import Foundation

@Suite("Bug 154 — no internal documentation in the app bundle")
struct BundleContentsTests {

    private static let forbiddenExtensions: Set<String> = ["md", "html"]

    @Test("The test host is Occulta.app with both appexes embedded")
    func hostIsTheApp() {
        let bundle = Bundle.main.bundleURL
        let plugIns = bundle.appendingPathComponent("PlugIns")

        #expect(bundle.lastPathComponent == "Occulta.app")
        #expect(FileManager.default.fileExists(atPath: plugIns.appendingPathComponent("ShareExtension.appex").path))
        #expect(FileManager.default.fileExists(atPath: plugIns.appendingPathComponent("OccultaPreview.appex").path))
    }

    @Test("No .md or .html anywhere in the app bundle or its appexes")
    func noDocsInBundle() throws {
        let bundle = Bundle.main.bundleURL
        let enumerator = try #require(FileManager.default.enumerator(at: bundle, includingPropertiesForKeys: nil))

        let leaked = enumerator
            .compactMap { $0 as? URL }
            .filter { Self.forbiddenExtensions.contains($0.pathExtension.lowercased()) }
            .map { String($0.path.dropFirst(bundle.path.count + 1)) }
            .sorted()

        #expect(leaked.isEmpty, """
            Internal docs are in the app bundle: \(leaked). Add each to the \
            membershipExceptions of 'Exceptions for "Occulta" folder in "Occulta" target' \
            in project.pbxproj, quoting any path containing '+' or a space.
            """)
    }
}
