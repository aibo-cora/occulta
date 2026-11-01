//
//  ApplicationSupportRoutingTests.swift
//  OccultaTests
//
//  Bug 191. `OccultaTests` is hosted in the app, so a test that writes or deletes a file under Application Support
//  does it in the real container of whatever device the run is on. `Manager.Paths.applicationSupport` gives a test host a
//  directory of its own; these tests hold the line that nothing resolves the system one around it.
//

import Testing
import Foundation
@testable import Occulta

@Suite("Bug 191 — a test host never resolves the real Application Support directory")
struct ApplicationSupportRoutingTests {

    private static let system = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]

    @Test("A test host gets a directory of its own, under the temporary directory")
    func hostGetsItsOwnDirectory() {
        let directory = Manager.Paths.applicationSupport

        #expect(directory.standardizedFileURL != Self.system.standardizedFileURL)
        #expect(directory.path.hasPrefix(FileManager.default.temporaryDirectory.path))
        #expect(FileManager.default.fileExists(atPath: directory.path))
    }

    @Test("The reseal's production locations and the drafts' folder follow it")
    func callSitesFollowTheSeam() {
        #expect(KeyReseal.Locations.production.applicationSupport == Manager.Paths.applicationSupport)
        #expect(Message.Draft.attachmentsRoot.deletingLastPathComponent() == Manager.Paths.applicationSupport)
    }

    // MARK: - The source tree

    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    /// Every file that may name the system directory: the seam, and nowhere else, tests included.
    private static let allowed = ["Occulta/Services/Manager+Paths.swift", "OccultaTests/ApplicationSupportRoutingTests.swift"]

    private static func swiftFiles(under roots: [String]) -> [URL] {
        roots.flatMap { root -> [URL] in
            let enumerator = FileManager.default.enumerator(at: Self.repoRoot.appendingPathComponent(root), includingPropertiesForKeys: nil)
            return (enumerator?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "swift" }
        }
    }

    @Test("Nothing but the seam resolves applicationSupportDirectory")
    func onlyTheSeamResolvesIt() {
        let files = Self.swiftFiles(under: ["Occulta", "ShareExtension", "OccultaPreview", "OccultaCore/Sources", "OccultaTests"])

        // Not a vacuous pass: a run on a physical device can't read the Mac's disk and would find no files.
        #expect(files.count >= 100, "Scanned only \(files.count) Swift files under \(Self.repoRoot.path)")

        let offenders = files
            .map { String($0.path.dropFirst(Self.repoRoot.path.count + 1)) }
            .filter { !Self.allowed.contains($0) }
            .filter { path in
                (try? String(contentsOf: Self.repoRoot.appendingPathComponent(path), encoding: .utf8))?
                    .contains("applicationSupportDirectory") == true
            }
        #expect(offenders.isEmpty, "Use Manager.Paths.applicationSupport instead: \(offenders)")
    }
}
