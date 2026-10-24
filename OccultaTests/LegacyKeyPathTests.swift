//
//  LegacyKeyPathTests.swift
//  OccultaTests
//
//  Bug 171, Stage 7: the v1 local DB key is `ECDH(identity key, G)`, a function of the identity key's public point, which
//  every contact holds. Anything still sealed under it is open to every contact who has the ciphertext, so nothing may reach
//  it except the one migration that moves such data off it. `KeyManagerProtocol` no longer declares
//  `createLocalEncryptionKey`, `Manager.Crypto` has no `decryptLegacy`, and `LegacyCryptoManager` is the single place that
//  asks for the key; `DatabaseMigration.migrateToV2` is the single place that calls `decryptLegacy`, and `LaunchSequence`
//  the single place that builds the manager and calls `migrateToV2`.
//
//  The source is scanned, as `OSTraceTests` scans it, because a call site added tomorrow has to fail a test and not only
//  a review. Comments are not code and are skipped.
//
//  Written first (Stage 7a): the protocol still declared the method and `Manager.Crypto` still had `decryptLegacy`.
//

import Testing
import Foundation
import CryptoKit

@testable import Occulta

@Suite("The v1 local key is reachable from migrateToV2 only")
@MainActor
struct LegacyKeyPathTests {

    private static let scannedRoots = ["Occulta", "ShareExtension", "OccultaPreview", "OccultaCore/Sources"]

    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private struct Line {
        /// Relative to the repository root.
        let path: String
        let number: Int
        /// The code of the line, with any `//` comment cut off.
        let code: String
    }

    /// Every line of every shipped Swift file that is code and not a comment.
    private static let lines: [Line] = {
        let files = Self.scannedRoots.flatMap { root -> [URL] in
            let directory = Self.repoRoot.appendingPathComponent(root)
            let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil)
            return (enumerator?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "swift" }
        }

        return files.flatMap { url -> [Line] in
            let relative = String(url.path.dropFirst(Self.repoRoot.path.count + 1))
            guard let source = try? String(contentsOf: url, encoding: .utf8) else { return [] }

            return source.components(separatedBy: "\n").enumerated().compactMap { index, text in
                let trimmed = text.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("//") || trimmed.hasPrefix("*") || trimmed.hasPrefix("/*") { return nil }
                let code = text.components(separatedBy: "//").first ?? text
                return Line(path: relative, number: index + 1, code: code)
            }
        }
    }()

    private static func hits(_ token: String, in path: String? = nil) -> [Line] {
        Self.lines.filter { $0.code.contains(token) && (path == nil || $0.path == path) }
    }

    private static func describe(_ lines: [Line]) -> String {
        lines.map { "\($0.path):\($0.number)" }.joined(separator: ", ")
    }

    private static let crypto = "Occulta/Services/Crypto+Manager.swift"
    private static let protocolFile = "Occulta/Protocols/KeyManagerProtocol.swift"
    private static let migration = "Occulta/Features/PostQuantum/PQmigration.swift"
    private static let launch = "Occulta/App/LaunchSequence.swift"

    /// Guards against a vacuous pass: a `#filePath` that no longer points into the repository finds no files.
    @Test("The scan reaches the source tree")
    func scanReachesSource() {
        #expect(Set(Self.lines.map(\.path)).count >= 100, "Scanned \(Set(Self.lines.map(\.path)).count) Swift files under \(Self.repoRoot.path)")
        #expect(!Self.hits("func createLocalEncryptionKey", in: "Occulta/Services/Key+Manager.swift").isEmpty, "the definition is where it was")
    }

    @Test("KeyManagerProtocol does not declare the v1 key: nothing that takes a key manager can reach it")
    func protocolDoesNotDeclareIt() {
        let declaration = Self.lines.filter { $0.path == Self.protocolFile && $0.code.contains("createLocalEncryptionKey") }

        // Its only appearances are the concrete test manager's own method, which `LegacyLocalKeyProviding` asks for.
        let protocolLines = Self.lines.filter { $0.path == Self.protocolFile }
        let testManagerStart = protocolLines.first { $0.code.contains("final class TestKeyManager") }?.number ?? Int.max
        let inProtocol = declaration.filter { $0.number < testManagerStart }
        #expect(inProtocol.isEmpty, "declared in the protocol: \(Self.describe(inProtocol))")
    }

    @Test("Only LegacyCryptoManager asks for the v1 key")
    func onlyTheLegacyManagerCallsIt() {
        let calls = Self.hits(".createLocalEncryptionKey(")

        #expect(calls.map(\.path) == [Self.crypto], "called from: \(Self.describe(calls))")

        // And inside LegacyCryptoManager, not Manager.Crypto.
        let start = Self.hits("final class LegacyCryptoManager", in: Self.crypto).first?.number ?? Int.max
        let end   = Self.hits("extension Manager {", in: Self.crypto).first?.number ?? 0
        #expect(calls.allSatisfy { $0.number > start && $0.number < end }, "called outside LegacyCryptoManager: \(Self.describe(calls))")
    }

    @Test("Manager.Crypto has no legacy decrypt, and CryptoProtocol does not ask for one")
    func managerCryptoHasNone() {
        let end = Self.hits("protocol CryptoProtocol", in: Self.crypto).first?.number ?? 0
        let start = Self.hits("extension Manager {", in: Self.crypto).first?.number ?? Int.max
        #expect(start < end, "Manager.Crypto sits between its extension and the protocol")
        let inside = Self.lines.filter { $0.path == Self.crypto && $0.number > start && $0.number < end && ($0.code.contains("decryptLegacy") || $0.code.contains("createLocalEncryptionKey")) }
        #expect(inside.isEmpty, "Manager.Crypto reaches the v1 key at: \(Self.describe(inside))")

        let cryptoProtocol = Self.hits("protocol CryptoProtocol", in: Self.crypto).first?.number ?? 0
        let next = Self.lines.filter { $0.path == Self.crypto && $0.number > cryptoProtocol && $0.code.contains("decryptLegacy") }.first
        let legacyProtocol = Self.hits("protocol LegacyCryptoProtocol", in: Self.crypto).first?.number ?? 0
        #expect(next == nil || next!.number > legacyProtocol && legacyProtocol > cryptoProtocol, "CryptoProtocol declares decryptLegacy")
    }

    @Test("Only the migration calls decryptLegacy")
    func onlyMigrationCallsDecryptLegacy() {
        let calls = Self.hits(".decryptLegacy(")

        #expect(!calls.isEmpty, "the migration calls it")
        #expect(Set(calls.map(\.path)) == [Self.migration], "called from: \(Self.describe(calls))")
    }

    @Test("Only the launch sequence builds the legacy manager and runs migrateToV2")
    func onlyTheLaunchSequenceRunsIt() {
        let builds = Self.hits("LegacyCryptoManager(")
        #expect(Set(builds.map(\.path)).isSubset(of: [Self.launch, Self.crypto]), "built at: \(Self.describe(builds))")
        #expect(builds.contains { $0.path == Self.launch })

        let migrations = Self.hits("DatabaseMigration.migrateToV2(")
        #expect(Set(migrations.map(\.path)) == [Self.launch], "migrateToV2 is called from: \(Self.describe(migrations))")
    }

    // MARK: - Behaviour

    @Test("LegacyCryptoManager opens a v1 value, rejects a v2 one, and returns nil without a key manager that has the v1 key")
    func legacyManagerBehaviour() throws {
        let keys = TestKeyManager()
        let plaintext = Data("sealed under the identity-derived key".utf8)

        let v1Key = try #require(try keys.createLocalEncryptionKey())
        let v1 = try #require(try AES.GCM.seal(plaintext, using: v1Key, nonce: AES.GCM.Nonce()).combined)
        #expect(try LegacyCryptoManager(keyManager: keys).decryptLegacy(data: v1) == plaintext)

        let v2 = try #require(try Manager.Crypto(keyManager: keys).encrypt(data: plaintext))
        #expect(throws: (any Error).self) { _ = try LegacyCryptoManager(keyManager: keys).decryptLegacy(data: v2) }

        #expect(try LegacyCryptoManager(keyManager: nil).decryptLegacy(data: v1) == nil)
    }
}
