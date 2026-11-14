//
//  JSONDecoderUseTests.swift
//  OccultaTests
//
//  Keeps `BoundedJSON` in front of every JSON document that came from outside (`bugs.md` Bug 189). Foundation's
//  scanner traps on 513 open brackets, so a `JSONDecoder` call on a file's or a peer's bytes is a way to end the app,
//  and the next such call written without thinking about it would be one.
//
//  Like `OSTraceTests`, it reads the source tree: it fails on a `JSONDecoder` in a file that isn't listed below. A
//  listed file decodes only what this device sealed under its own key, which nobody outside can write: local rows,
//  the app's settings, and records of a contact's keys. Adding a file here means checking that.
//

import Testing
import Foundation

/// Finds `JSONDecoder` uses in one Swift source file. Pure: source text in, line numbers out.
struct JSONDecoderScanner {

    /// The line numbers (1-based) of a `JSONDecoder(` in code, not in a comment.
    static func uses(in source: String) -> [Int] {
        source.split(separator: "\n", omittingEmptySubsequences: false).enumerated().compactMap { index, line in
            let code = line.drop { $0 == " " || $0 == "\t" }
            guard !code.hasPrefix("//") else { return nil }
            // A trailing comment doesn't count either.
            let beforeComment = code.components(separatedBy: "//").first ?? ""
            return beforeComment.contains("JSONDecoder(") ? index + 1 : nil
        }
    }
}

@Suite("JSONDecoder is only used on what this device sealed")
struct JSONDecoderUseTests {

    /// File, and how many `JSONDecoder(` it may hold. Each decodes a field this device sealed itself.
    private static let local: [String: Int] = [
        "Occulta/Data Models/Group+Model.swift": 1,                             // a sealed timestamp
        "Occulta/Features/Forward+Secrecy/PrekeyRecordCodec.swift": 1,          // the legacy record, from the local row
        "Occulta/Features/IdentityChallenge/IdentityChallenge+Coordinator.swift": 2,   // a contact's stored ML-KEM material
        "Occulta/Features/SecureMode/AppLayerConfig+Model.swift": 4,            // sealed settings
        "Occulta/Features/Vault/ShardCustody+Manager.swift": 1,                 // a sealed custody row
        "Occulta/Features/Vault/Vault+Manager+Backup.swift": 1,                 // the legacy backup-key row
        "Occulta/Features/Vault/Vault+Manager+ReturnBuffer.swift": 1,           // a sealed buffer row
        "Occulta/Features/Vault/Vault+Manager+Shards.swift": 1,                 // a sealed pending row
        "Occulta/Features/Vault/Vault+Manager.swift": 1,                        // a sealed entry label
        "Occulta/Services/Contact+Manager.swift": 3,                            // a contact's stored ML-KEM material
        "Occulta/UI/Tabs/Contacts/v2/Contacts+DesignTokens.swift": 1,           // the same, to see whether it decodes
        "Occulta/UI/Tabs/Contacts/v2/DraftStore.swift": 2,                      // a sealed draft
    ]

    private static let scannedRoots = ["Occulta", "ShareExtension", "OccultaPreview"]

    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private static func sourceFiles() -> [URL] {
        Self.scannedRoots.flatMap { root -> [URL] in
            let enumerator = FileManager.default.enumerator(at: Self.repoRoot.appendingPathComponent(root), includingPropertiesForKeys: nil)
            return (enumerator?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "swift" }
        }
    }

    private static func relative(_ url: URL) -> String { String(url.path.dropFirst(Self.repoRoot.path.count + 1)) }

    @Test("The scan reaches the source tree")
    func scanReachesSource() {
        let files = Self.sourceFiles()
        #expect(files.count >= 100, "Scanned only \(files.count) Swift files under \(Self.repoRoot.path)")
        let bounded = files.reduce(0) { total, url in
            total + ((try? String(contentsOf: url, encoding: .utf8))?.components(separatedBy: "BoundedJSON.decode(").count ?? 1) - 1
        }
        #expect(bounded >= 12, "BoundedJSON.decode is called \(bounded) times; the scan is not seeing what it should")
    }

    @Test("Every JSONDecoder is on a listed file, within its count")
    func onlyLocalDecodes() {
        var unlisted: [String] = []
        for url in Self.sourceFiles() {
            guard let source = try? String(contentsOf: url, encoding: .utf8) else { unlisted.append(Self.relative(url) + " (unreadable)"); continue }
            let uses = JSONDecoderScanner.uses(in: source)
            let allowed = Self.local[Self.relative(url)] ?? 0
            if uses.count > allowed {
                unlisted.append("\(Self.relative(url)):\(uses.map(String.init).joined(separator: ",")) — \(uses.count) JSONDecoder, \(allowed) allowed. Decode bytes from outside with BoundedJSON.decode (Bug 189)")
            }
        }
        #expect(unlisted.isEmpty, "\(unlisted.joined(separator: "\n"))")
    }

    @Test("The listed files still hold what they are listed for, so the list can't go stale")
    func listIsCurrent() {
        for (path, count) in Self.local {
            let url = Self.repoRoot.appendingPathComponent(path)
            guard let source = try? String(contentsOf: url, encoding: .utf8) else { Issue.record("\(path) is listed and not there"); continue }
            #expect(JSONDecoderScanner.uses(in: source).count == count, "\(path) is listed with \(count)")
        }
    }

    @Test("A planted JSONDecoder is found, and a comment about one is not")
    func plantedViolation() {
        let planted = """
        let a = 1
        let b = try JSONDecoder().decode(Thing.self, from: data)
        // JSONDecoder() in a comment
        let c = 2 // JSONDecoder() after code
        """
        #expect(JSONDecoderScanner.uses(in: planted) == [2])
    }
}
