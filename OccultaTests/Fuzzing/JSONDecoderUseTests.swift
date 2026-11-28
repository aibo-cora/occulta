//
//  JSONDecoderUseTests.swift
//  OccultaTests
//
//  Keeps `BoundedJSON` in front of every JSON document the app reads (`bugs.md` Bug 189). Foundation's scanner traps
//  on 513 open brackets, so a `JSONDecoder` call on a file's or a peer's bytes is a way to end the app, and the next
//  such call written without thinking about it would be one.
//
//  The rule is the simplest sound one: no `JSONDecoder` in shipped code except the one inside `BoundedJSON`. There is
//  no list of files that "only decode what this device sealed", because that list was the control, and a listed file
//  that gained an outside-facing decode passed. A decode of local data goes through `BoundedJSON` too; it costs one
//  pass over bytes that are already in memory and refuses nothing Occulta writes (the deepest document nests under
//  ten levels, the limit is 64).
//
//  Like `OSTraceTests`, it reads the source tree, blanking comments and strings with the same lexer (`OSTraceScanner`),
//  so a `JSONDecoder` mentioned in a comment doesn't count and one named any other way does: a stored decoder, a type
//  annotation, a typealias.
//
//  One exception, temporary: three files owned by the passphrase refactor (the store, the data model and Secure Mode),
//  which a second branch is rewriting. They still hold the decodes they held before this rule, each of a field this
//  device sealed under its own key. The list below is exact, so it can't grow unnoticed and can't go stale. Convert them
//  when that branch lands, and empty it.
//

import Testing
import Foundation

/// Finds `JSONDecoder` in one Swift source file. Pure: source text in, line numbers out.
struct JSONDecoderScanner {

    /// The line numbers (1-based) where the identifier `JSONDecoder` appears in code: not in a comment, a string
    /// literal or an interpolation, and not as part of a longer name.
    static func uses(in source: String) -> [Int] {
        let code = OSTraceScanner.lex(Array(source.utf8)).code
        let needle = Array("JSONDecoder".utf8)
        var lines: [Int] = []
        var line = 1
        var index = 0
        while index < code.count {
            if code[index] == 0x0A {
                line += 1
            } else if code[index] == needle[0], index + needle.count <= code.count,
                      code[index..<index + needle.count].elementsEqual(needle),
                      !Self.isIdentifier(index == 0 ? nil : code[index - 1]),
                      !Self.isIdentifier(index + needle.count < code.count ? code[index + needle.count] : nil) {
                lines.append(line)
            }
            index += 1
        }
        return lines
    }

    private static func isIdentifier(_ byte: UInt8?) -> Bool {
        guard let byte else { return false }
        return (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
            || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || byte == UInt8(ascii: "_")
    }

    /// What is wrong with `sources` (relative path to text) given how many `JSONDecoder` each path may hold. Empty is a pass.
    /// A path that isn't in `allowed` may hold none. A path that is must hold exactly the count: fewer means the list is stale.
    static func findings(in sources: [String: String], allowed: [String: Int]) -> [String] {
        var found: [String] = []
        for (path, source) in sources.sorted(by: { $0.key < $1.key }) {
            let lines = Self.uses(in: source)
            let limit = allowed[path] ?? 0
            let at = lines.map(String.init).joined(separator: ",")
            if lines.count > limit {
                found.append("\(path):\(at) — \(lines.count) JSONDecoder, \(limit) allowed. Decode with BoundedJSON.decode (Bug 189)")
            } else if lines.count < limit {
                found.append("\(path) — \(lines.count) JSONDecoder, listed with \(limit): shrink the list")
            }
        }
        for path in allowed.keys.sorted() where sources[path] == nil {
            found.append("\(path) is listed and not there")
        }
        return found
    }
}

@Suite("No JSONDecoder outside BoundedJSON")
struct JSONDecoderUseTests {

    /// The one place Foundation's decoder is called. `BoundedJSON.decode` counts the nesting first.
    static let boundedJSON = "OccultaCore/Sources/OccultaFormats/BoundedJSON.swift"

    /// Files that still decode local fields with `JSONDecoder` directly, and how many: the passphrase refactor owns them.
    /// Each decodes a field this device sealed under its own key. Temporary; see the header.
    static let pending: [String: Int] = [
        "Occulta/Data Models/Group+Model.swift": 1,                    // a sealed timestamp
        "Occulta/Features/SecureMode/AppLayerConfig+Model.swift": 4,   // sealed settings
        "Occulta/Services/Contact+Manager.swift": 3,                   // a contact's stored ML-KEM material
    ]

    private static let allowed = Self.pending.merging([Self.boundedJSON: 1]) { first, _ in first }

    /// Every directory compiled into a shipped target, the package's sources included, which is where `BoundedJSON` lives.
    private static let scannedRoots = ["Occulta", "ShareExtension", "OccultaPreview", "OccultaCore/Sources"]

    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private static func relative(_ url: URL) -> String { String(url.path.dropFirst(Self.repoRoot.path.count + 1)) }

    /// Relative path to source text. A file that can't be read is its own finding, not a skipped one.
    private static func sources() -> [String: String] {
        var result: [String: String] = [:]
        for root in Self.scannedRoots {
            let enumerator = FileManager.default.enumerator(at: Self.repoRoot.appendingPathComponent(root), includingPropertiesForKeys: nil)
            for url in (enumerator?.allObjects as? [URL] ?? []) where url.pathExtension == "swift" {
                result[Self.relative(url)] = (try? String(contentsOf: url, encoding: .utf8)) ?? "JSONDecoder // unreadable"
            }
        }
        return result
    }

    @Test("The scan reaches the source tree")
    func scanReachesSource() {
        let sources = Self.sources()
        #expect(sources.count >= 100, "Scanned only \(sources.count) Swift files under \(Self.repoRoot.path)")
        for root in Self.scannedRoots {
            #expect(sources.keys.contains { $0.hasPrefix(root + "/") }, "No Swift files found under \(root)")
        }
        #expect(sources[Self.boundedJSON] != nil, "BoundedJSON.swift is not where the rule expects it")
        let bounded = sources.values.reduce(0) { $0 + $1.components(separatedBy: "BoundedJSON.decode(").count - 1 }
        #expect(bounded >= 30, "BoundedJSON.decode is called \(bounded) times; the scan is not seeing what it should")
    }

    @Test("No JSONDecoder in shipped code but the one in BoundedJSON, and the files that are listed")
    func noOtherJSONDecoder() {
        let found = JSONDecoderScanner.findings(in: Self.sources(), allowed: Self.allowed)
        #expect(found.isEmpty, "\(found.joined(separator: "\n"))")
    }

    @Test("The list of pending files only names files, and BoundedJSON is not among them")
    func listIsWellFormed() {
        #expect(Self.pending[Self.boundedJSON] == nil)
        #expect(Self.pending.values.allSatisfy { $0 > 0 })
    }

    // MARK: - The check itself

    /// Planted: each one is a `JSONDecoder` a reviewer could miss, and the forms next to them that are not.
    private static let planted: [(source: String, lines: [Int])] = [
        ("let a = try JSONDecoder().decode(Thing.self, from: data)", [1]),
        ("let decoder = JSONDecoder()", [1]),
        ("typealias Reader = JSONDecoder", [1]),
        ("func read(with decoder: JSONDecoder) {}", [1]),
        ("let d = JSONDecoder.init()", [1]),
        ("let d = JSONDecoder\n    ()", [1]),
        ("let a = 1\nlet b = try JSONDecoder().decode(Thing.self, from: data)\nlet c = JSONDecoder()", [2, 3]),
        ("let a = BoundedJSON.decode(Thing.self, from: data)", []),
        ("// JSONDecoder() in a comment", []),
        ("/// `JSONDecoder` in a doc comment", []),
        ("/* outer /* JSONDecoder() */ still a comment */", []),
        ("let c = 2 // JSONDecoder() after code", []),
        (#"let message = "JSONDecoder() in a string""#, []),
        ("let s = \"\"\"\nJSONDecoder()\n\"\"\"", []),
        ("let kind = MyJSONDecoder()", []),
        ("let kind = JSONDecoderLike()", []),
        ("let kind = _JSONDecoder()", []),
    ]

    @Test("Each planted JSONDecoder is found on its line, and mentions and longer names are not")
    func plantedUses() {
        for (source, lines) in Self.planted {
            #expect(JSONDecoderScanner.uses(in: source) == lines, "\(source)")
        }
    }

    @Test("A violation in a shipped file fails the check, with the line")
    func plantedViolation() {
        let sources = [
            "Occulta/Features/Planted.swift": "import Foundation\nlet x = try JSONDecoder().decode(Int.self, from: bytes)\n",
            "Occulta/Features/Clean.swift": "// JSONDecoder is not used here\nlet x = try BoundedJSON.decode(Int.self, from: bytes)\n",
        ]
        let found = JSONDecoderScanner.findings(in: sources, allowed: [:])
        #expect(found.count == 1)
        #expect(found.first?.hasPrefix("Occulta/Features/Planted.swift:2 ") == true)
    }

    @Test("A second JSONDecoder in BoundedJSON, or in a listed file, fails; so does a list that has gone stale")
    func plantedExceptions() {
        let one = "let a = JSONDecoder()"
        let two = "let a = JSONDecoder()\nlet b = JSONDecoder()"
        let none = "let a = 1"

        #expect(JSONDecoderScanner.findings(in: ["BoundedJSON.swift": one], allowed: ["BoundedJSON.swift": 1]).isEmpty)
        #expect(JSONDecoderScanner.findings(in: ["BoundedJSON.swift": two], allowed: ["BoundedJSON.swift": 1]).count == 1)
        #expect(JSONDecoderScanner.findings(in: ["Listed.swift": two], allowed: ["Listed.swift": 1]).count == 1)
        // The listed file no longer needs its exception, or is gone: the list has to shrink.
        #expect(JSONDecoderScanner.findings(in: ["Listed.swift": none], allowed: ["Listed.swift": 1]).count == 1)
        #expect(JSONDecoderScanner.findings(in: [:], allowed: ["Gone.swift": 1]).count == 1)
        // A file nobody listed gets no exception just because another has one.
        #expect(JSONDecoderScanner.findings(in: ["Other.swift": one, "Listed.swift": one], allowed: ["Listed.swift": 1]).count == 1)
    }
}
