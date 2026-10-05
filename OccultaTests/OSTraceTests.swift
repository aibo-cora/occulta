//
//  OSTraceTests.swift
//  OccultaTests
//
//  Hardening step 9 (`Docs/v2.0.0/HARDENING_STEPS.md`). The worst leaks found so far were outside
//  the app's own storage: the keyboard's learned-words file (register F1) and Universal Clipboard
//  (F2). Both were fixed by hand while one correct instance of each already existed in the code, and
//  F1 came straight back — three inputs were fixed in 2026-08, and every text input added after that
//  shipped without the modifier, message compose fields included.
//
//  This suite reads the source tree and fails on each kind of API that leaves a trace in the OS, so
//  the next one fails CI instead of shipping:
//
//  - a text input whose own modifier chain lacks `.autocorrectionDisabled()`, a `.searchable` not
//    followed by it, or a UIKit text input, whose traits the check cannot see;
//  - a pasteboard write that bypasses `UIPasteboard.copySensitive(_:)`, system text selection
//    included, since its Copy menu writes the general pasteboard with no `.localOnly` and no expiry;
//  - `NSUserActivity`, Core Spotlight, user notifications, or Siri/Intents donations;
//  - a `UserDefaults`/`@AppStorage` key outside the list `SECURITY_CHECKLIST.md` reviews.
//
//  It scans text, so it sees what is written, not what runs. A modifier applied to a container fails
//  here even though SwiftUI's environment would cover the field. That is deliberate: the field is
//  where the next reader looks, and a container can be refactored away without anyone noticing.
//

import Testing
import Foundation
import SwiftUI
import UIKit
@testable import Occulta

// MARK: - Scanner

/// Finds OS-trace APIs in one Swift source file. Pure: source text in, violations out.
struct OSTraceScanner {

    enum Rule: String, CaseIterable {
        case keyboardLearning
        case pasteboard
        case osDonation
        case defaultsKey

        var message: String {
            switch self {
            case .keyboardLearning:
                return "text input without .autocorrectionDisabled() in its own modifier chain (register F1)"
            case .pasteboard:
                return "pasteboard write outside UIPasteboard.copySensitive(_:) (register F2)"
            case .osDonation:
                return "NSUserActivity, Core Spotlight, notification or Siri/Intents API"
            case .defaultsKey:
                return "UserDefaults/@AppStorage key not on the reviewed list (SECURITY_CHECKLIST.md)"
            }
        }
    }

    struct Violation: CustomStringConvertible, Equatable {
        let rule: Rule
        let path: String
        let line: Int

        var description: String { "\(self.path):\(self.line) — \(self.rule.message)" }
    }

    /// Key expressions allowed as a `UserDefaults`/`@AppStorage` key. The same five keys
    /// `SECURITY_CHECKLIST.md` lists under "No sensitive material written to `UserDefaults`". Adding
    /// one means reviewing it against that item first: no key material, no identifiers, and no name
    /// that discloses Secure Mode.
    static let allowedDefaultsKeys: Set<String> = [
        "\"showFingerprints\"",
        "\"showTrustSummary\"",
        "\"hasCompletedOnboarding\"",
        "\"vault.postRestoreActionNeeded\"",
        "WhatsNew.lastSeenKey",
    ]

    /// The one file allowed to touch `UIPasteboard` directly.
    static let pasteboardHelperPath = "Occulta/Extensions/UIPasteboard.swift"

    private static let textInputs = ["TextField", "SecureField", "TextEditor"]
    private static let uncheckableTextInputs = [
        "UITextField", "UITextView", "UISearchBar", "UISearchTextField", "UISearchController",
    ]
    private static let donationTypes = [
        "NSUserActivity", "CSSearchableItem", "CSSearchableIndex", "CSSearchableItemAttributeSet",
        "UNUserNotificationCenter", "INInteraction", "AppIntent", "AppShortcutsProvider",
    ]
    private static let donationModules: Set<String> = [
        "CoreSpotlight", "UserNotifications", "UserNotificationsUI", "Intents", "IntentsUI", "AppIntents",
    ]
    private static let importKinds: Set<String> = [
        "struct", "class", "enum", "protocol", "func", "var", "let", "typealias",
    ]

    let path: String
    /// Source with comments and string contents blanked to spaces, newlines kept.
    private let code: [UInt8]
    /// Source with comments blanked, strings kept. Same length and offsets as `code`.
    private let text: [UInt8]

    init(source: String, path: String) {
        self.path = path
        (self.code, self.text) = Self.lex(Array(source.utf8))
    }

    func violations() -> [Violation] {
        (self.keyboardLearning() + self.pasteboard() + self.osDonation() + self.defaultsKeys())
            .sorted { $0.line < $1.line }
    }

    // MARK: Rules

    private func keyboardLearning() -> [Violation] {
        var found: [Violation] = []
        for input in Self.textInputs {
            for start in self.occurrences(of: input) {
                let open = self.skipSpace(start + input.utf8.count)
                guard open < self.code.count, self.code[open] == UInt8(ascii: "(") else { continue }
                let chain = self.modifierChain(after: self.closing(open) + 1)
                let disabled = chain.contains { $0.name == "autocorrectionDisabled" && ($0.args.isEmpty || $0.args == "true") }
                if !disabled { found.append(self.violation(.keyboardLearning, at: start)) }
            }
        }
        for input in Self.uncheckableTextInputs {
            found += self.occurrences(of: input).map { self.violation(.keyboardLearning, at: $0) }
        }
        // A search field takes the modifier only from after `.searchable` in the chain; one placed
        // before it is ignored (`SearchableModifierPlacementTests`).
        for search in self.modifierCalls(named: "searchable") {
            let chain = self.modifierChain(after: search.end)
            let disabled = chain.contains { $0.name == "autocorrectionDisabled" && ($0.args.isEmpty || $0.args == "true") }
            if !disabled { found.append(self.violation(.keyboardLearning, at: search.start)) }
        }
        return found
    }

    private func pasteboard() -> [Violation] {
        var found: [Violation] = []
        if !self.path.hasSuffix(Self.pasteboardHelperPath) {
            for start in self.occurrences(of: "UIPasteboard")
            where self.matchTokens(["UIPasteboard", ".", "general", ".", "copySensitive", "("], at: start) == nil {
                found.append(self.violation(.pasteboard, at: start))
            }
        }
        found += self.modifierCalls(named: "textSelection")
            .filter { $0.args.contains("enabled") }
            .map { self.violation(.pasteboard, at: $0.start) }
        found += self.modifierCalls(named: "copyable").map { self.violation(.pasteboard, at: $0.start) }
        return found
    }

    private func osDonation() -> [Violation] {
        var found: [Violation] = []
        for type in Self.donationTypes {
            found += self.occurrences(of: type).map { self.violation(.osDonation, at: $0) }
        }
        for name in ["userActivity", "onContinueUserActivity"] {
            found += self.modifierCalls(named: name).map { self.violation(.osDonation, at: $0.start) }
        }
        for start in self.occurrences(of: "import") {
            var (module, end) = self.identifier(at: self.skipSpace(start + "import".utf8.count))
            if Self.importKinds.contains(module) {
                (module, end) = self.identifier(at: self.skipSpace(end))
            }
            if Self.donationModules.contains(module) { found.append(self.violation(.osDonation, at: start)) }
        }
        return found
    }

    private func defaultsKeys() -> [Violation] {
        var found: [Violation] = []
        for start in self.occurrences(of: "AppStorage") where self.previousNonSpace(start) == UInt8(ascii: "@") {
            let open = self.skipSpace(start + "AppStorage".utf8.count)
            guard open < self.code.count, self.code[open] == UInt8(ascii: "("),
                  Self.allowedDefaultsKeys.contains(self.firstArgument(from: open + 1))
            else {
                found.append(self.violation(.defaultsKey, at: start))
                continue
            }
        }
        // State restoration and iCloud key-value storage both persist outside the app's control.
        for name in ["SceneStorage", "NSUbiquitousKeyValueStore"] {
            found += self.occurrences(of: name).map { self.violation(.defaultsKey, at: $0) }
        }
        // Every line that mentions UserDefaults must name an allowed key in that same line. A
        // multi-line call or a stored `UserDefaults.standard` reference fails, which keeps the key
        // next to the call where this check — and a reviewer — can see it.
        for start in self.occurrences(of: "UserDefaults") {
            let (lineStart, lineEnd) = self.lineBounds(around: start)
            let line = Array(self.code[lineStart..<lineEnd])
            var allowed = false
            if let forKey = Self.find(Array("forKey:".utf8), in: line) {
                allowed = Self.allowedDefaultsKeys.contains(self.firstArgument(from: lineStart + forKey + "forKey:".utf8.count))
            }
            if Self.find(Array("suiteName".utf8), in: line) != nil { allowed = false }
            if !allowed { found.append(self.violation(.defaultsKey, at: start)) }
        }
        return found
    }

    // MARK: Matching

    private struct Call {
        let start: Int
        let name: String
        let args: String
        /// Offset just past the closing parenthesis.
        let end: Int
    }

    /// Offsets where `word` appears as a whole identifier in code.
    private func occurrences(of word: String) -> [Int] {
        let needle = Array(word.utf8)
        var result: [Int] = []
        var from = 0
        while let hit = Self.find(needle, in: self.code, from: from) {
            let before = hit == 0 ? nil : self.code[hit - 1]
            let afterIndex = hit + needle.count
            let after = afterIndex < self.code.count ? self.code[afterIndex] : nil
            if !Self.isIdentifier(before), !Self.isIdentifier(after) { result.append(hit) }
            from = hit + 1
        }
        return result
    }

    /// `.name(…)` calls, located at the `name` token.
    private func modifierCalls(named name: String) -> [Call] {
        self.occurrences(of: name).compactMap { start in
            guard self.previousNonSpace(start) == UInt8(ascii: ".") else { return nil }
            let open = self.skipSpace(start + name.utf8.count)
            guard open < self.code.count, self.code[open] == UInt8(ascii: "(") else { return nil }
            let close = self.closing(open)
            return Call(start: start, name: name, args: self.slice(open + 1, close), end: close + 1)
        }
    }

    /// The `.modifier(…)` chain starting at `index`, each with its trailing closure skipped.
    private func modifierChain(after index: Int) -> [Call] {
        var calls: [Call] = []
        var cursor = self.skipTrailingClosure(index)
        while true {
            let dot = self.skipSpace(cursor)
            guard dot < self.code.count, self.code[dot] == UInt8(ascii: ".") else { break }
            let (name, nameEnd) = self.identifier(at: self.skipSpace(dot + 1))
            guard !name.isEmpty else { break }
            var end = nameEnd
            var args = ""
            let open = self.skipSpace(nameEnd)
            if open < self.code.count, self.code[open] == UInt8(ascii: "(") {
                let close = self.closing(open)
                args = self.slice(open + 1, close)
                end = close + 1
            }
            calls.append(Call(start: dot, name: name, args: args, end: end))
            cursor = self.skipTrailingClosure(end)
        }
        return calls
    }

    /// Matches `tokens` at `start`, allowing whitespace between them. Returns the end offset.
    private func matchTokens(_ tokens: [String], at start: Int) -> Int? {
        var cursor = start
        for (index, token) in tokens.enumerated() {
            if index > 0 { cursor = self.skipSpace(cursor) }
            let bytes = Array(token.utf8)
            guard cursor + bytes.count <= self.code.count,
                  Array(self.code[cursor..<cursor + bytes.count]) == bytes
            else { return nil }
            cursor += bytes.count
        }
        return cursor
    }

    /// The first argument after an opening parenthesis, from the string-preserving text, trimmed.
    private func firstArgument(from index: Int) -> String {
        var depth = 0
        var cursor = index
        while cursor < self.code.count {
            switch self.code[cursor] {
            case UInt8(ascii: "("), UInt8(ascii: "["): depth += 1
            case UInt8(ascii: ")"), UInt8(ascii: "]"):
                if depth == 0 { return self.slice(index, cursor, from: self.text) }
                depth -= 1
            case UInt8(ascii: ","):
                if depth == 0 { return self.slice(index, cursor, from: self.text) }
            default: break
            }
            cursor += 1
        }
        return self.slice(index, cursor, from: self.text)
    }

    // MARK: Low-level

    private func violation(_ rule: Rule, at offset: Int) -> Violation {
        Violation(rule: rule, path: self.path, line: self.code[..<offset].filter { $0 == 0x0A }.count + 1)
    }

    private func slice(_ from: Int, _ to: Int, from source: [UInt8]? = nil) -> String {
        let bytes = source ?? self.code
        let upper = min(max(to, from), bytes.count)
        return String(decoding: bytes[from..<upper], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func identifier(at index: Int) -> (String, Int) {
        var end = index
        while end < self.code.count, Self.isIdentifier(self.code[end]) { end += 1 }
        return (String(decoding: self.code[index..<end], as: UTF8.self), end)
    }

    private func skipSpace(_ index: Int) -> Int {
        var cursor = index
        while cursor < self.code.count, Self.isSpace(self.code[cursor]) { cursor += 1 }
        return cursor
    }

    private func skipTrailingClosure(_ index: Int) -> Int {
        let brace = self.skipSpace(index)
        guard brace < self.code.count, self.code[brace] == UInt8(ascii: "{") else { return index }
        return self.closing(brace) + 1
    }

    private func previousNonSpace(_ index: Int) -> UInt8? {
        var cursor = index - 1
        while cursor >= 0, Self.isSpace(self.code[cursor]) { cursor -= 1 }
        return cursor >= 0 ? self.code[cursor] : nil
    }

    /// Offset of the bracket closing the one at `open`. Strings are already blanked, so counting is safe.
    private func closing(_ open: Int) -> Int {
        let opener = self.code[open]
        let closer: UInt8 = opener == UInt8(ascii: "(") ? UInt8(ascii: ")") : UInt8(ascii: "}")
        var depth = 0
        var cursor = open
        while cursor < self.code.count {
            if self.code[cursor] == opener { depth += 1 }
            if self.code[cursor] == closer {
                depth -= 1
                if depth == 0 { return cursor }
            }
            cursor += 1
        }
        return self.code.count - 1
    }

    private func lineBounds(around index: Int) -> (Int, Int) {
        var start = index
        while start > 0, self.code[start - 1] != 0x0A { start -= 1 }
        var end = index
        while end < self.code.count, self.code[end] != 0x0A { end += 1 }
        return (start, end)
    }

    private static func find(_ needle: [UInt8], in haystack: [UInt8], from: Int = 0) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        var index = from
        while index <= haystack.count - needle.count {
            if haystack[index] == needle[0], Array(haystack[index..<index + needle.count]) == needle { return index }
            index += 1
        }
        return nil
    }

    private static func isIdentifier(_ byte: UInt8?) -> Bool {
        guard let byte else { return false }
        return (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
            || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || byte == UInt8(ascii: "_")
    }

    private static func isSpace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    // MARK: Lexing

    private enum Context {
        case string(multiline: Bool)
        case interpolation(depth: Int)
    }

    /// Blanks comments in both outputs, and string literals (interpolations included) in `code`.
    /// Handles nested block comments, `"""` strings and `\(…)` with strings inside. The app has no
    /// raw strings (`#"…"#`); one would be lexed as an ordinary string, which is close enough here.
    private static func lex(_ source: [UInt8]) -> (code: [UInt8], text: [UInt8]) {
        let quote = UInt8(ascii: "\""), slash = UInt8(ascii: "/"), star = UInt8(ascii: "*")
        let backslash = UInt8(ascii: "\\"), open = UInt8(ascii: "("), close = UInt8(ascii: ")")
        var code = source
        var text = source
        var stack: [Context] = []
        var index = 0

        func blank(_ target: inout [UInt8], _ position: Int) {
            if position < target.count, target[position] != 0x0A { target[position] = 0x20 }
        }
        func at(_ position: Int) -> UInt8? { position < source.count ? source[position] : nil }
        func opensMultiline(_ position: Int) -> Bool { at(position + 1) == quote && at(position + 2) == quote }

        while index < source.count {
            let byte = source[index]
            switch stack.last {
            case .string(let multiline)?:
                blank(&code, index)
                if byte == backslash {
                    blank(&code, index + 1)
                    if at(index + 1) == open { stack.append(.interpolation(depth: 0)) }
                    index += 2
                    continue
                }
                if byte == quote {
                    if !multiline {
                        stack.removeLast()
                    } else if opensMultiline(index) {
                        blank(&code, index + 1)
                        blank(&code, index + 2)
                        stack.removeLast()
                        index += 3
                        continue
                    }
                }
                index += 1

            case .interpolation(let depth)?:
                blank(&code, index)
                if byte == quote {
                    let multiline = opensMultiline(index)
                    if multiline { blank(&code, index + 1); blank(&code, index + 2) }
                    stack.append(.string(multiline: multiline))
                    index += multiline ? 3 : 1
                    continue
                }
                if byte == open { stack[stack.count - 1] = .interpolation(depth: depth + 1) }
                if byte == close {
                    if depth == 0 { stack.removeLast() } else { stack[stack.count - 1] = .interpolation(depth: depth - 1) }
                }
                index += 1

            case nil:
                if byte == slash, at(index + 1) == slash {
                    while index < source.count, source[index] != 0x0A {
                        blank(&code, index)
                        blank(&text, index)
                        index += 1
                    }
                    continue
                }
                if byte == slash, at(index + 1) == star {
                    var depth = 0
                    repeat {
                        if at(index) == slash, at(index + 1) == star {
                            depth += 1
                            blank(&code, index); blank(&text, index)
                            index += 1
                        } else if at(index) == star, at(index + 1) == slash {
                            depth -= 1
                            blank(&code, index); blank(&text, index)
                            index += 1
                        }
                        blank(&code, index); blank(&text, index)
                        index += 1
                    } while depth > 0 && index < source.count
                    continue
                }
                if byte == quote {
                    let multiline = opensMultiline(index)
                    blank(&code, index)
                    if multiline { blank(&code, index + 1); blank(&code, index + 2) }
                    stack.append(.string(multiline: multiline))
                    index += multiline ? 3 : 1
                    continue
                }
                index += 1
            }
        }
        return (code, text)
    }
}

// MARK: - The real source tree

@Suite("Hardening step 9 — no API that leaves a trace in the OS")
struct OSTraceTests {

    /// Every directory compiled into a shipped target.
    private static let scannedRoots = ["Occulta", "ShareExtension", "OccultaPreview", "OccultaCore/Sources"]

    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private static let violations: [OSTraceScanner.Violation] = {
        OSTraceTests.sourceFiles().flatMap { url -> [OSTraceScanner.Violation] in
            let relative = String(url.path.dropFirst(OSTraceTests.repoRoot.path.count + 1))
            guard let source = try? String(contentsOf: url, encoding: .utf8) else {
                return [OSTraceScanner.Violation(rule: .keyboardLearning, path: relative + " (unreadable)", line: 0)]
            }
            return OSTraceScanner(source: source, path: relative).violations()
        }
    }()

    private static func sourceFiles() -> [URL] {
        Self.scannedRoots.flatMap { root -> [URL] in
            let directory = Self.repoRoot.appendingPathComponent(root)
            let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil)
            return (enumerator?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "swift" }
        }
    }

    /// Guards against a vacuous pass. If `#filePath` stops pointing into the repository — a moved
    /// file, or a run on a physical device, which can't read the Mac's disk — the scan would find no
    /// files and every rule below would report zero violations.
    @Test("The scan reaches the source tree")
    func scanReachesSource() {
        let files = Self.sourceFiles()
        #expect(files.count >= 100, "Scanned only \(files.count) Swift files under \(Self.repoRoot.path)")
        for root in Self.scannedRoots {
            #expect(files.contains { $0.path.contains("/\(root)/") }, "No Swift files found under \(root)")
        }
    }

    @Test("Every text input disables autocorrection on its own modifier chain")
    func keyboardLearning() {
        self.expectNone(.keyboardLearning)
    }

    @Test("Every pasteboard write goes through copySensitive, and no text is system-selectable")
    func pasteboard() {
        self.expectNone(.pasteboard)
    }

    @Test("No NSUserActivity, Core Spotlight, notification or Siri/Intents API")
    func osDonation() {
        self.expectNone(.osDonation)
    }

    @Test("Every UserDefaults/@AppStorage key is on the reviewed list")
    func defaultsKeys() {
        self.expectNone(.defaultsKey)
    }

    /// The allowlist names this constant rather than its value, so pin the value.
    @Test("WhatsNew.lastSeenKey is the key SECURITY_CHECKLIST.md lists")
    @MainActor
    func whatsNewKeyValue() {
        #expect(WhatsNew.lastSeenKey == "whatsNewLastSeenVersion")
    }

    private func expectNone(_ rule: OSTraceScanner.Rule) {
        let found = Self.violations.filter { $0.rule == rule }
        let list = found.map(\.description).joined(separator: "\n")
        #expect(found.isEmpty, "\(found.count) violation(s):\n\(list)")
    }
}

// MARK: - The scanner itself

/// Planted violations, one per kind, and the compliant forms next to them. Stage 0's done-condition
/// for step 9 is that the check fails on a planted violation of each kind it covers.
@Suite("OSTraceScanner — planted violations")
struct OSTraceScannerTests {

    struct Case: CustomTestStringConvertible {
        let source: String
        let path: String
        let expected: OSTraceScanner.Rule?

        init(_ source: String, _ expected: OSTraceScanner.Rule?, path: String = "Occulta/View.swift") {
            self.source = source
            self.expected = expected
            self.path = path
        }

        var testDescription: String { self.source.replacingOccurrences(of: "\n", with: " ⏎ ") }
    }

    static let cases: [Case] = [
        // Keyboard learning
        Case(#"TextField("Name", text: $name)"#, .keyboardLearning),
        Case(#"TextEditor(text: $body).font(.body)"#, .keyboardLearning),
        Case(#"SecureField("Secret", text: $secret)"#, .keyboardLearning),
        Case(#"TextField("Name", text: $name).autocorrectionDisabled(false)"#, .keyboardLearning),
        Case("VStack {\n    TextField(\"Name\", text: $name)\n}\n.autocorrectionDisabled()", .keyboardLearning),
        Case(#"let field = UITextField()"#, .keyboardLearning),
        Case(#"List { }.searchable(text: $query)"#, .keyboardLearning),
        Case(#"List { }.autocorrectionDisabled().searchable(text: $query)"#, .keyboardLearning),
        Case("List { }\n    .searchable(text: $query, prompt: \"Search\")\n    .autocorrectionDisabled()", nil),
        Case("TextField(\"Name\", text: $name, axis: .vertical)\n    .lineLimit(4...10)\n    .autocorrectionDisabled()", nil),
        Case("TextEditor(text: $body)\n    .onSubmit { send() }\n    .autocorrectionDisabled(true)", nil),
        Case(#"// TextField("Name", text: $name)"#, nil),
        Case("/* outer /* TextField(\"a\", text: $a) */ still a comment */", nil),
        Case(#"let label = "TextField(\"Name\", text: $name)""#, nil),
        Case(#"let label = "value: \(format("TextField(")) end""#, nil),
        Case(#"struct MyTextField: View { }"#, nil),

        // Pasteboard
        Case(#"UIPasteboard.general.string = secret"#, .pasteboard),
        Case(#"UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: s]])"#, .pasteboard),
        Case(#"Text(note).textSelection(.enabled)"#, .pasteboard),
        Case(#"Text(note).copyable([note])"#, .pasteboard),
        Case(#"UIPasteboard.general.copySensitive(secret)"#, nil),
        Case(#"UIPasteboard.general.string = secret"#, nil, path: "Occulta/Extensions/UIPasteboard.swift"),
        Case(#"Text(secret).textSelection(.disabled)"#, nil),

        // OS donations
        Case("import CoreSpotlight", .osDonation),
        Case("import UserNotifications", .osDonation),
        Case("@preconcurrency import Intents", .osDonation),
        Case("import struct AppIntents.IntentParameter", .osDonation),
        Case(#"let activity = NSUserActivity(activityType: "contact")"#, .osDonation),
        Case(#"view.userActivity("contact") { _ in }"#, .osDonation),
        Case(#"view.onContinueUserActivity("contact") { _ in }"#, .osDonation),
        Case("struct Open: AppIntent { }", .osDonation),
        Case("UNUserNotificationCenter.current()", .osDonation),
        Case("import SwiftUI", nil),

        // Defaults keys
        Case(#"@AppStorage("currentDepth") private var depth = 0"#, .defaultsKey),
        Case(#"UserDefaults.standard.set(true, forKey: "secureModeEnabled")"#, .defaultsKey),
        Case(#"let defaults = UserDefaults.standard"#, .defaultsKey),
        Case(#"UserDefaults(suiteName: "group.x")?.set(1, forKey: "showFingerprints")"#, .defaultsKey),
        Case(#"@SceneStorage("tab") private var tab = 0"#, .defaultsKey),
        Case("NSUbiquitousKeyValueStore.default.synchronize()", .defaultsKey),
        Case(#"@AppStorage("showFingerprints") private var showFingerprints = false"#, nil),
        Case(#"@AppStorage(WhatsNew.lastSeenKey) private var whatsNewLastSeen = """#, nil),
        Case(#"UserDefaults.standard.removeObject(forKey: "vault.postRestoreActionNeeded")"#, nil),
        Case(#"/// `UserDefaults` key holding the last acknowledged marketing version."#, nil),
    ]

    @Test("Each planted snippet reports only its own rule, and compliant ones report nothing", arguments: OSTraceScannerTests.cases)
    func planted(_ testCase: Case) {
        let rules = OSTraceScanner(source: testCase.source, path: testCase.path).violations().map(\.rule)
        if let expected = testCase.expected {
            #expect(Set(rules) == [expected])
        } else {
            #expect(rules.isEmpty)
        }
    }

    @Test("A violation reports the line it is on")
    func lineNumbers() {
        let source = "import SwiftUI\n\n/* note\n spanning */\nTextField(\"Name\", text: $name)\n"
        let found = OSTraceScanner(source: source, path: "Occulta/View.swift").violations()
        #expect(found.map(\.line) == [5])
    }

    @Test("Every rule has at least one planted violation")
    func everyRuleIsPlanted() {
        let planted = Set(Self.cases.compactMap(\.expected))
        #expect(planted == Set(OSTraceScanner.Rule.allCases))
    }
}

// MARK: - What the searchable rule relies on

/// The scanner accepts `.autocorrectionDisabled()` for a search field only after `.searchable` in
/// the chain. That rests on SwiftUI behaviour, measured here on the real `UISearchTextField`: a
/// modifier after `.searchable` reaches it, and one before is ignored. The probe uses
/// `.autocorrectionDisabled(false)` because SwiftUI's search field already defaults to `.no` on
/// iOS 26, so only turning it *on* shows whether the modifier arrives. If either test fails,
/// SwiftUI changed and the scanner's placement rule needs to change with it.
@Suite("Where .autocorrectionDisabled() reaches a .searchable field", .serialized)
@MainActor
struct SearchableModifierPlacementTests {

    @Test("A modifier after .searchable reaches the search field")
    func afterReaches() async throws {
        let field = try await self.searchField(for: NavigationStack {
            List { Text("a") }.searchable(text: .constant("")).autocorrectionDisabled(false)
        })
        #expect(field.autocorrectionType == .yes)
    }

    @Test("A modifier before .searchable does not")
    func beforeIsIgnored() async throws {
        let field = try await self.searchField(for: NavigationStack {
            List { Text("a") }.autocorrectionDisabled(false).searchable(text: .constant(""))
        })
        #expect(field.autocorrectionType != .yes)
    }

    /// Hosts `view` in a window attached to the test host's scene. A window with no scene is not
    /// reliably laid out, and its navigation search controller then never appears.
    private func searchField(for view: some View) async throws -> UISearchTextField {
        let scene = try #require(UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first)
        let window = UIWindow(windowScene: scene)
        window.rootViewController = UIHostingController(rootView: view)
        window.makeKeyAndVisible()
        defer { window.isHidden = true }
        for _ in 0..<40 {
            window.layoutIfNeeded()
            try await Task.sleep(nanoseconds: 50_000_000)
            if let field = Self.searchField(in: window.rootViewController) { return field }
        }
        return try #require(Self.searchField(in: window.rootViewController), "No search field appeared within 2 s")
    }

    private static func searchField(in controller: UIViewController?) -> UISearchTextField? {
        guard let controller else { return nil }
        if let field = controller.navigationItem.searchController?.searchBar.searchTextField { return field }
        for child in controller.children {
            if let field = Self.searchField(in: child) { return field }
        }
        return nil
    }
}
