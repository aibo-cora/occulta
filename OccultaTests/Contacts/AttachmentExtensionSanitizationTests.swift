//
//  AttachmentExtensionSanitizationTests.swift
//  OccultaTests
//
//  Regression coverage for the inbound-attachment path traversal finding:
//  OccultaApp.swift built a temp-file URL via
//  `tempDir.appendingPathComponent(metadata.name ?? UUID().uuidString)
//           .appendingPathExtension(metadata.extension ?? "bin")`
//  where `metadata` comes from the decrypted, sender-controlled Basket on the inbound
//  message path. `metadata.name` is now dropped entirely in favor of a fresh UUID;
//  `metadata.extension` is validated by `sanitizedFilesystemExtension` before being
//  used in `.appendingPathExtension`, since a crafted value like "../../etc/passwd"
//  could otherwise steer the write outside tempDir to a guessable sandbox path.
//

import Testing
import Foundation
@testable import Occulta

@Suite("Occulta.File.Metadata — sanitizedFilesystemExtension")
struct AttachmentExtensionSanitizationTests {

    @Test func pathTraversalSequence_fallsBackToBin() {
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension("../../etc/passwd") == "bin")
    }

    @Test func pathTraversalTargetingAppSupport_fallsBackToBin() {
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension("../Library/Application Support/default.store") == "bin")
    }

    @Test func embeddedSlash_fallsBackToBin() {
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension("jpg/evil") == "bin")
    }

    @Test func doubleExtensionAttempt_fallsBackToBin() {
        // A "." embedded in the supposed extension — e.g. trying to smuggle a second
        // extension — is rejected outright rather than partially accepted.
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension("jpg.exe") == "bin")
    }

    @Test func nilExtension_fallsBackToBin() {
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension(nil) == "bin")
    }

    @Test func emptyExtension_fallsBackToBin() {
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension("") == "bin")
    }

    @Test func overlyLongExtension_fallsBackToBin() {
        // Even if every character is alphanumeric, an implausibly long "extension"
        // (e.g. a smuggled blob) is rejected by the length guard.
        let long = String(repeating: "a", count: 200)
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension(long) == "bin")
    }

    @Test func nonASCIINumeral_fallsBackToBin() {
        // Regression guard for an operator-precedence slip during implementation:
        // `$0.isASCII && $0.isLetter || $0.isNumber` would have let a non-ASCII
        // "number" character (Character.isNumber is true for many non-ASCII digits)
        // through unchecked. Correct precedence requires ASCII for both branches.
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension("\u{0661}") == "bin")  // Arabic-Indic digit one
    }

    @Test func ordinaryExtensions_passThroughUnchanged() {
        for ext in ["jpg", "png", "pdf", "mp4", "heic", "mov", "docx"] {
            #expect(Occulta.File.Metadata.sanitizedFilesystemExtension(ext) == ext)
        }
    }

    @Test func uppercaseExtension_passesThroughUnchanged() {
        // Metadata.init already lowercases on decode — this function doesn't need to
        // re-lowercase, just confirm it doesn't reject a case it's never actually fed
        // in practice.
        #expect(Occulta.File.Metadata.sanitizedFilesystemExtension("JPG") == "JPG")
    }
}
