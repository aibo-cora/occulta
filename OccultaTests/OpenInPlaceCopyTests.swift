//
//  OpenInPlaceCopyTests.swift
//  OccultaTests
//
//  Bug 101 — a file opened with "Open in Occulta" arrives as a copy iOS makes inside the app's
//  own container, and nothing deleted it. `handleOpenURL` now deletes any opened file that
//  `FileManager.isInsideAppContainer` places inside the container, and keeps anything outside
//  it, which is the user's original opened in place from Files. That predicate is what stands
//  between the fix and deleting a user's file, so it is pinned here. `handleOpenURL` itself lives
//  on `OccultaApp`, which can't be constructed in a test (`RECOVERY_BUFFER_LAYERING.md` §2.1).
//
//  The launch sweep of `tmp/` must leave `*-Inbox` alone: on a cold launch iOS has already put
//  the incoming copy there, and the sweep would race `handleOpenURL` for it.
//

import Testing
import Foundation
@testable import Occulta

@Suite("Bug 101 — the copy iOS makes for Open in Occulta")
struct OpenInPlaceCopyTests {

    private let fileManager = FileManager.default

    private func makeScratchDirectory() throws -> URL {
        let url = self.fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try self.fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    // MARK: - isInsideAppContainer

    @Test("A file in tmp/<bundle-id>-Inbox is inside the container")
    func tmpInboxCopyIsInside() throws {
        let inbox = self.fileManager.temporaryDirectory.appendingPathComponent("com.occulta.test-Inbox-\(UUID().uuidString)", isDirectory: true)
        try self.fileManager.createDirectory(at: inbox, withIntermediateDirectories: true)
        defer { try? self.fileManager.removeItem(at: inbox) }
        let file = inbox.appendingPathComponent("backup.occbak")
        try Data([1]).write(to: file)

        #expect(self.fileManager.isInsideAppContainer(file))
    }

    @Test("A file in Documents/Inbox is inside the container")
    func documentsInboxCopyIsInside() throws {
        let documents = try #require(self.fileManager.urls(for: .documentDirectory, in: .userDomainMask).first)
        let file = documents.appendingPathComponent("Inbox").appendingPathComponent("\(UUID().uuidString).occ")

        #expect(self.fileManager.isInsideAppContainer(file))
    }

    @Test("The container's own root is not inside it")
    func homeItselfIsNotInside() {
        #expect(!self.fileManager.isInsideAppContainer(URL(fileURLWithPath: NSHomeDirectory())))
    }

    @Test("A sibling whose path merely starts with the container's path is outside")
    func siblingWithSharedPrefixIsOutside() {
        let sibling = URL(fileURLWithPath: NSHomeDirectory() + "X").appendingPathComponent("file.occ")

        #expect(!self.fileManager.isInsideAppContainer(sibling))
    }

    @Test("A path outside the container is outside")
    func unrelatedPathIsOutside() {
        #expect(!self.fileManager.isInsideAppContainer(URL(fileURLWithPath: "/private/var/mobile/Documents/file.occbak")))
    }

    @Test("A path that climbs out with .. is outside")
    func dotDotEscapeIsOutside() {
        let escaping = URL(fileURLWithPath: NSHomeDirectory() + "/tmp/../../outside.occ")

        #expect(!self.fileManager.isInsideAppContainer(escaping))
    }

    @Test("A symlink inside the container pointing outside it is outside")
    func symlinkToOutsideIsOutside() throws {
        let scratch = try self.makeScratchDirectory()
        defer { try? self.fileManager.removeItem(at: scratch) }
        let link = scratch.appendingPathComponent("link.occ")
        try self.fileManager.createSymbolicLink(at: link, withDestinationURL: URL(fileURLWithPath: "/usr/bin/true"))

        #expect(!self.fileManager.isInsideAppContainer(link))
    }

    // MARK: - clearContents

    @Test("The sweep deletes ordinary items and keeps *-Inbox folders")
    func sweepKeepsInbox() throws {
        let scratch = try self.makeScratchDirectory()
        defer { try? self.fileManager.removeItem(at: scratch) }
        let inbox = scratch.appendingPathComponent("com.occulta.Occulta-Inbox", isDirectory: true)
        try self.fileManager.createDirectory(at: inbox, withIntermediateDirectories: true)
        let incoming = inbox.appendingPathComponent("backup.occbak")
        try Data([1]).write(to: incoming)
        let attachment = scratch.appendingPathComponent("attachment.jpg")
        try Data([2]).write(to: attachment)
        let folder = scratch.appendingPathComponent("decrypted", isDirectory: true)
        try self.fileManager.createDirectory(at: folder, withIntermediateDirectories: true)

        self.fileManager.clearContents(of: scratch)

        #expect(self.fileManager.fileExists(atPath: incoming.path))
        #expect(!self.fileManager.fileExists(atPath: attachment.path))
        #expect(!self.fileManager.fileExists(atPath: folder.path))
    }
    // MARK: - clearInboxes

    /// Runs when the app goes to the background, so it must take every Inbox, with the copies
    /// earlier versions left there, and nothing else.
    @Test("Clearing the Inboxes removes both Inbox folders and their copies, and nothing else")
    func clearInboxesRemovesOnlyInboxes() throws {
        let documents = try self.makeScratchDirectory()
        let temporary = try self.makeScratchDirectory()
        defer {
            try? self.fileManager.removeItem(at: documents)
            try? self.fileManager.removeItem(at: temporary)
        }
        let documentsInbox = documents.appendingPathComponent("Inbox", isDirectory: true)
        let tmpInbox       = temporary.appendingPathComponent("com.occulta.Occulta-Inbox", isDirectory: true)
        for inbox in [documentsInbox, tmpInbox] {
            try self.fileManager.createDirectory(at: inbox, withIntermediateDirectories: true)
            try Data([1]).write(to: inbox.appendingPathComponent("left-by-v1.10.3.occbak"))
        }
        let otherDocument = documents.appendingPathComponent("export.occbak")
        let otherTemp     = temporary.appendingPathComponent("attachment.jpg")
        try Data([2]).write(to: otherDocument)
        try Data([3]).write(to: otherTemp)

        self.fileManager.clearInboxes(documents: documents, temporary: temporary)

        #expect(!self.fileManager.fileExists(atPath: documentsInbox.path))
        #expect(!self.fileManager.fileExists(atPath: tmpInbox.path))
        #expect(self.fileManager.fileExists(atPath: otherDocument.path))
        #expect(self.fileManager.fileExists(atPath: otherTemp.path))
    }

    @Test("Clearing the Inboxes when there are none does nothing")
    func clearInboxesWithNoneIsHarmless() throws {
        let documents = try self.makeScratchDirectory()
        let temporary = try self.makeScratchDirectory()
        defer {
            try? self.fileManager.removeItem(at: documents)
            try? self.fileManager.removeItem(at: temporary)
        }

        self.fileManager.clearInboxes(documents: documents, temporary: temporary)

        #expect(self.fileManager.fileExists(atPath: documents.path))
        #expect(self.fileManager.fileExists(atPath: temporary.path))
    }
}
