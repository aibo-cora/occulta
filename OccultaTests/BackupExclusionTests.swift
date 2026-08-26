//
//  BackupExclusionTests.swift
//  OccultaTests
//
//  Bug 70 — the lockout counter lives in the SwiftData store, and restoring from an
//  iTunes/Finder backup replaces the whole store file, silently reverting it to zero.
//  The fix (`RootView.excludeStoreFromBackup(url:)`, commit a320e3b) excludes the store
//  and its -wal/-shm sidecars from both iCloud and local backups via the standard
//  `isExcludedFromBackup` resource value. It shipped in June and has been called at
//  init and on every save since, but had zero automated coverage until this file.
//
//  Cannot exercise a real iTunes/Finder backup-and-restore cycle here — that's an
//  out-of-process OS mechanism, not something a unit test controls. What's verifiable
//  is the contract the fix actually depends on: that the flag gets set on the store and
//  both sidecars, and that a sidecar created *after* the first call still ends up
//  covered once the function runs again — which is the whole reason
//  `reapplyFileProtection()` re-invokes this on every save rather than once at launch
//  (SQLite creates/recreates -wal/-shm at points in its own lifecycle).
//

import Testing
import Foundation
@testable import Occulta

@Suite("Bug 70 — backup exclusion for the SwiftData store and its sidecars")
@MainActor
struct BackupExclusionTests {

    private func makeTempStoreURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("BackupExclusionTests-\(UUID().uuidString)")
            .appendingPathExtension("sqlite")
    }

    private func isExcluded(_ url: URL) throws -> Bool {
        try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup ?? false
    }

    @Test("Excludes the main store file from backup")
    func excludesMainFile() throws {
        let url = self.makeTempStoreURL()
        try Data("store".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        RootView.excludeStoreFromBackup(url: url)

        #expect(try self.isExcluded(url), "the main store file must be excluded from backup")
    }

    @Test("Excludes both WAL and SHM sidecars when they already exist")
    func excludesExistingSidecars() throws {
        let url = self.makeTempStoreURL()
        let wal = URL(fileURLWithPath: url.path + "-wal")
        let shm = URL(fileURLWithPath: url.path + "-shm")
        try Data("store".utf8).write(to: url)
        try Data("wal".utf8).write(to: wal)
        try Data("shm".utf8).write(to: shm)
        defer {
            for f in [url, wal, shm] { try? FileManager.default.removeItem(at: f) }
        }

        RootView.excludeStoreFromBackup(url: url)

        #expect(try self.isExcluded(wal), "the WAL sidecar must be excluded from backup")
        #expect(try self.isExcluded(shm), "the SHM sidecar must be excluded from backup")
    }

    /// SQLite creates -wal/-shm lazily and can recreate them later (e.g. after a
    /// checkpoint), and a freshly (re)created file starts with no resource values set.
    /// A sidecar that doesn't exist yet at call time is silently skipped — `setResourceValues`
    /// throws "no such file" and `excludeStoreFromBackup` swallows it with `try?` — which is
    /// exactly why `reapplyFileProtection()` calls this again on every save instead of once
    /// at launch. This test pins that recovery path directly.
    @Test("A sidecar created after the first call is covered once the function runs again")
    func coversLateCreatedSidecar() throws {
        let url = self.makeTempStoreURL()
        let wal = URL(fileURLWithPath: url.path + "-wal")
        try Data("store".utf8).write(to: url)
        defer {
            for f in [url, wal] { try? FileManager.default.removeItem(at: f) }
        }

        // First call: the WAL sidecar doesn't exist yet, so it's silently skipped —
        // not a crash, but not covered either.
        RootView.excludeStoreFromBackup(url: url)
        #expect(!FileManager.default.fileExists(atPath: wal.path))

        // SQLite creates it later, mid-session.
        try Data("wal".utf8).write(to: wal)

        // Second call — the same one reapplyFileProtection makes on every save.
        RootView.excludeStoreFromBackup(url: url)

        #expect(try self.isExcluded(wal), """
            A sidecar created after the store's first exclusion pass must still end up \
            excluded once excludeStoreFromBackup runs again — this is the only thing \
            standing between a SQLite-recreated WAL file and reappearing in an iTunes/ \
            Finder backup, carrying the lockout counter's history with it.
            """)
    }
}
