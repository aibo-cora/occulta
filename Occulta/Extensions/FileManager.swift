//
//  FileManager.swift
//  Occulta
//
//  Created by Yura on 3/7/26.
//

import Foundation

extension FileManager {
    /// Deletes ALL contents of the app's temporary directory (but keeps the folder itself),
    /// except the system's `<bundle-id>-Inbox` — see `clearContents(of:)`.
    func clearTemporaryDirectory() {
        Task.detached {
            self.clearContents(of: self.temporaryDirectory)
        }
    }

    /// Deletes every item in `directory` except folders named `*-Inbox`.
    ///
    /// iOS copies a file opened with "Open in Occulta" into `tmp/<bundle-id>-Inbox/` *before*
    /// launching the app, so on a cold launch this sweep would race `handleOpenURL` for the
    /// incoming file and could delete it unread. `handleOpenURL` deletes that copy itself once
    /// read, and `clearInboxes()` clears the folder when the app goes to the background
    /// (`bugs.md` Bug 101).
    nonisolated func clearContents(of directory: URL) {
        guard let contents = try? self.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: .skipsHiddenFiles) else { return }
        for file in contents where !file.lastPathComponent.hasSuffix("-Inbox") {
            try? self.removeItem(at: file)
        }
    }

    /// Deletes the copies iOS left in the app's Inbox folders for "Open in Occulta", and the
    /// folders themselves (`bugs.md` Bug 101): `Documents/Inbox/`, where iOS 26 puts them and
    /// which is in device backups, and any `tmp/<bundle-id>-Inbox/`.
    ///
    /// Called when the app goes to the background. By then every delivered file has been read:
    /// iOS brings the app to the foreground to hand a file over, and `handleOpenURL` reads it
    /// straight away. So unlike a sweep at launch, this can't delete an incoming file unread. It
    /// removes what `handleOpenURL`'s own delete can't reach: copies left by versions before
    /// that fix, and a copy stranded by a crash between delivery and read. Removing the folder
    /// too leaves no sign that a file was ever opened into the app.
    ///
    /// Not by age: iOS gives the copy the original's dates, so an old file arrives looking old.
    nonisolated func clearInboxes(
        documents: URL? = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first,
        temporary: URL = FileManager.default.temporaryDirectory
    ) {
        var inboxes = documents.map { [$0.appendingPathComponent("Inbox", isDirectory: true)] } ?? []
        let tmpItems = (try? self.contentsOfDirectory(at: temporary, includingPropertiesForKeys: nil)) ?? []
        inboxes += tmpItems.filter { $0.lastPathComponent.hasSuffix("-Inbox") }

        for inbox in inboxes {
            try? self.removeItem(at: inbox)
        }
    }

    /// Whether `url` lies inside this app's own sandbox container.
    ///
    /// Decides whether a file handed to `handleOpenURL` is a copy iOS made for us (inside,
    /// `tmp/<bundle-id>-Inbox/` or `Documents/Inbox/`, safe to delete) or the user's original
    /// opened in place from Files (outside, never touched). Symlinks are resolved first, so a
    /// link inside the container pointing outside it counts as outside; comparing path
    /// components rather than string prefixes keeps a sibling like `<home>X` from matching.
    nonisolated func isInsideAppContainer(_ url: URL) -> Bool {
        let home   = URL(fileURLWithPath: NSHomeDirectory()).resolvingSymlinksInPath().standardizedFileURL.pathComponents
        let target = url.resolvingSymlinksInPath().standardizedFileURL.pathComponents
        return target.count > home.count && Array(target.prefix(home.count)) == home
    }
}
