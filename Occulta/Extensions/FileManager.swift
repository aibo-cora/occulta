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
    /// read (`bugs.md` Bug 101).
    nonisolated func clearContents(of directory: URL) {
        guard let contents = try? self.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: .skipsHiddenFiles) else { return }
        for file in contents where !file.lastPathComponent.hasSuffix("-Inbox") {
            try? self.removeItem(at: file)
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
