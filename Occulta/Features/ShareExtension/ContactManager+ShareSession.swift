//
//  ContactManager+ShareSession.swift
//  Occulta
//
//  Cleanup of the share extension's staging directory. Main app only.
//
//  This file used to hold `syncShareIndex()`, which mirrored the contact list into
//  `ShareIndex.sqlite` in the App Group so the extension could draw a picker. Keeping that
//  mirror at the right depth was the whole of Bugs 6, 65, 66, 67, 68, and 69. The picker
//  moved into the app (Bug 84), so the mirror has no reader and is gone.
//

import Foundation

extension ContactManager {

    /// Delete stale or half-written share sessions, and any leftovers from the mirror.
    ///
    /// Called on every `scenePhase == .active`.
    func cleanupPendingSessions() {
        guard let container = ShareSession.sharedContainer else { return }

        ShareSession.sweep(in: container, keyManager: ShareIndexKeyManager())
        ShareSession.removeLegacyContactIndex(in: container)
    }
}
