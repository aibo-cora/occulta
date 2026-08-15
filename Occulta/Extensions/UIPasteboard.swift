//
//  UIPasteboard.swift
//  Occulta
//
//  Created by Yura on 8/15/26.
//

import UIKit

extension UIPasteboard {
    /// How long a sensitive copy stays on the pasteboard before iOS clears it.
    private static let sensitiveCopyLifetime: TimeInterval = 120

    /// Copies text that must not leave the device.
    ///
    /// `UIPasteboard.general` is system-wide and, by default, syncs to the user's other
    /// Apple devices through Universal Clipboard — so a decrypted vault entry assigned to
    /// `.string` leaves the device over the network, which nothing else in this app does.
    /// `.localOnly` suppresses that. `.expirationDate` bounds how long the plaintext sits
    /// readable by every other app on the device.
    ///
    /// Use this for anything that was encrypted at rest. Assigning `.string` directly gets
    /// neither protection, which is the bug this exists to stop recurring.
    func copySensitive(_ text: String) {
        self.setItems(
            [[UIPasteboard.typeAutomatic: text]],
            options: [
                .localOnly:      true,
                .expirationDate: Date().addingTimeInterval(Self.sensitiveCopyLifetime)
            ]
        )
    }
}
