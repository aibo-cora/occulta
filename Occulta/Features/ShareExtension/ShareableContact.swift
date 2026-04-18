//
//  ShareableContact.swift
//  Occulta
//
//  SwiftData model for the encrypted contact index in the shared App Group container.
//  Linked by both the main app and the share extension.
//

import Foundation
import SwiftData

@Model
final class ShareableContact {
    /// AES-GCM encrypted contact identifier (the hash-based ID from Contact.Profile).
    var encryptedIdentifier: Data = Data()
    /// AES-GCM encrypted display name (givenName + " " + familyName).
    var encryptedDisplayName: Data = Data()

    init(encryptedIdentifier: Data, encryptedDisplayName: Data) {
        self.encryptedIdentifier = encryptedIdentifier
        self.encryptedDisplayName = encryptedDisplayName
    }
}
