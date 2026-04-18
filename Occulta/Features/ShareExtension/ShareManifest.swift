//
//  ShareManifest.swift
//  Occulta
//
//  Codable struct for the encrypted handoff manifest between the share extension and main app.
//  Linked by both the main app and the share extension.
//

import Foundation

struct ShareManifest: Codable {
    /// Contact identifier — matches Contact.Profile.identifier in the main store.
    let contactIdentifier: String
    /// One entry per file, in order.
    let files: [FileEntry]
    /// Timestamp for stale session detection.
    let createdAt: Date

    struct FileEntry: Codable {
        /// Filename in the session directory ("0.tmp", "1.tmp", ...).
        let filename: String
        /// UTI of the original content (e.g., "public.jpeg", "com.adobe.pdf").
        let uti: String
        /// Original file extension (e.g., "jpg", "pdf").
        let fileExtension: String
    }
}
