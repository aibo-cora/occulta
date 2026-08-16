//
//  ShareManifest.swift
//  Occulta
//
//  Codable struct for the encrypted handoff manifest between the share extension and main app.
//  Linked by both the main app and the share extension.
//

import Foundation

struct ShareManifest: Codable {
    /// No recipient field. The extension stages files; the main app picks who they are
    /// encrypted for, after the PIN (Bug 84). A manifest written by a pre-1.11.0 extension
    /// still decodes — `JSONDecoder` ignores its now-unknown `contactIdentifier` — and a
    /// session staged by this build and left for an older app is caught by the 1-hour sweep.
    ///
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
