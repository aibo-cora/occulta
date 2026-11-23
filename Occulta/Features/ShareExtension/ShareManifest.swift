//
//  ShareManifest.swift
//  Occulta
//
//  Codable struct for the encrypted handoff manifest between the share extension and main app.
//  Linked by both the main app and the share extension.
//

import Foundation
import CryptoKit

nonisolated struct ShareManifest: Codable {
    /// No recipient field. The extension stages files; the main app picks who they are
    /// encrypted for, after the PIN (Bug 84).
    ///
    /// The session directory's name. The app refuses a manifest found under any other name, so one can't be moved into
    /// another session (Bug 213). A manifest from a build before 2.0.5 has none and doesn't decode: that session is
    /// refused, and the person shares again.
    let sessionID: String
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

    /// Domain separator for `sessionKey`. An input to the derivation: changing it orphans every staged session.
    private static let sessionKeyInfo = "Occulta-v1-share-session-2026".data(using: .utf8)!

    /// The key a session's files are sealed under: the staging key, bound to the session's ID (Bug 213). A file staged
    /// for another session doesn't open under it, so a file can't be moved from one session to another, now or after
    /// the app has checked it.
    static func sessionKey(staging: SymmetricKey, sessionID: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: staging,
            salt: Data(sessionID.utf8),
            info: Self.sessionKeyInfo,
            outputByteCount: 32
        )
    }
}
