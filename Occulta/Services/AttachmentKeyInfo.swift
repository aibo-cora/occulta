//
//  AttachmentKeyInfo.swift
//  Occulta
//
//  The HKDF info string of the `.eatt` per-file key. A file of its own, so the share extension, which seals the
//  files it stages and must not compile the key manager, can share it with the app. STREAMING_SPEC §8.4.
//

import Foundation

enum AttachmentKeyInfo {
    /// Domain separator for the per-file key derived from a contact (or staging) key and the file's salt.
    /// It is an input to the derivation: changing it orphans every sealed attachment.
    nonisolated static let fileKey = "Occulta-v1-file-key-2025".data(using: .utf8)!
}
