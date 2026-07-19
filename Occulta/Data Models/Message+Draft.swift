//
//  Message+Draft.swift
//  Occulta
//

import Foundation
import SwiftData
import CryptoKit

// MARK: - Message

enum Message { }

// MARK: - Message.Draft

extension Message {

    /// A single in-progress, unsent composition — at most one per recipient.
    ///
    /// Named `Message.Draft`, not `ContactDraft`: `Contact.Draft` already exists
    /// (`Contact+Draft.swift`) as an unrelated staging struct for editing a
    /// contact's profile fields. See `Docs/Features/Message Persistence/FINDINGS.md`,
    /// "Drafts — Resolved Design", for the full design rationale.
    @Model
    final class Draft {

        // MARK: Persisted fields

        /// Row identity and the on-disk attachment folder name — opaque, carries
        /// no meaning outside this row.
        var id: UUID = UUID()

        /// AES-256-GCM ciphertext of the recipient's contact/group identifier.
        /// Sealed with the canonical local DB key; AAD = `aad(for: .recipientID)`.
        var encryptedRecipientID: Data = Data()

        /// AES-256-GCM ciphertext of a sealed `Basket` (draft text + attachments,
        /// bundled together so there's only ever one thing to crypto-erase).
        /// Sealed with the canonical local DB key; AAD = `aad(for: .content)`.
        var encryptedContent: Data = Data()

        // MARK: Init

        /// `id` must be provided explicitly, not left to default, whenever the
        /// caller already sealed `encryptedRecipientID`/`encryptedContent` against
        /// a specific id via `Message.Draft.aad(id:field:)` — which every real
        /// caller does, since the AAD has to exist before the row does. Passing a
        /// mismatched (or default-generated) id here would silently produce a row
        /// whose ciphertext fails GCM authentication forever; there's no separate
        /// "fix up the id afterward" step to forget.
        init(id: UUID, encryptedRecipientID: Data, encryptedContent: Data) {
            self.id                   = id
            self.encryptedRecipientID = encryptedRecipientID
            self.encryptedContent     = encryptedContent
        }

        // MARK: AAD construction

        /// Identifies which ciphertext field an AAD blob belongs to — prevents
        /// cross-field ciphertext swaps (sealing `encryptedContent` with
        /// `.recipientID`'s AAD, or vice versa) from passing GCM authentication.
        enum Field: UInt8 {
            case recipientID = 0x01
            case content     = 0x02
        }

        /// Authenticated additional data for AES-GCM seal/open of a specific field.
        ///
        /// Wire encoding: `id.uuidString` (UTF-8, 36 bytes) ∥ `field.rawValue`
        /// (1 byte). No timestamp component — unlike `VaultEntry.aad(for:)`,
        /// `Message.Draft` has no persisted creation date to bind one to (see
        /// "Drafts — Resolved Design" in FINDINGS.md: draft count is too small
        /// for a plaintext timestamp to be worth the metadata leak).
        ///
        /// ⚠️ This layout is a sealed contract. Any change to field order,
        /// encoding, or byte width makes existing ciphertext unreadable.
        func aad(for field: Field) -> Data {
            Self.aad(id: self.id, field: field)
        }

        /// Static variant for callers that need the AAD before a row exists —
        /// e.g. sealing a brand-new draft's fields with an `id` not yet backed
        /// by an inserted `Draft` instance.
        static func aad(id: UUID, field: Field) -> Data {
            var data = Data()
            data.append(id.uuidString.data(using: .utf8)!)
            data.append(field.rawValue)
            return data
        }

        // MARK: Lookup

        /// Finds the draft for a given recipient, if one exists. `encryptedRecipientID`
        /// isn't queryable (it's ciphertext), so this decrypts and compares every row —
        /// acceptable because draft count is bounded by contact count, not message volume.
        static func find(recipientID: String, in context: ModelContext) -> Message.Draft? {
            guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else { return nil }
            let rows = (try? context.fetch(FetchDescriptor<Message.Draft>())) ?? []
            return rows.first { row in
                guard let box     = try? AES.GCM.SealedBox(combined: row.encryptedRecipientID),
                      let opened  = try? AES.GCM.open(box, using: key, authenticating: row.aad(for: .recipientID)),
                      let decoded = String(data: opened, encoding: .utf8)
                else { return false }
                return decoded == recipientID
            }
        }

        // MARK: Attachment storage

        /// `Application Support/Drafts/<id>/` — one folder per draft, named by the
        /// row's own opaque id, never by the recipient's identifier. Holds each
        /// attachment as its own file, named by its `Occulta.File.id`, still sealed
        /// under the contact's per-contact key (see FINDINGS.md, "Key" and
        /// "Attachment storage" — attachment bytes are never re-sealed under the
        /// canonical DB key that protects this row).
        static func attachmentsFolder(for id: UUID) -> URL {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            return appSupport
                .appendingPathComponent("Drafts", isDirectory: true)
                .appendingPathComponent(id.uuidString, isDirectory: true)
        }

        /// On-disk filename for a given attachment within its draft's folder —
        /// `<file.id>` plus a real extension when one is known, so AVFoundation's
        /// content-type detection (`URL.pathExtension`, used for video playback)
        /// still works after a draft is reloaded. The tradeoff: a directory listing
        /// now reveals attachment *type* (`.mp4`, `.jpg`), not just an opaque id —
        /// still never the original filename, which stays inside the sealed
        /// `Basket`'s `format` metadata.
        ///
        /// Used identically by both the save side (to know where to copy a file
        /// to) and the load side (to reconstruct a fresh, correct URL rather than
        /// trusting one persisted at save time — see `attachmentsFolder(for:)`
        /// callers in `DraftStore`).
        static func attachmentFilename(for file: Occulta.File) -> String {
            guard case .file(let meta) = file.format,
                  let ext = meta.extension, !ext.isEmpty
            else { return file.id.uuidString }
            return "\(file.id.uuidString).\(ext)"
        }

        // MARK: Lifecycle (classification-driven)

        /// Deletes a draft row and its entire attachment folder together — the
        /// only correct way to delete a draft. Attachment files aren't protected
        /// by the row's own key rotation (see FINDINGS.md), so deleting just the
        /// row would leave their content readable on disk, referenced by nothing.
        /// Does not save `modelContext` — callers that need the deletion committed
        /// immediately are responsible for that, matching existing call sites.
        static func delete(_ draft: Message.Draft, in modelContext: ModelContext) {
            try? FileManager.default.removeItem(at: attachmentsFolder(for: draft.id))
            modelContext.delete(draft)
        }

        /// Deletes the draft for a recipient, if any. Called when that recipient
        /// becomes sensitive — Option E: sensitive contacts get zero draft
        /// persistence going forward, and any draft already written before the
        /// classification change is purged rather than left to linger.
        static func purge(recipientID: String, in modelContext: ModelContext) {
            guard let draft = find(recipientID: recipientID, in: modelContext) else { return }
            delete(draft, in: modelContext)
        }

        /// Secure Mode activation pass: every draft row either survives re-keyed
        /// under the staged key, or is purged (row and attachment folder) — never
        /// left encrypted under a key about to be destroyed. Selective, matching
        /// §S7's preserve-and-rekey precedent for `VaultEntry`, not a blanket wipe.
        ///
        /// A draft survives if its recipient isn't a known contact (a group, not yet
        /// classified sensitive/safe here — see FINDINGS.md) or is in
        /// `safeContactIdentifiers` (visible at the new, deeper layer too). Anything
        /// undecryptable under `oldKey`, or that fails to re-seal, is purged rather
        /// than left in a broken or ambiguous state — fail-safe to gone.
        ///
        /// Attachment *files* are never touched here, surviving or not: a surviving
        /// contact's per-contact key keeps deriving correctly after their profile is
        /// re-encrypted elsewhere in activation, so their attachment folder needs no
        /// re-seal; a purged contact's folder is deleted outright by `delete(_:in:)`,
        /// which is the only erasure mechanism attachment files get (see FINDINGS.md,
        /// "Key" — they're never protected by this row's key rotation).
        static func reKeyOrPurgeAll(
            safeContactIdentifiers: Set<String>,
            allContactIdentifiers:  Set<String>,
            oldKey: SymmetricKey,
            newKey: SymmetricKey,
            in modelContext: ModelContext
        ) throws {
            for draft in try modelContext.fetch(FetchDescriptor<Message.Draft>()) {
                guard
                    let recipientBox   = try? AES.GCM.SealedBox(combined: draft.encryptedRecipientID),
                    let recipientPlain = try? AES.GCM.open(recipientBox, using: oldKey, authenticating: draft.aad(for: .recipientID)),
                    let recipientID    = String(data: recipientPlain, encoding: .utf8)
                else {
                    delete(draft, in: modelContext)
                    continue
                }

                let isKnownContact = allContactIdentifiers.contains(recipientID)
                let survives = !isKnownContact || safeContactIdentifiers.contains(recipientID)
                guard survives else {
                    delete(draft, in: modelContext)
                    continue
                }

                guard
                    let contentBox   = try? AES.GCM.SealedBox(combined: draft.encryptedContent),
                    let contentPlain = try? AES.GCM.open(contentBox, using: oldKey, authenticating: draft.aad(for: .content)),
                    let newRecipient = try? AES.GCM.seal(recipientPlain, using: newKey, nonce: AES.GCM.Nonce(),
                                                          authenticating: draft.aad(for: .recipientID)).combined,
                    let newContent   = try? AES.GCM.seal(contentPlain, using: newKey, nonce: AES.GCM.Nonce(),
                                                          authenticating: draft.aad(for: .content)).combined
                else {
                    delete(draft, in: modelContext)
                    continue
                }

                draft.encryptedRecipientID = newRecipient
                draft.encryptedContent     = newContent
            }
            try modelContext.save()
        }
    }
}
