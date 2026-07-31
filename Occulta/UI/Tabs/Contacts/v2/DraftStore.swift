import Foundation
import SwiftData
import CryptoKit

// MARK: - DraftStore

/// Debounced persistence for message drafts. Depends only on `ModelContext` (and an
/// `isSensitive` check the caller provides) — never on `ContactManager` — so a compose
/// screen's draft handling stays decoupled from the app's contact/classification layer.
///
/// Every method takes `modelContext` as a plain parameter rather than storing one.
/// Callers must always pass `contactManager.modelContext` — the same instance
/// `setVisibility` and `activateSecureMode`'s draft re-key pass already use — never
/// `@Environment(\.modelContext)`, which is a *different* context instance and would
/// silently desync from what those two see.
@Observable
final class DraftStore {
    private var saveTask: Task<Void, Never>? = nil

    /// How long `scheduleSave` waits before actually writing. A `let` (not hardcoded
    /// inline) only so tests can use a short interval instead of waiting out the real
    /// debounce window; production call sites all use the default.
    private let debounceDelay: Duration

    /// What this store last confirmed matches disk — set after `load()` and
    /// after every successful `save()`. Used only as a cheap pre-filter for
    /// whether a save is worth attempting at all; never trusted on its own to
    /// skip one. `save()` always re-verifies against the actual persisted row
    /// before it actually skips writing — see `matchesPersisted`.
    private var lastPersisted: (text: String, attachmentIDs: Set<UUID>, wasThreadMode: Bool)? = nil

    init(debounceDelay: Duration = .seconds(2)) {
        self.debounceDelay = debounceDelay
    }

    /// `isSensitive` is a closure, not a `Bool` — it's called once, AFTER the debounce
    /// delay, immediately before the write, never before. A contact's classification can
    /// change during the delay (e.g. the user hides it via Trust Check mid-keystroke);
    /// capturing a `Bool` snapshot at schedule time would let a draft get written to disk
    /// moments after a purge meant to remove it, defeating `save()`'s "Option E" no-write
    /// guarantee for sensitive contacts. Evaluating once, late, also means a burst of
    /// keystrokes pays this check's cost (a DB fetch + Secure Enclave decrypt) at most
    /// once per debounce window instead of once per keystroke — every earlier call in the
    /// same window gets superseded by `saveTask?.cancel()` before its closure ever runs.
    func scheduleSave(
        recipientID:  String,
        isSensitive:  @escaping () -> Bool,
        text:         String,
        messages:     [Occulta.File],
        useThread:    Bool,
        modelContext: ModelContext
    ) {
        self.saveTask?.cancel()
        self.saveTask = Task { [weak self, debounceDelay] in
            try? await Task.sleep(for: debounceDelay)
            guard !Task.isCancelled, let self else { return }
            await self.save(
                recipientID: recipientID, isSensitive: isSensitive(), text: text,
                messages: messages, useThread: useThread, modelContext: modelContext
            )
        }
    }

    /// Immediate, non-debounced save — for `.onDisappear`, where a 2s wait would
    /// risk losing state to backgrounding or termination before it fires.
    func flush(
        recipientID:  String,
        isSensitive:  Bool,
        text:         String,
        messages:     [Occulta.File],
        useThread:    Bool,
        modelContext: ModelContext
    ) async {
        self.saveTask?.cancel()
        await self.save(
            recipientID: recipientID, isSensitive: isSensitive, text: text,
            messages: messages, useThread: useThread, modelContext: modelContext
        )
    }

    /// Decrypts an existing draft for this recipient, if one exists. Call once,
    /// before the user starts typing.
    ///
    /// `payload.basket.files` mixes two kinds of already-committed entries:
    /// attachments (no stored `url` — each one's location is reconstructed
    /// fresh from the row's own id and the file's id via
    /// `Message.Draft.attachmentsFolder(for:)`/`attachmentFilename(for:)`,
    /// never trusted from a path persisted at save time, see FINDINGS.md
    /// "Attachment storage") and, in thread compose mode, already-"sent"
    /// text bubbles (`.text` format, `content` already inline — passed
    /// through as-is, nothing to reconstruct). `payload.draftText` is the
    /// separate, not-yet-committed input field text; `payload.wasThreadMode`
    /// tells the caller which compose UI to restore.
    func load(
        recipientID:  String,
        modelContext: ModelContext
    ) -> (text: String, messages: [Occulta.File], wasThreadMode: Bool)? {
        guard let row = Message.Draft.find(recipientID: recipientID, in: modelContext) else { return nil }
        do {
            guard let key = try Manager.Key().createHybridLocalEncryptionKey() else { return nil }
            let box     = try AES.GCM.SealedBox(combined: row.encryptedContent)
            let plain   = try AES.GCM.open(box, using: key, authenticating: row.aad(for: .content))
            let payload = try JSONDecoder().decode(Message.Draft.Payload.self, from: plain)

            let folder = Message.Draft.attachmentsFolder(for: row.id)
            var loadedMessages: [Occulta.File] = []
            for file in payload.basket.files {
                if case .text = file.format, file.content != nil {
                    loadedMessages.append(file)
                    continue
                }
                let url = folder.appendingPathComponent(Message.Draft.attachmentFilename(for: file))
                var restored = Occulta.File(url: url, format: file.format, date: file.date)
                restored.id = file.id
                loadedMessages.append(restored)
            }
            self.lastPersisted = (payload.draftText, Set(loadedMessages.map(\.id)), payload.wasThreadMode)
            return (payload.draftText, loadedMessages, payload.wasThreadMode)
        } catch {
            // Corrupt or undecryptable draft — treat as if none existed.
            return nil
        }
    }

    /// Persist the current composition as a draft. No-ops if the recipient is
    /// currently sensitive (Option E) — nothing is written for them, matching
    /// today's ephemeral-loss behavior exactly. If there's nothing to save,
    /// deletes any stale existing draft row (and its attachment folder) instead
    /// of writing an empty one.
    private func save(
        recipientID:  String,
        isSensitive:  Bool,
        text:         String,
        messages:     [Occulta.File],
        useThread:    Bool,
        modelContext: ModelContext
    ) async {
        guard !isSensitive else { return }

        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasContent = !trimmed.isEmpty || !messages.isEmpty
        guard hasContent else {
            if let existing = Message.Draft.find(recipientID: recipientID, in: modelContext) {
                Message.Draft.delete(existing, in: modelContext)
                try? modelContext.save()
            }
            self.lastPersisted = nil
            return
        }

        let currentSnapshot = (
            text: trimmed,
            attachmentIDs: Set(messages.map(\.id)),
            wasThreadMode: useThread
        )

        do {
            guard let key = try Manager.Key().createHybridLocalEncryptionKey() else { return }

            let existing = Message.Draft.find(recipientID: recipientID, in: modelContext)

            // Fast pre-filter: only worth checking against disk at all if we
            // believe nothing changed since the last save/load. If the cache
            // already disagrees, a real edit happened — skip straight to
            // writing, no point verifying first.
            if let lastPersisted, lastPersisted == currentSnapshot {
                if let existing, self.matchesPersisted(existing, currentSnapshot, key: key) {
                    return
                }
                // Cache said "unchanged" but disk disagrees — the row is
                // missing, corrupted, or was changed elsewhere. Fall through
                // and write for real rather than trusting a stale belief.
            }

            let draftID = existing?.id ?? UUID()

            // Attachments stay separate encrypted files, referenced by id from
            // the payload's Basket, never inlined into it — see FINDINGS.md,
            // "Attachment storage." Each is copied into place once (same bytes,
            // same per-contact key — no decrypt/re-encrypt) and left untouched
            // on every subsequent save. The folder itself is created lazily, on
            // the first real attachment — a text-only draft never gets one.
            //
            // Already-committed thread text bubbles (ComposeViewModel.addText())
            // are already just inline content — passed through as-is, nothing
            // to copy. The current, not-yet-committed input field text is kept
            // out of this array entirely — it lives in Payload.draftText.
            let folder = Message.Draft.attachmentsFolder(for: draftID)
            var referencedFiles: [Occulta.File] = []
            for file in messages {
                if let sourceURL = file.url {
                    let destinationURL = folder.appendingPathComponent(Message.Draft.attachmentFilename(for: file))
                    if !FileManager.default.fileExists(atPath: destinationURL.path) {
                        if !FileManager.default.fileExists(atPath: folder.path) {
                            try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                            var excludedFolder = folder
                            var resourceValues = URLResourceValues()
                            resourceValues.isExcludedFromBackup = true
                            try? excludedFolder.setResourceValues(resourceValues)
                        }
                        try? FileManager.default.copyItem(at: sourceURL, to: destinationURL)
                    }
                    guard FileManager.default.fileExists(atPath: destinationURL.path) else { continue }
                    var referenced = Occulta.File(format: file.format, date: file.date)
                    referenced.id = file.id
                    referencedFiles.append(referenced)
                } else if file.content != nil {
                    referencedFiles.append(file)
                }
            }

            let payload = Message.Draft.Payload(
                draftText:     trimmed,
                basket:        Basket(files: referencedFiles),
                wasThreadMode: useThread
            )
            let payloadData = try JSONEncoder().encode(payload)

            let recipientData = Data(recipientID.utf8)
            let sealedRecipient = try AES.GCM.seal(
                recipientData, using: key, nonce: AES.GCM.Nonce(),
                authenticating: Message.Draft.aad(id: draftID, field: .recipientID)
            )
            let sealedContent = try AES.GCM.seal(
                payloadData, using: key, nonce: AES.GCM.Nonce(),
                authenticating: Message.Draft.aad(id: draftID, field: .content)
            )
            guard let recipientCombined = sealedRecipient.combined,
                  let contentCombined   = sealedContent.combined
            else { return }

            if let existing {
                existing.encryptedRecipientID = recipientCombined
                existing.encryptedContent     = contentCombined
            } else {
                let draft = Message.Draft(id: draftID, encryptedRecipientID: recipientCombined, encryptedContent: contentCombined)
                modelContext.insert(draft)
            }
            do {
                try modelContext.save()
                // Only trust the cache after a save that actually succeeded —
                // updating it unconditionally would let a silent write failure
                // look identical to "already correctly persisted," causing a
                // later debounce/flush to see "matches cache" and skip retrying
                // entirely, permanently losing this content.
                self.lastPersisted = currentSnapshot
            } catch {
                // Best-effort — failing to save a draft is no worse than today's loss.
            }
        } catch {
            // Best-effort — failing to save a draft is no worse than today's loss.
        }
    }

    /// Decrypts `row`'s persisted content and checks whether it already
    /// matches `snapshot` — the live-truth check that gates whether a save can
    /// actually be skipped. `lastPersisted` alone is never enough: it's only a
    /// memory of what this store last wrote, and can go stale if the row is
    /// ever deleted or changed by something else (an activation re-key pass
    /// purging a corrupted row, for instance). This always re-derives the
    /// answer from the row itself before anything is allowed to skip.
    private func matchesPersisted(
        _ row: Message.Draft,
        _ snapshot: (text: String, attachmentIDs: Set<UUID>, wasThreadMode: Bool),
        key: SymmetricKey
    ) -> Bool {
        guard
            let box     = try? AES.GCM.SealedBox(combined: row.encryptedContent),
            let plain   = try? AES.GCM.open(box, using: key, authenticating: row.aad(for: .content)),
            let payload = try? JSONDecoder().decode(Message.Draft.Payload.self, from: plain)
        else { return false }

        guard payload.draftText == snapshot.text, payload.wasThreadMode == snapshot.wasThreadMode
        else { return false }

        let persistedIDs = Set(payload.basket.files.map(\.id))
        return persistedIDs == snapshot.attachmentIDs
    }
}
