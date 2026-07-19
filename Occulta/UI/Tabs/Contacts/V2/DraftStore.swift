import Foundation
import SwiftData
import CryptoKit

// MARK: - DraftStore

/// Debounced persistence for message drafts. Depends only on `ModelContext` (and an
/// `isSensitive` flag the caller computes) — never on `ContactManager` — so a compose
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

    func scheduleSave(
        recipientID:  String,
        isSensitive:  Bool,
        text:         String,
        messages:     [Occulta.File],
        modelContext: ModelContext
    ) {
        self.saveTask?.cancel()
        self.saveTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled, let self else { return }
            await self.save(
                recipientID: recipientID, isSensitive: isSensitive, text: text,
                messages: messages, modelContext: modelContext
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
        modelContext: ModelContext
    ) async {
        self.saveTask?.cancel()
        await self.save(
            recipientID: recipientID, isSensitive: isSensitive, text: text,
            messages: messages, modelContext: modelContext
        )
    }

    /// Decrypts an existing draft for this recipient, if one exists. Call once,
    /// before the user starts typing.
    ///
    /// Attachment entries in the decrypted `Basket` carry no stored `url` — each
    /// one's location is reconstructed fresh from the row's own id and the
    /// file's id via `Message.Draft.attachmentsFolder(for:)`/`attachmentFilename(for:)`,
    /// never trusted from a path persisted at save time (see FINDINGS.md,
    /// "Attachment storage"). The resulting file is still sealed under the
    /// contact's per-contact key — the exact key the compose UI's own
    /// `AttachmentManager` already holds — so no decrypt/re-encrypt/temp-copy is
    /// needed to make it usable again.
    func load(
        recipientID:  String,
        modelContext: ModelContext
    ) -> (text: String, messages: [Occulta.File])? {
        guard let row = Message.Draft.find(recipientID: recipientID, in: modelContext) else { return nil }
        do {
            guard let key = try Manager.Key().createHybridLocalEncryptionKey() else { return nil }
            let box   = try AES.GCM.SealedBox(combined: row.encryptedContent)
            let plain = try AES.GCM.open(box, using: key, authenticating: row.aad(for: .content))
            let basket = try JSONDecoder().decode(Basket.self, from: plain)

            let folder = Message.Draft.attachmentsFolder(for: row.id)
            var text = ""
            var loadedMessages: [Occulta.File] = []
            for file in basket.files {
                if case .text = file.format, let data = file.content,
                   let str = String(data: data, encoding: .utf8) {
                    text = str
                    continue
                }
                let url = folder.appendingPathComponent(Message.Draft.attachmentFilename(for: file))
                var restored = Occulta.File(url: url, format: file.format, date: file.date)
                restored.id = file.id
                loadedMessages.append(restored)
            }
            return (text, loadedMessages)
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
            return
        }

        do {
            guard let key = try Manager.Key().createHybridLocalEncryptionKey() else { return }

            let existing = Message.Draft.find(recipientID: recipientID, in: modelContext)
            let draftID  = existing?.id ?? UUID()

            // Attachments stay separate encrypted files, referenced by URL from the
            // Basket, never inlined into it — see FINDINGS.md, "Attachment storage."
            // Each is copied into place once (same bytes, same per-contact key —
            // no decrypt/re-encrypt) and left untouched on every subsequent save.
            let folder = Message.Draft.attachmentsFolder(for: draftID)
            if !FileManager.default.fileExists(atPath: folder.path) {
                try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                var excludedFolder = folder
                var resourceValues = URLResourceValues()
                resourceValues.isExcludedFromBackup = true
                try? excludedFolder.setResourceValues(resourceValues)
            }

            // The Basket entry deliberately carries no `url` — load() reconstructs
            // one fresh from the row's own id + file.id rather than trusting a
            // path persisted at save time (see FINDINGS.md, "Attachment storage").
            var referencedFiles: [Occulta.File] = []
            for file in messages {
                guard let sourceURL = file.url else { continue }
                let destinationURL = folder.appendingPathComponent(Message.Draft.attachmentFilename(for: file))
                if !FileManager.default.fileExists(atPath: destinationURL.path) {
                    try? FileManager.default.copyItem(at: sourceURL, to: destinationURL)
                }
                guard FileManager.default.fileExists(atPath: destinationURL.path) else { continue }
                var referenced = Occulta.File(format: file.format, date: file.date)
                referenced.id = file.id
                referencedFiles.append(referenced)
            }
            if !trimmed.isEmpty {
                referencedFiles.append(Occulta.File(content: trimmed.data(using: .utf8), format: .text, date: Date()))
            }

            guard !Task.isCancelled else { return }

            let basket     = Basket(files: referencedFiles)
            let basketData = try JSONEncoder().encode(basket)

            let recipientData = Data(recipientID.utf8)
            let sealedRecipient = try AES.GCM.seal(
                recipientData, using: key, nonce: AES.GCM.Nonce(),
                authenticating: Message.Draft.aad(id: draftID, field: .recipientID)
            )
            let sealedContent = try AES.GCM.seal(
                basketData, using: key, nonce: AES.GCM.Nonce(),
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
            try? modelContext.save()
        } catch {
            // Best-effort — failing to save a draft is no worse than today's loss.
        }
    }
}
