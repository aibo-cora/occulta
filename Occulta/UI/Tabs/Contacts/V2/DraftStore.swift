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
        recipientID:       String,
        isSensitive:       Bool,
        text:              String,
        messages:          [Occulta.File],
        attachmentManager: AttachmentManager?,
        modelContext:      ModelContext
    ) {
        self.saveTask?.cancel()
        self.saveTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled, let self else { return }
            await self.save(
                recipientID: recipientID, isSensitive: isSensitive, text: text,
                messages: messages, attachmentManager: attachmentManager, modelContext: modelContext
            )
        }
    }

    /// Immediate, non-debounced save — for `.onDisappear`, where a 2s wait would
    /// risk losing state to backgrounding or termination before it fires.
    func flush(
        recipientID:       String,
        isSensitive:       Bool,
        text:              String,
        messages:          [Occulta.File],
        attachmentManager: AttachmentManager?,
        modelContext:      ModelContext
    ) async {
        self.saveTask?.cancel()
        await self.save(
            recipientID: recipientID, isSensitive: isSensitive, text: text,
            messages: messages, attachmentManager: attachmentManager, modelContext: modelContext
        )
    }

    /// Decrypts an existing draft for this recipient, if one exists. Call once,
    /// before the user starts typing.
    func load(
        recipientID:       String,
        attachmentManager: AttachmentManager?,
        modelContext:      ModelContext
    ) -> (text: String, messages: [Occulta.File])? {
        guard let row = Message.Draft.find(recipientID: recipientID, in: modelContext) else { return nil }
        do {
            guard let key = try Manager.Key().createHybridLocalEncryptionKey() else { return nil }
            let box   = try AES.GCM.SealedBox(combined: row.encryptedContent)
            let plain = try AES.GCM.open(box, using: key, authenticating: row.aad(for: .content))
            let basket = try JSONDecoder().decode(Basket.self, from: plain)

            var text = ""
            var loadedMessages: [Occulta.File] = []
            for file in basket.files {
                guard let data = file.content else { continue }
                if case .text = file.format, let str = String(data: data, encoding: .utf8) {
                    text = str
                    continue
                }
                guard case .file(let meta) = file.format else { continue }
                let filename = [meta.name, meta.extension].compactMap { $0 }.joined(separator: ".")
                let url = FileManager.default.temporaryDirectory.appendingPathComponent(
                    filename.isEmpty ? UUID().uuidString : filename
                )
                if let attachmentManager {
                    try? attachmentManager.encrypt(data, to: url)
                } else {
                    try? data.writeProtected(to: url)
                }
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
    /// deletes any stale existing draft row instead of writing an empty one.
    private func save(
        recipientID:       String,
        isSensitive:       Bool,
        text:              String,
        messages:          [Occulta.File],
        attachmentManager: AttachmentManager?,
        modelContext:      ModelContext
    ) async {
        guard !isSensitive else { return }

        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasContent = !trimmed.isEmpty || !messages.isEmpty
        guard hasContent else {
            if let existing = Message.Draft.find(recipientID: recipientID, in: modelContext) {
                modelContext.delete(existing)
                try? modelContext.save()
            }
            return
        }

        do {
            guard let key = try Manager.Key().createHybridLocalEncryptionKey() else { return }

            var allFiles = messages
            if !trimmed.isEmpty {
                allFiles.append(Occulta.File(content: trimmed.data(using: .utf8), format: .text, date: Date()))
            }

            // Inline attachment plaintext into the Basket so the whole draft seals
            // as one unit — one key to destroy, not two, on Secure Mode activation
            // or when the recipient later becomes sensitive.
            var inlineFiles: [Occulta.File] = []
            for file in allFiles {
                if let fileURL = file.url {
                    guard let data = try? await attachmentManager?.data(at: fileURL) else { continue }
                    var inlined = Occulta.File(content: data, format: file.format, date: file.date)
                    inlined.id = file.id
                    inlineFiles.append(inlined)
                } else {
                    inlineFiles.append(file)
                }
            }

            guard !Task.isCancelled else { return }

            let basket     = Basket(files: inlineFiles)
            let basketData = try JSONEncoder().encode(basket)

            let existing = Message.Draft.find(recipientID: recipientID, in: modelContext)
            let draftID  = existing?.id ?? UUID()

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
                let draft = Message.Draft(encryptedRecipientID: recipientCombined, encryptedContent: contentCombined)
                draft.id = draftID
                modelContext.insert(draft)
            }
            try? modelContext.save()
        } catch {
            // Best-effort — failing to save a draft is no worse than today's loss.
        }
    }
}
