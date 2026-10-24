//
//  ReceivedAttachmentKey.swift
//  Occulta
//
//  The key a received attachment is sealed under in `tmp/`, resolved in one place so the writer
//  (`OccultaApp.buildOwnedBasket`) and the reader (the message sheet) cannot disagree.
//  STREAMING_SPEC §6, Bug 184.
//

import Foundation
import CryptoKit
import OccultaFormats

extension ContactManager {

    /// The sender's per-contact file key, else the compose staging key (what `ComposeViewModel`
    /// seals sends under for a recipient it holds no key for). Nil when neither can be derived.
    ///
    /// `fileEncryptionKey(for:)` throws for any sender we hold no public key for, an
    /// introduction-card contact not yet met in person among them. Before this resolver the
    /// writer answered that by leaving the attachment as plaintext in `tmp/`, and the reader
    /// answered it with no manager at all.
    ///
    /// A nil result means the attachment is refused. Callers never write it unsealed.
    func receivedAttachmentKey(
        for owner: String,
        stagingKeyProvider: any ComposeStagingKeyProviding = TierUComposeStagingKey()
    ) -> SymmetricKey? {
        if let key = try? self.fileEncryptionKey(for: owner) {
            return key
        }
        return try? stagingKeyProvider.deriveComposeStagingKey()
    }

    /// Writes each `.file` of a received basket into `directory`, sealed under the key above, and
    /// returns the basket with those files now pointing at their sealed copies. Other formats stay
    /// in memory, as they arrived.
    ///
    /// Throws `ImportError.stagingKeyUnavailable` before anything is written when the basket holds a
    /// file and no key can be derived: a received file is never written unsealed (Bug 184).
    func sealReceivedFiles(
        of basket: Basket,
        owner: String,
        stagingKeyProvider: (any ComposeStagingKeyProviding)? = nil,
        in directory: URL = FileManager.default.temporaryDirectory
    ) async throws -> OwnedBasket {
        let attachmentManager = self.receivedAttachmentKey(for: owner, stagingKeyProvider: stagingKeyProvider ?? TierUComposeStagingKey())
            .map { AttachmentManager(contactKey: $0) }

        // Checked before the loop so no task has started a write.
        if attachmentManager == nil, basket.files.contains(where: { if case .file = $0.format { true } else { false } }) {
            throw ImportError.stagingKeyUnavailable
        }

        return try await withThrowingTaskGroup(of: OccultaFormats.File.self) { group in
            var processed: [OccultaFormats.File] = []

            for file in basket.files {
                switch file.format {
                case .file(let metadata):
                    // metadata.name/.extension come from the decrypted, sender-controlled
                    // Basket — never trusted for path construction. The name is dropped
                    // entirely in favor of a fresh UUID (matching the outbound share-extension
                    // path's existing discipline); the extension is validated by
                    // sanitizedFilesystemExtension since a crafted value like
                    // "../../etc/passwd" could otherwise steer the write outside the directory.
                    // Rejecting anything unsafe doesn't lose real data — the file's display
                    // name/extension in the UI still comes from the untouched `metadata` in
                    // `file.format` below, only the on-disk path changes.
                    let fileURL = directory
                        .appendingPathComponent(UUID().uuidString)
                        .appendingPathExtension(OccultaFormats.File.Metadata.sanitizedFilesystemExtension(metadata.extension))
                    let content = file.content ?? Data()

                    group.addTask {
                        guard let manager = attachmentManager else { throw ImportError.stagingKeyUnavailable }
                        try manager.encrypt(content, to: fileURL)
                        return OccultaFormats.File(url: fileURL, format: file.format, date: file.date)
                    }

                default:
                    processed.append(file)
                }
            }

            for try await file in group {
                processed.append(file)
            }

            let sorted = processed.sorted { ($0.date ?? .now) < ($1.date ?? .now) }
            let modifiedBasket = Basket(
                id:    basket.id,
                files: sorted,
                date:  basket.date,
                owner: basket.owner
            )

            return OwnedBasket(basket: modifiedBasket, owner: owner)
        }
    }
}
