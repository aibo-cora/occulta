//
//  Contact+Manager+AttachmentKey.swift
//  Occulta
//
//  Moves the attachments sealed under a contact's old base key to the new one (`bugs.md` Bug 196). Until that fix the base
//  key was `createSharedSecret(using:)`, the same value as a classical long-term slot's key; it is now the same ECDH under
//  `SaltInfo.kAttachmentBaseKeyInfo`. The key is local to this phone and nothing of it is sent, so only the files this phone
//  keeps are affected: a draft to one contact under `Application Support/Drafts/<draft id>/`. A received attachment under
//  `tmp/` is not walked: `OccultaApp.init` empties `tmp/` at every launch, before the first unlock, so none sealed under the
//  old key can be there.
//
//  Per draft: the draft row holds its recipient, so the pass derives the keys of that one contact and moves that draft's files,
//  instead of trying every file against every key of every contact. What a pass costs follows the drafts that hold sealed
//  files, not the number of contacts, and a file moves to its own recipient's current key even when two records share an
//  identity key. A group draft is sealed under the compose staging key, which this fix did not change: no contact has its
//  recipient id, so it is skipped, as is a folder with no draft row.
//
//  Modelled on `KeyReseal.resealDraftFiles`: a file is found by trial (its header authenticates under exactly the key that
//  sealed it), moved with `AttachmentManager.reseal` (streamed, written to a temporary, read back, then renamed), and a file
//  that opens under no old key is left alone, and a file that will not move is left as it was while the run goes on. There is
//  no marker: a file already moved no longer opens under an old key, so running it again changes nothing.
//

import Foundation
import CryptoKit
import SwiftData

extension ContactManager {

    struct AttachmentReseal: Equatable {
        /// Files moved to the new key by this run.
        var resealed = 0
        /// Files that would not move. The run goes on to the next file, so one it cannot read does not hold back the rest; the
        /// failed one is left as it was and tried again at the next unlock.
        var failed = 0
    }

    /// The keys for one contact: the new key of its current row, which is what `fileEncryptionKey(for:)` returns, and the old
    /// key of every row it has held. A file sealed under an earlier row's old key moves to the current row's new key, so it
    /// opens again.
    func attachmentKeyPairs(
        for contact: Contact.Profile, using keyManager: any KeyManagerProtocol
    ) -> [(old: AttachmentManager, new: AttachmentManager)] {
        func material(_ row: Contact.Profile.Key) -> Data? {
            guard let encrypted = row.material else { return nil }
            return (try? Manager.Crypto().decrypt(data: encrypted)) ?? nil
        }

        guard
            let current = contact.displayedKey.flatMap(material),
            let newKey = keyManager.createAttachmentBaseKey(using: current)
        else { return [] }
        let new = AttachmentManager(contactKey: newKey)

        var seen = Set<Data>()
        var pairs: [(old: AttachmentManager, new: AttachmentManager)] = []
        for row in contact.contactPublicKeys ?? [] {
            guard let held = material(row), let oldKey = keyManager.createSharedSecret(using: held) else { continue }
            // Two rows of one contact that hold one identity key have one old key: tried once.
            guard seen.insert(oldKey.withUnsafeBytes { Data($0) }).inserted else { continue }
            pairs.append((AttachmentManager(contactKey: oldKey), new))
        }
        return pairs
    }

    /// The identifier a draft is addressed to, or nil for a row that will not open. A group draft's is a group's id, which no
    /// contact has.
    private func draftRecipientIdentifier(of draft: Message.Draft, using key: SymmetricKey) -> String? {
        guard
            let box = try? AES.GCM.SealedBox(combined: draft.encryptedRecipientID),
            let plain = try? AES.GCM.open(box, using: key, authenticating: draft.aad(for: .recipientID))
        else { return nil }
        return String(data: plain, encoding: .utf8)
    }

    /// Every sealed file under `directories`, removing the temporaries a killed run left (the file beside one is still the
    /// original). Synchronous: an enumerator's iterator can't be made in an async context under Swift 6.
    private static func sealedFiles(in directories: [URL]) -> [URL] {
        let files = FileManager.default
        var sealed: [URL] = []
        for directory in directories {
            guard let enumerator = files.enumerator(at: directory, includingPropertiesForKeys: [.isRegularFileKey]) else { continue }
            for case let file as URL in enumerator {
                if file.pathExtension == AttachmentManager.resealingSuffix {
                    try? files.removeItem(at: file)
                    continue
                }
                guard
                    (try? file.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true,
                    AttachmentManager.isSealed(at: file)
                else { continue }
                sealed.append(file)
            }
        }
        return sealed
    }

    /// Moves every draft attachment that is sealed under its contact's old base key to that contact's new one.
    ///
    /// Runs on the main actor, like `AttachmentManager.reseal`, which writes through `StreamingEncryptor`. A file is one
    /// streamed pass, so a large video holds the main actor for as long as that takes; the run yields after every file,
    /// moved or not. Each draft's folder is listed first and its contact's keys derived only if it holds a sealed file, so a
    /// phone with no sealed file pays for the draft rows and directory listings and not for an Enclave round trip per
    /// contact. A phone with sealed draft files derives one contact's keys for each such draft at each unlock. Every draft at
    /// every depth, whatever is visible, as `fetchContact(by:)` is. A file opened before the run reaches it, by a draft
    /// opened right at unlock, may not open until the run has.
    @discardableResult
    func resealAttachmentKeys(
        in draftsRoot: URL = Message.Draft.attachmentsRoot,
        using keyManager: (any KeyManagerProtocol)? = nil
    ) async -> AttachmentReseal {
        var result = AttachmentReseal()
        guard
            let localKey = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey(),
            let drafts = try? self.modelContext.fetch(FetchDescriptor<Message.Draft>())
        else { return result }

        var keys = keyManager
        for draft in drafts {
            let sealed = Self.sealedFiles(in: [draftsRoot.appendingPathComponent(draft.id.uuidString, isDirectory: true)])
            guard
                !sealed.isEmpty,
                let identifier = self.draftRecipientIdentifier(of: draft, using: localKey),
                let contact = try? self.fetchContact(by: identifier)
            else { continue }

            let manager = keys ?? Manager.Key()
            keys = manager
            let pairs = self.attachmentKeyPairs(for: contact, using: manager)
            guard !pairs.isEmpty else { continue }

            for file in sealed {
                if let match = pairs.first(where: { $0.old.opens(at: file) }) {
                    do {
                        try match.old.reseal(at: file, to: match.new)
                        result.resealed += 1
                    } catch {
                        result.failed += 1
                    }
                }
                await Task.yield()
            }
        }
        return result
    }
}
