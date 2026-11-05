//
//  Contact+Manager+AttachmentKey.swift
//  Occulta
//
//  Moves the attachments sealed under a contact's old base key to the new one (`bugs.md` Bug 196). Until that fix the base
//  key was `createSharedSecret(using:)`, the same value as a classical long-term slot's key; it is now the same ECDH under
//  `SaltInfo.kAttachmentBaseKeyInfo`. The key is local to this phone and nothing of it is sent, so only the files this phone
//  keeps are affected: a draft to one contact under `Application Support/Drafts/<draft id>/`, and a received attachment
//  not yet opened under `tmp/`.
//
//  Modelled on `KeyReseal.resealDraftFiles`: a file is found by trial (its header authenticates under exactly the key that
//  sealed it), moved with `AttachmentManager.reseal` (streamed, written to a temporary, read back, then renamed), and a file
//  that opens under no old key is left alone. There is no marker: a file already moved no longer opens under an old key, so
//  running it again changes nothing.
//

import Foundation
import CryptoKit

extension ContactManager {

    struct AttachmentReseal: Equatable {
        /// Files moved to the new key by this run.
        var resealed = 0
        /// Files that would not move. The run stops at the first, leaving it as it was, and the next run tries again.
        var failed = 0
    }

    /// Every non-deleted contact at every depth, whatever is visible: the old key of each key row a contact has held, and
    /// the new key of its current row, which is what `fileEncryptionKey(for:)` returns. A file sealed under an earlier row's
    /// old key is moved to the current row's new key, so it opens again.
    func attachmentKeyPairs(
        using keyManager: any KeyManagerProtocol = Manager.Key()
    ) throws -> [(old: AttachmentManager, new: AttachmentManager)] {
        func material(_ row: Contact.Profile.Key) -> Data? {
            guard let encrypted = row.material else { return nil }
            return (try? Manager.Crypto().decrypt(data: encrypted)) ?? nil
        }

        var pairs: [(old: AttachmentManager, new: AttachmentManager)] = []
        for contact in try self.fetchAllContacts() {
            guard
                let current = contact.displayedKey.flatMap(material),
                let newKey = keyManager.createAttachmentBaseKey(using: current)
            else { continue }
            let new = AttachmentManager(contactKey: newKey)

            for row in contact.contactPublicKeys ?? [] {
                guard let held = material(row), let oldKey = keyManager.createSharedSecret(using: held) else { continue }
                pairs.append((AttachmentManager(contactKey: oldKey), new))
            }
        }
        return pairs
    }

    /// Moves every attachment under `directories` that is sealed under a contact's old base key to that contact's new one.
    ///
    /// Runs on the main actor, like `AttachmentManager.reseal`, which writes through `StreamingEncryptor`. A file is one
    /// streamed pass, so a large video holds the main actor for as long as that takes; the run yields between files.
    @discardableResult
    func resealAttachmentKeys(
        in directories: [URL] = [Message.Draft.attachmentsRoot, FileManager.default.temporaryDirectory],
        using keyManager: any KeyManagerProtocol = Manager.Key()
    ) async -> AttachmentReseal {
        var result = AttachmentReseal()
        guard let pairs = try? self.attachmentKeyPairs(using: keyManager), !pairs.isEmpty else { return result }
        let files = FileManager.default

        for directory in directories {
            guard let enumerator = files.enumerator(at: directory, includingPropertiesForKeys: [.isRegularFileKey]) else { continue }
            let urls = enumerator.compactMap { $0 as? URL }

            for file in urls {
                // A temporary a killed run left; the file beside it is still the original.
                if file.pathExtension == AttachmentManager.resealingSuffix {
                    try? files.removeItem(at: file)
                    continue
                }
                guard
                    (try? file.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true,
                    AttachmentManager.isSealed(at: file),
                    let match = pairs.first(where: { $0.old.opens(at: file) })
                else { continue }

                do {
                    try match.old.reseal(at: file, to: match.new)
                    result.resealed += 1
                } catch {
                    result.failed += 1
                    return result
                }
                await Task.yield()
            }
        }
        return result
    }
}
