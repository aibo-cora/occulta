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
//  that opens under no old key is left alone, and a file that will not move is left as it was while the run goes on. There is
//  no marker: a file already moved no longer opens under an old key, so running it again changes nothing.
//

import Foundation
import CryptoKit

extension ContactManager {

    struct AttachmentReseal: Equatable {
        /// Files moved to the new key by this run.
        var resealed = 0
        /// Files that would not move. The run goes on to the next file, so one it cannot read does not hold back the rest; the
        /// failed one is left as it was and tried again at the next unlock.
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
        var seen = Set<Data>()
        for contact in try self.fetchAllContacts() {
            guard
                let current = contact.displayedKey.flatMap(material),
                let newKey = keyManager.createAttachmentBaseKey(using: current)
            else { continue }
            let new = AttachmentManager(contactKey: newKey)

            for row in contact.contactPublicKeys ?? [] {
                guard let held = material(row), let oldKey = keyManager.createSharedSecret(using: held) else { continue }
                // Two rows, or two contacts, that hold one identity key have one old key: tried once.
                guard seen.insert(oldKey.withUnsafeBytes { Data($0) }).inserted else { continue }
                pairs.append((AttachmentManager(contactKey: oldKey), new))
            }
        }
        return pairs
    }

    /// Moves every attachment under `directories` that is sealed under a contact's old base key to that contact's new one.
    ///
    /// Runs on the main actor, like `AttachmentManager.reseal`, which writes through `StreamingEncryptor`. A file is one
    /// streamed pass, so a large video holds the main actor for as long as that takes; the run yields after every file,
    /// moved or not. The sealed files are listed first and the keys derived only if there is one, so a phone with nothing
    /// to move pays for a directory listing and not for an Enclave round trip per contact. A file opened before the run
    /// reaches it, by a draft opened right at unlock, may not open until the run has: drafts are listed first.
    @discardableResult
    func resealAttachmentKeys(
        in directories: [URL] = [Message.Draft.attachmentsRoot, FileManager.default.temporaryDirectory],
        using keyManager: any KeyManagerProtocol = Manager.Key()
    ) async -> AttachmentReseal {
        var result = AttachmentReseal()
        let files = FileManager.default

        var sealed: [URL] = []
        for directory in directories {
            guard let enumerator = files.enumerator(at: directory, includingPropertiesForKeys: [.isRegularFileKey]) else { continue }
            for case let file as URL in enumerator {
                // A temporary a killed run left; the file beside it is still the original.
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
        guard !sealed.isEmpty, let pairs = try? self.attachmentKeyPairs(using: keyManager), !pairs.isEmpty else { return result }

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
        return result
    }
}
