//
//  Vault+Manager+Diagnostic.swift
//  Occulta
//
//  Debug-only, read-only. Says which vault key the stored entry keys and backup-key rows open under, to find out why a
//  vault entry reads empty after Bug 171's rewrap. Writes nothing and prints only the epoch, the key mode in use, and
//  counts: no key material, no plaintext, no ids. Compiled out of Release.
//

#if DEBUG
import Foundation
import SwiftData
import CryptoKit
import LocalAuthentication

extension VaultManager {

    /// Prints one `[VaultDiag]` block to the Xcode console. Call it before anything in `unlock` can write.
    func printVaultKeyDiagnostic(authContext: LAContext) {
        let epoch = KeyReseal.vaultEpoch(in: self.modelContext)
        var lines = ["epoch: \(epoch.map { "\($0.number) \($0.form)" } ?? "unreadable")"]
        lines.append("process vault key mode: \(Manager.Ambient.vaultKeys)")
        lines.append("tier U key mode: \(Manager.Ambient.tierUKeys)")

        let record = (try? self.keyManager.tierPQRecord(.vault)) ?? nil
        lines.append("tier B record: \(record.map { "\($0.mode)" } ?? "none")")
        let secret = (try? self.keyManager.tierSecret(.biometry(authContext))) ?? nil
        lines.append("r_B: \(secret == nil ? "unreadable or absent" : "present")")

        let candidates: [(String, SymmetricKey?)] = [
            ("legacy", try? self.keyManager.legacyKey(.vault(authContext))),
            ("enclaveBound", try? self.keyManager.enclaveBoundKey(.vault(authContext))),
            ("enclaveBoundClassical", try? self.keyManager.enclaveBoundKey(.vault(authContext), record: .classical))
        ]
        for (name, key) in candidates { lines.append("derives \(name): \(key == nil ? "nil" : "yes")") }

        func opens(_ sealed: Data, _ aad: Data) -> [String] {
            guard let box = try? AES.GCM.SealedBox(combined: sealed) else { return ["malformed"] }
            let hits = candidates.compactMap { name, key -> String? in
                guard let key, (try? AES.GCM.open(box, using: key, authenticating: aad)) != nil else { return nil }
                return name
            }
            return hits.isEmpty ? ["none"] : hits
        }

        func tally(_ title: String, _ results: [[String]]) {
            var counts: [String: Int] = [:]
            for result in results { counts[result.joined(separator: "+"), default: 0] += 1 }
            let summary = counts.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ", ")
            lines.append("\(title) (\(results.count)): \(summary.isEmpty ? "-" : summary)")
        }

        let entries = (try? self.modelContext.fetch(FetchDescriptor<VaultEntry>())) ?? []
        tally("entry keys opening under", entries.filter { !$0.encryptedEntryKey.isEmpty }.map { opens($0.encryptedEntryKey, $0.aad(for: .entryKey)) })

        let rows = (try? self.modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())) ?? []
        tally("backup-key rows opening under (filler shows as none)", rows.filter { !$0.encryptedPayload.isEmpty }.map { opens($0.encryptedPayload, $0.aad()) })

        print("[VaultDiag]\n" + lines.map { "  " + $0 }.joined(separator: "\n"))
    }
}
#endif
