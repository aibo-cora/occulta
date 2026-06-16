//
//  ShareViewController.swift
//  ShareExtension
//
//  Share extension entry point: contact picker → file intake → manifest write → handoff.
//  Extension only — never linked by the main app.
//
//  Security boundary: this process NEVER links Manager.Key, Manager.Crypto,
//  ContactManager, PrekeyManager, PQProvider, or OccultaBundle. The only crypto
//  it performs is ShareIndexKeyManager's AES-GCM for the contact index and manifest.
//

import UIKit
import SwiftUI
import SwiftData
import UniformTypeIdentifiers

class ShareViewController: UIViewController {

    private let shareKeyManager = ShareIndexKeyManager()
    private var sessionID: String?

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()

        // `.occ` inputs are already encrypted — re-encrypting them makes no
        // sense. Hand them to the main app for decryption instead of showing
        // the contact picker.
        //
        // Why this lives in the share extension at all: apps like WhatsApp
        // present attachments through the system share sheet, which only
        // surfaces App Extensions — not main-app document handlers. Without
        // this branch, tapping "Occulta" on a `.occ` in WhatsApp wrongly
        // routes through the encrypt-for-recipient picker.
        if self.tryHandoffInboundOCC() { return }

        self.showContactPicker()
    }

    // MARK: - Phase 1: Contact Picker

    private func showContactPicker() {
        let contacts = self.loadContacts()

        if contacts.isEmpty {
            self.showEmptyState()
            return
        }

        let picker = ContactPickerView(contacts: contacts) { [weak self] selected in
            self?.handleContactSelected(selected, allContacts: contacts)
        } onCancel: { [weak self] in
            self?.cancel()
        }

        let host = UIHostingController(rootView: picker)
        self.addChild(host)
        host.view.frame = self.view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        self.view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    private func showEmptyState() {
        let label = UILabel()
        label.text = "Open Occulta to set up your contacts."
        label.textAlignment = .center
        label.textColor = .secondaryLabel
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        self.view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: self.view.centerYAnchor),
            label.leadingAnchor.constraint(greaterThanOrEqualTo: self.view.leadingAnchor, constant: 32),
            label.trailingAnchor.constraint(lessThanOrEqualTo: self.view.trailingAnchor, constant: -32)
        ])
    }

    /// Fetch all contacts from the shared SwiftData store, decrypt in memory.
    ///
    /// Opens the store read-only, decrypts each record's identifier and display name,
    /// and returns plain structs. Decrypted Data buffers are zeroed before returning.
    private func loadContacts() -> [DecryptedContact] {
        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
        else { return [] }

        let storeURL = containerURL.appendingPathComponent("ShareIndex.sqlite")
        guard FileManager.default.fileExists(atPath: storeURL.path) else { return [] }

        let config = ModelConfiguration(
            schema: Schema([ShareableContact.self]),
            url: storeURL,
            cloudKitDatabase: .none
        )

        guard
            let container = try? ModelContainer(for: ShareableContact.self, configurations: config)
        else { return [] }

        let context = ModelContext(container)
        let descriptor = FetchDescriptor<ShareableContact>()
        guard let records = try? context.fetch(descriptor) else { return [] }

        var results: [DecryptedContact] = []

        for record in records {
            guard
                var idData = try? self.shareKeyManager.decrypt(data: record.encryptedIdentifier),
                var nameData = try? self.shareKeyManager.decrypt(data: record.encryptedDisplayName),
                let identifier = String(data: idData, encoding: .utf8),
                let displayName = String(data: nameData, encoding: .utf8)
            else { continue }

            results.append(DecryptedContact(identifier: identifier, displayName: displayName))

            // Zero the decrypted Data buffers immediately after extracting strings.
            // Swift Strings may copy the bytes (small-string optimization stores inline
            // on the stack), but zeroing the Data buffer is the best we can do.
            _ = idData.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            _ = nameData.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            idData = Data()
            nameData = Data()
        }

        return results
    }

    /// After picker selection, zero the full contact list and retain only the selected ID.
    ///
    /// The plan requires zeroing all decrypted contact data immediately after selection.
    /// Swift String doesn't support in-place zeroing (COW, small-string optimization),
    /// so reassigning to "" releases the heap reference — best effort.
    private func handleContactSelected(_ selected: DecryptedContact, allContacts: [DecryptedContact]) {
        let selectedIdentifier = selected.identifier

        // Zero all contact strings. Reassigning to "" releases the original String's
        // backing storage. This doesn't guarantee the memory is overwritten (Swift runtime
        // may defer deallocation), but it drops all references immediately.
        var mutableContacts = allContacts
        for i in mutableContacts.indices {
            mutableContacts[i].identifier = ""
            mutableContacts[i].displayName = ""
        }
        mutableContacts = []

        Task {
            await self.processAttachments(contactIdentifier: selectedIdentifier)
        }
    }

    // MARK: - Phase 2: File Intake

    /// Copy all shared attachments to the session directory in the shared container.
    ///
    /// Files are processed sequentially — one at a time — to:
    /// - Limit memory to one temp file from loadFileRepresentation at a time
    /// - Ensure each copy completes before requesting the next attachment
    /// - Avoid exceeding memory from multiple concurrent loadDataRepresentation fallbacks
    ///
    /// Files are named 0.tmp, 1.tmp, etc. — original filenames are recorded only
    /// inside the encrypted manifest. Filesystem inspection reveals no filename metadata.
    private func processAttachments(contactIdentifier: String) async {
        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
        else {
            self.cancel()
            return
        }

        let sessionID = UUID().uuidString
        self.sessionID = sessionID
        let sessionDir = containerURL
            .appendingPathComponent("pending")
            .appendingPathComponent(sessionID)

        let fm = FileManager.default

        do {
            try fm.createDirectory(at: sessionDir, withIntermediateDirectories: true)
            try (sessionDir as NSURL).setResourceValue(
                URLFileProtection.complete,
                forKey: .fileProtectionKey
            )
        } catch {
            self.cancel()
            return
        }

        guard let extensionItems = self.extensionContext?.inputItems as? [NSExtensionItem] else {
            self.cancel()
            return
        }

        var providers: [NSItemProvider] = []
        for item in extensionItems {
            if let attachments = item.attachments {
                providers.append(contentsOf: attachments)
            }
        }

        var fileEntries: [ShareManifest.FileEntry] = []

        for (index, provider) in providers.enumerated() {
            let filename = "\(index).tmp"
            let destURL = sessionDir.appendingPathComponent(filename)

            let uti = provider.registeredTypeIdentifiers.first ?? UTType.data.identifier
            let utType = UTType(uti) ?? .data
            let fileExt = utType.preferredFilenameExtension ?? "bin"

            do {
                // Prefer loadFileRepresentation — bytes flow through the kernel, not app memory.
                // This is O(1) on APFS (copy-on-write clone). No memory pressure for any file size.
                let copied = try await self.copyFileRepresentation(
                    from: provider, uti: uti, to: destURL
                )

                if !copied {
                    // Some NSItemProvider sources don't support file representation.
                    // Fall back to loadDataRepresentation with a 10 MB size guard.
                    try await self.copyDataRepresentation(
                        from: provider, uti: uti, to: destURL
                    )
                }

                fileEntries.append(ShareManifest.FileEntry(
                    filename: filename, uti: uti, fileExtension: fileExt
                ))
            } catch {
                try? fm.removeItem(at: sessionDir)
                self.cancel()
                return
            }
        }

        // Phase 3: Write encrypted manifest and hand off to main app
        do {
            let manifest = ShareManifest(
                contactIdentifier: contactIdentifier,
                files: fileEntries,
                createdAt: Date()
            )

            var manifestData = try JSONEncoder().encode(manifest)
            let encryptedManifest = try self.shareKeyManager.encrypt(data: manifestData)

            // Zero plaintext manifest — it contains the contact identifier (relationship metadata).
            _ = manifestData.withUnsafeMutableBytes { buffer in
                memset(buffer.baseAddress!, 0, buffer.count)
            }
            manifestData = Data()

            let manifestURL = sessionDir.appendingPathComponent("manifest.enc")
            try encryptedManifest.write(to: manifestURL)

            // Explicit file protection — same copyItem caveat applies to any file
            // created in the shared container.
            try (manifestURL as NSURL).setResourceValue(
                URLFileProtection.complete,
                forKey: .fileProtectionKey
            )

            self.openContainingApp(sessionID: sessionID)
        } catch {
            try? fm.removeItem(at: sessionDir)
            self.cancel()
        }
    }

    /// Copy via `loadFileRepresentation`, encrypt with the share key, write ciphertext.
    /// Returns false if this provider doesn't support file representation for the given UTI.
    ///
    /// Note: reading the source into Data for encryption reintroduces memory pressure for
    /// large files. This is an accepted tradeoff — the alternative (streaming AES-GCM) would
    /// require custom framing not available in CryptoKit.
    private func copyFileRepresentation(
        from provider: NSItemProvider, uti: String, to destination: URL
    ) async throws -> Bool {
        guard provider.hasRepresentationConforming(toTypeIdentifier: uti, fileOptions: []) else {
            return false
        }

        return try await withCheckedThrowingContinuation { continuation in
            provider.loadFileRepresentation(forTypeIdentifier: uti) { sourceURL, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let sourceURL else {
                    continuation.resume(returning: false)
                    return
                }
                do {
                    var plaintext = try Data(contentsOf: sourceURL)
                    let ciphertext = try self.shareKeyManager.encrypt(data: plaintext)
                    _ = plaintext.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                    plaintext = Data()
                    try ciphertext.write(to: destination, options: .completeFileProtection)
                    continuation.resume(returning: true)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Fallback: load into memory with a 10 MB size guard, encrypt before writing.
    private func copyDataRepresentation(
        from provider: NSItemProvider, uti: String, to destination: URL
    ) async throws {
        var data: Data = try await withCheckedThrowingContinuation { continuation in
            provider.loadDataRepresentation(forTypeIdentifier: uti) { data, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let data else {
                    continuation.resume(throwing: ShareError.noData)
                    return
                }
                continuation.resume(returning: data)
            }
        }

        guard data.count <= 10_000_000 else {
            throw ShareError.fileTooLarge
        }

        let ciphertext = try self.shareKeyManager.encrypt(data: data)
        _ = data.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
        data = Data()
        try ciphertext.write(to: destination, options: .completeFileProtection)
    }

    // MARK: - Phase 3: Handoff

    /// Open the main app via the registered `occulta://` URL scheme.
    ///
    /// Uses the responder chain to reach UIApplication.open — share extensions
    /// don't have direct access to UIApplication.shared.
    private func openContainingApp(sessionID: String) {
        guard
            let url = URL(string: "occulta://share?session=\(sessionID)")
        else {
            self.extensionContext?.completeRequest(returningItems: nil)
            
            return
        }

        var responder: UIResponder? = self
        
        while let r = responder {
            if r.responds(to: #selector(UIApplication.open(_:options:completionHandler:))) {
                r.perform(
                    #selector(UIApplication.open(_:options:completionHandler:)),
                    with: url, with: nil
                )
                break
            }
            responder = r.next
        }

        self.extensionContext?.completeRequest(returningItems: nil)
    }

    // MARK: - Inbound `.occ` handoff

    /// UTI for `.occ` files as declared in the main app's Info.plist
    /// (`UTExportedTypeDeclarations`). Providers that preserve UTI metadata
    /// (e.g. Files.app, AirDrop) tag `.occ` attachments with this string.
    private static let occUTI = "com.github.aibo-cora.occulta"

    /// Returns true iff at least one attachment looks like an `.occ` file
    /// AND we successfully kicked off the async handoff to the main app.
    ///
    /// The detection logic is lenient: many source apps (notably WhatsApp)
    /// strip or replace the UTI when presenting an attachment through the
    /// system share sheet. We therefore match on either:
    ///   1. The exported UTI, or
    ///   2. A `public.file-url` item whose path extension is `occ`.
    ///
    /// Returning true short-circuits `viewDidLoad` — the picker never shows.
    /// Returning false falls back to the outbound encrypt-for-contact flow.
    private func tryHandoffInboundOCC() -> Bool {
        guard let extensionItems = self.extensionContext?.inputItems as? [NSExtensionItem] else {
            return false
        }

        var providers: [NSItemProvider] = []
        for item in extensionItems {
            if let attachments = item.attachments {
                providers.append(contentsOf: attachments)
            }
        }

        guard let provider = providers.first(where: { Self.looksLikeOCC(provider: $0) }) else {
            return false
        }

        Task { await self.handoffInboundOCC(provider: provider) }
        return true
    }

    /// True if the provider advertises the `.occ` UTI or a file URL with
    /// a `.occ` path extension.
    private static func looksLikeOCC(provider: NSItemProvider) -> Bool {
        if provider.hasItemConformingToTypeIdentifier(Self.occUTI) {
            return true
        }

        // Some sources advertise the attachment as a file URL with no
        // specific UTI. `registeredTypeIdentifiers` may include
        // `public.file-url` / `public.url` — sniff the extension from the
        // provider's suggestedName if available.
        if let suggested = provider.suggestedName,
           (suggested as NSString).pathExtension.lowercased() == "occ" {
            return true
        }

        return false
    }

    /// Load the `.occ` bytes, stash them in the shared container, and launch
    /// the main app with `occulta://inbound?session=<uuid>`.
    ///
    /// Failures at any stage cancel the extension request so the user isn't
    /// stuck on a blank screen — in that case the `inbound/<uuid>.occ` file
    /// either never got written or is deleted best-effort.
    private func handoffInboundOCC(provider: NSItemProvider) async {
        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
        else {
            self.extensionContext?.cancelRequest(withError: ShareError.noData)
            return
        }

        let sessionID = UUID().uuidString
        let inboundDir = containerURL.appendingPathComponent("inbound")
        let destURL    = inboundDir.appendingPathComponent("\(sessionID).occ")
        let fm = FileManager.default

        do {
            try fm.createDirectory(at: inboundDir, withIntermediateDirectories: true)
            try (inboundDir as NSURL).setResourceValue(
                URLFileProtection.complete,
                forKey: .fileProtectionKey
            )
        } catch {
            self.extensionContext?.cancelRequest(withError: ShareError.noData)
            return
        }

        // Pick the UTI to request. If the provider advertises the exported
        // Occulta UTI, use it; otherwise ask for the first registered type
        // (often `public.file-url`).
        let uti = provider.hasItemConformingToTypeIdentifier(Self.occUTI)
            ? Self.occUTI
            : (provider.registeredTypeIdentifiers.first ?? UTType.data.identifier)

        do {
            // Prefer file representation — bytes flow through the kernel,
            // not app memory. Falls back to data representation for
            // providers that don't support it.
            let copied = try await self.copyFileRepresentation(
                from: provider, uti: uti, to: destURL
            )
            if !copied {
                try await self.copyDataRepresentation(
                    from: provider, uti: uti, to: destURL
                )
            }
            try (destURL as NSURL).setResourceValue(
                URLFileProtection.complete,
                forKey: .fileProtectionKey
            )
        } catch {
            try? fm.removeItem(at: destURL)
            self.extensionContext?.cancelRequest(withError: ShareError.noData)
            return
        }

        // Launch the main app — identical responder-chain dance as
        // `openContainingApp`. We don't reuse that method because the URL
        // scheme path differs (`inbound` vs `share`) and that method also
        // completes the extension request; keeping them separate keeps each
        // read straightforwardly.
        guard let url = URL(string: "occulta://inbound?session=\(sessionID)") else {
            try? fm.removeItem(at: destURL)
            self.extensionContext?.cancelRequest(withError: ShareError.noData)
            return
        }

        await MainActor.run {
            var responder: UIResponder? = self
            while let r = responder {
                if r.responds(to: #selector(UIApplication.open(_:options:completionHandler:))) {
                    r.perform(
                        #selector(UIApplication.open(_:options:completionHandler:)),
                        with: url, with: nil
                    )
                    break
                }
                responder = r.next
            }
            self.extensionContext?.completeRequest(returningItems: nil)
        }
    }

    /// Best-effort cleanup on cancellation. If the extension is killed before this
    /// runs, the main app's cleanupPendingSessions sweep catches it.
    private func cancel() {
        if let sessionID {
            if let containerURL = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared") {
                let sessionDir = containerURL
                    .appendingPathComponent("pending")
                    .appendingPathComponent(sessionID)
                try? FileManager.default.removeItem(at: sessionDir)
            }
        }
        self.extensionContext?.cancelRequest(withError: ShareError.cancelled)
    }

    // MARK: - Types

    struct DecryptedContact: Identifiable {
        var identifier: String
        var displayName: String
        var id: String { self.identifier }
    }

    enum ShareError: Error {
        case noData
        case fileTooLarge
        case cancelled
    }
}

// MARK: - Contact Picker SwiftUI View

private struct ContactPickerView: View {
    let contacts: [ShareViewController.DecryptedContact]
    let onSelect: (ShareViewController.DecryptedContact) -> Void
    let onCancel: () -> Void

    @State private var searchText = ""

    private var filtered: [ShareViewController.DecryptedContact] {
        if self.searchText.isEmpty { return self.contacts }

        return self.contacts.filter {
            $0.displayName.localizedCaseInsensitiveContains(self.searchText)
        }
    }

    var body: some View {
        NavigationView {
            List(self.filtered) { contact in
                Button {
                    self.onSelect(contact)
                } label: {
                    Text(contact.displayName)
                        .foregroundStyle(.primary)
                }
            }
            .searchable(text: self.$searchText, prompt: "Search contacts")
            .navigationTitle("Encrypt for")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: self.onCancel)
                }
            }
        }
    }
}

#Preview {
    ContactPickerView(contacts: [ShareViewController.DecryptedContact(identifier: UUID().uuidString, displayName: "Alex")]) { onSelect in

    } onCancel: {

    }
}
