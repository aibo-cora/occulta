//
//  ShareViewController.swift
//  ShareExtension
//
//  Share extension entry point: file intake → manifest write → handoff.
//  Extension only — never linked by the main app.
//
//  Security boundary: this process NEVER links Manager.Key, Manager.Crypto,
//  ContactManager, PrekeyManager, PQProvider, or OccultaBundle. The only crypto
//  it performs is ShareIndexKeyManager's AES-GCM for the staged files and manifest.
//
//  It does not choose the recipient. Picking one here meant the app received what looked
//  like a finished instruction and executed it — the reason the outbound pipeline ran with
//  no PIN entered (Bug 84 Part A), and the reason a mirror of the contact list had to live
//  in the App Group at all (Bugs 6, 65-69). The main app owns the picker now, behind its
//  own gate, where the depth is known.
//

import UIKit
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

        self.showStagingIndicator()

        Task { await self.processAttachments() }
    }

    /// The extension has nothing to ask the user, so it shows only that work is under way.
    /// Staging a large attachment is not instant, and `completeRequest` fires from the
    /// handoff — this is on screen for that window.
    private func showStagingIndicator() {
        let spinner = UIActivityIndicatorView(style: .medium)
        spinner.translatesAutoresizingMaskIntoConstraints = false
        spinner.startAnimating()
        self.view.addSubview(spinner)
        NSLayoutConstraint.activate([
            spinner.centerXAnchor.constraint(equalTo: self.view.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: self.view.centerYAnchor)
        ])
    }

    // MARK: - File Intake

    /// Copy all shared attachments to the session directory in the shared container.
    ///
    /// Files are processed sequentially — one at a time — to:
    /// - Limit memory to one temp file from loadFileRepresentation at a time
    /// - Ensure each copy completes before requesting the next attachment
    /// - Avoid exceeding memory from multiple concurrent loadDataRepresentation fallbacks
    ///
    /// Files are named 0.tmp, 1.tmp, etc. — original filenames are recorded only
    /// inside the encrypted manifest. Filesystem inspection reveals no filename metadata.
    private func processAttachments() async {
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

        // Write encrypted manifest and hand off to main app
        do {
            let manifest = ShareManifest(files: fileEntries, createdAt: Date())

            var manifestData = try JSONEncoder().encode(manifest)
            let encryptedManifest = try self.shareKeyManager.encrypt(data: manifestData)

            // Zero plaintext manifest. It no longer carries a recipient, but it still lists
            // original file extensions, and it stays encrypted for that reason.
            _ = manifestData.withUnsafeMutableBytes { buffer in
                memset(buffer.baseAddress!, 0, buffer.count)
            }
            manifestData = Data()

            let manifestURL = sessionDir.appendingPathComponent("manifest.enc")

            // Protection class applied by the write itself, as every other write in this
            // file does. Setting it afterwards via `setResourceValue` — which is what this
            // used to do — leaves the manifest at the default class for the window between
            // the two calls.
            try encryptedManifest.write(to: manifestURL, options: .completeFileProtection)

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
            // The .occ is already encrypted by the sender — just land it on disk
            // with NSFileProtection.complete. No share-key encryption needed.
            let data: Data = try await withCheckedThrowingContinuation { cont in
                provider.loadDataRepresentation(forTypeIdentifier: uti) { data, error in
                    if let error { cont.resume(throwing: error); return }
                    guard let data else { cont.resume(throwing: ShareError.noData); return }
                    cont.resume(returning: data)
                }
            }
            try data.write(to: destURL, options: .completeFileProtection)
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

    enum ShareError: Error {
        case noData
        case fileTooLarge
        case cancelled
    }
}
