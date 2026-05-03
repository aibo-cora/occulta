//
//  OccultaApp.swift
//  Occulta
//
//  Created by Yura on 10/13/25.
//

import SwiftUI
import SwiftData
import ImageIO
import UniformTypeIdentifiers

// TODO: We don't have the Rotate Key option available right now. However, if it becomes available, we need to consider an edge case where we rotate a key and include a new ID as the message owner, but the recipient would not have this ID on record. We would need to keep track of all our past and current IDs and include them in the message for look up.

@main
struct OccultaApp: App {
    @State private var contactManager: ContactManager
    @State private var identityChallenge = IdentityChallenge.Coordinator()
    @State private var vaultManager: VaultManager
    @State private var shardCustodyManager: ShardCustodyManager
    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false
    @Environment(\.scenePhase) private var scenePhase
    
    var sharedModelContainer: ModelContainer
    
    init() {
        let sharedModelContainer: ModelContainer = {
            let schema = Schema([
                Contact.Profile.self,
                Contact.Profile.PhoneNumber.self,
                Contact.Profile.EmailAddress.self,
                Contact.Profile.PostalAddress.self,
                Contact.Profile.URLAddress.self,
                Contact.Profile.Key.self,
                Contact.Message.self,
                VaultEntry.self,
                CustodyShard.self,
                ReconstructShard.self,
                PendingShardDistribute.self,
                PendingShardReturn.self,
                PendingReturnAcknowledge.self,
                PendingShardRevoke.self,
                PendingShardAcknowledge.self,
                PendingShardNotFound.self,
                PendingShardStatusUpdate.self,
                GlobalShardConfig.self,
            ])
            
            let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false, cloudKitDatabase: .none)

            do {
                return try ModelContainer(for: schema, configurations: [modelConfiguration])
            } catch {
                fatalError("Could not create ModelContainer: \(error)")
            }
        }()
        
        self.sharedModelContainer = sharedModelContainer
        self.contactManager      = ContactManager(modelContainer: sharedModelContainer)
        self.vaultManager        = VaultManager(modelContainer: sharedModelContainer)
        self.shardCustodyManager = ShardCustodyManager(
            modelContainer: sharedModelContainer,
            keyManager:     Manager.Key()
        )
        
        self.migrate()
    }
    
    /// Run migration before any UI accesses contacts.
    ///
    /// Migrate our local database encryption scheme to a PQ resistant variant.
    private func migrate() {
        let context = ModelContext(self.sharedModelContainer)
        let legacyCrypto = LegacyCryptoManager()
        let newCrypto = Manager.Crypto()

        do {
            try DatabaseMigration.migrateToV2(modelContext: context, legacyCrypto: legacyCrypto, newCrypto: newCrypto)
        } catch {
            // Migration failure is not recoverable — the DB is in a known state
            // because migration saves per-record. Log and continue; un-migrated
            // records will be retried on next launch.
            #if DEBUG
            debugPrint("Migration error: \(error)")
            #endif
        }
    }
    
    enum Tabs: String, Hashable {
        case contacts, sign, verify, vault, settings

        var image: Image {
            switch self {
            case .contacts:
                .init(systemName: "person.2.fill")
            case .sign:
                .init(systemName: "signature")
            case .settings:
                .init(systemName: "gearshape.fill")
            case .verify:
                .init(systemName: "checkmark.bubble")
            case .vault:
                .init(systemName: "lock.fill")
            }
        }

        var name: some View {
            switch self {
            case .contacts:
                Text("Contacts")
            case .sign:
                Text("Sign")
            case .settings:
                Text("Settings")
            case .verify:
                Text("Verify")
            case .vault:
                Text("Vault")
            }
        }
    }
    /// Container with plaintext message or file.
    @State private var openedFileContents: OwnedBasket?
    /// Encrypted contacts database.
    @State private var openedEncryptedFileContents: EncryptedFile?
    // Error feedback
    @State private var showError = false
    @State private var errorMessage = ""
    /// Encrypted `.occ` file ready for sharing via UIActivityViewController.
    @State private var shareResult: ShareResult?

    var body: some Scene {
        WindowGroup {
            if self.hasCompleted == false {
                OnboardingView()
            } else {
                TabView {
                    ContactsV2()
                        .tag(Tabs.contacts)
                        .tabItem {
                            Tabs.contacts.image
                            Tabs.contacts.name
                        }
                    
                    if FeatureFlags.isEnabled(.signature) {
                        Sign()
                            .tag(Tabs.sign)
                            .tabItem {
                                Tabs.sign.image
                                Tabs.sign.name
                            }
                        
                        Verify()
                            .tag(Tabs.verify)
                            .tabItem {
                                Tabs.verify.image
                                Tabs.verify.name
                            }
                    }
                    
                    VaultTab()
                        .tag(Tabs.vault)
                        .tabItem {
                            Tabs.vault.image
                            Tabs.vault.name
                        }

                    Settings()
                        .tag(Tabs.settings)
                        .tabItem {
                            Tabs.settings.image
                            Tabs.settings.name
                        }
                }
                .onOpenURL { url in
                    // Handle share extension handoff (outbound) and inbound .occ routing.
                    if url.scheme == "occulta",
                       let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                       let sessionID = components.queryItems?.first(where: { $0.name == "session" })?.value {
                        switch url.host {
                        case "inbound":
                            Task { await self.processInboundSession(sessionID: sessionID) }
                        default:
                            Task { await self.processShareSession(sessionID: sessionID) }
                        }
                        return
                    }

                    let accessing = url.startAccessingSecurityScopedResource()
                    
                    Task {
                        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                        /// Contents of the encrypted file we opened.
                        let (data, _) = try await URLSession.shared.data(from: url)
                        
                        do {
                            if let ownedBasket = try await self.buildOwnedBasket(from: data) {
                                self.openedFileContents = ownedBasket
                            }
                            // If nil, the bundle was an identity-challenge and
                            // the IdentityChallenge.Coordinator has taken over
                            // presentation (approval sheet or result sheet).
                        } catch ContactManager.Errors.messageHasNoData {
                            self.errorMessage = "This message contains no data."
                            self.showError = true
                        } catch ContactManager.Errors.noPublicKeyToEncryptWith {
                            self.errorMessage = "Could not find this file's owner's public key. It is either corrupted and you need to update the app and try again or the message was not addressed to you."
                            self.showError = true
                        } catch {
                            self.errorMessage = "There was an error. \(error.localizedDescription)"
                            self.showError = true
                        }
                    }
                }
                .alert("Error", isPresented: self.$showError) {
                    Button("OK") { }
                } message: {
                    Text(self.errorMessage)
                }
                .sheet(item: self.$openedFileContents) {
                    /// Dismiss
                } content: { data in
                    ComposableMessage.Conversation(mode: .read(messageOwner: data.owner), messages: .constant(data.basket.files))
                }
                .sheet(item: self.$openedEncryptedFileContents) { encryptedContactsFile in
                    Import.Contacts(encryptedFile: encryptedContactsFile)
                }
                .sheet(item: self.$shareResult) { result in
                    ShareActivityView(url: result.url)
                        .onDisappear {
                            try? FileManager.default.removeItem(at: result.url)
                        }
                }
                // Identity-challenge outbound share (challenge OR response `.occ`).
                .sheet(item: Binding(
                    get: { self.identityChallenge.outboundShare },
                    set: { self.identityChallenge.outboundShare = $0 }
                )) { share in
                    ShareActivityView(url: share.url)
                        .onDisappear {
                            try? FileManager.default.removeItem(at: share.url)
                        }
                }
                // Identity-challenge responder approval sheet.
                .sheet(item: Binding(
                    get: { self.identityChallenge.incomingChallenge },
                    set: { self.identityChallenge.incomingChallenge = $0 }
                )) { incoming in
                    IdentityChallenge.IncomingChallengeSheet(
                        incoming:  incoming,
                        onApprove: { self.identityChallenge.approvePending() },
                        onDecline: { self.identityChallenge.declinePending() }
                    )
                }
                // Identity-challenge verification result on the challenger side.
                .sheet(item: Binding(
                    get: { self.identityChallenge.verificationOutcome },
                    set: { self.identityChallenge.verificationOutcome = $0 }
                )) { outcome in
                    IdentityChallenge.VerificationResultSheet(
                        outcome:   outcome,
                        onDismiss: { self.identityChallenge.verificationOutcome = nil }
                    )
                }
                .onChange(of: self.scenePhase) { _, newPhase in
                    if newPhase == .active {
                        // Keep the share extension's contact index in sync and
                        // delete stale/orphaned session directories from the shared container.
                        self.contactManager.syncShareIndex()
                        self.contactManager.cleanupPendingSessions()
                    }
                }
                // Key-rotation → two-sided response:
                // • Bob's path: if we hold shards for this contact, schedule auto-return.
                // • Alice's path: mark any shards we distributed TO this contact as .lost —
                //   their stored shard bytes are cryptographically unreachable under the new key.
                .onReceive(self.contactManager.contactKeyRotated) { identifier in
                    self.shardCustodyManager.scheduleReturnIfShardsCustodied(for: identifier)
                    self.vaultManager.markShardsLost(forContact: identifier)
                }
            }
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
        .environment(self.identityChallenge)
        .environment(self.vaultManager)
        .environment(self.shardCustodyManager)
    }
    
    /// Decode and decrypt an inbound `.occ` file into a shareable ``OwnedBasket``.
    ///
    /// Dispatches to the correct decryption path based on the bundle version:
    /// - `.v3fs` — forward-secret path via ``ContactManager/decrypt(bundle:)``
    /// - `default` — legacy path via ``ContactManager/decrypt(data:)``
    ///
    /// After decryption, file-type attachments are written to a temporary directory
    /// so `AsyncImage` and `AVPlayer` can load them by URL.
    private func buildOwnedBasket(from fileContents: Data) async throws -> OwnedBasket? {
        try await withThrowingTaskGroup(of: Occulta.File.self) { group in
            let bundle = try? OccultaBundle.decoded(from: fileContents)

            debugPrint("Building basket for version: \(bundle?.version.rawValue ?? "none (legacy)")")

            let decrypted: (plaintext: Data, ownerID: String)

            switch bundle?.version {
            case .v3fs:
                guard let bundle else {
                    throw ContactManager.Errors.messageHasNoData
                }

                // ContactManager owns sender identification, prekey resolution,
                // consumed-key cleanup, inbound batch sync, and model persistence.
                //
                // We decrypt into the full SealedPayload (not just the message
                // bytes) so we can peek at the identity-challenge envelope and
                // route that traffic out of the basket pipeline entirely.
                let (sealed, ownerID) = try self.contactManager.decryptSealed(bundle: bundle)

                // Identity-challenge traffic rides on .v3fs/.longTermFallback
                // but is NOT a basket — hand it to the coordinator and bail.
                if let identityEnvelope = sealed.identityChallenge {
                    if let sender = try? self.contactManager.fetchContact(by: ownerID) {
                        _ = self.identityChallenge.handleInboundChallenge(
                            bundle:   bundle,
                            envelope: identityEnvelope,
                            sender:   sender
                        )
                    }
                    return nil
                }

                // Shard-protocol traffic rides on the same envelope. Route on
                // sealed.shardOperations; ShardCustodyManager handles all ops
                // (.distribute / .acknowledge / .revoke / .handback /
                // .notFound / .returnAcknowledged) and decides what to persist.
                if let ops = sealed.shardOperations, !ops.isEmpty,
                   let senderPub = try? self.contactManager.currentPublicKey(forIdentifier: ownerID) {
                    _ = self.shardCustodyManager.handleInbound(
                        sealed:           sealed,
                        senderPublicKey:  senderPub,
                        senderIdentifier: ownerID,
                        vaultManager:     self.vaultManager
                    )

                    return nil
                }

                decrypted = (sealed.message, ownerID)
            default:
                // Legacy path — v1, v2, or pre-versioned files.
                // Falls back to long-term ECDH trial decryption across all contacts.
                decrypted = try self.contactManager.decrypt(data: fileContents)
            }

            let basket = try JSONDecoder().decode(Basket.self, from: decrypted.plaintext)
 
            // ── Write file attachments, photos, videos to temp directory ─────────────────
            
            var processed: [Occulta.File] = []
            let tempDir = FileManager.default.temporaryDirectory
 
            for file in basket.files {
                switch file.format {
                case .file(let metadata):
                    /// Store photos, videos and documents in temp folder if the file's content is a file
                    let fileURL = tempDir
                        .appendingPathComponent(metadata.name ?? UUID().uuidString)
                        .appendingPathExtension(metadata.extension ?? "bin")
                    let content = file.content ?? Data()
 
                    group.addTask {
                        try content.write(to: fileURL)
                        return Occulta.File(url: fileURL, format: file.format, date: file.date)
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
 
            return OwnedBasket(basket: modifiedBasket, owner: decrypted.ownerID)
        }
    }

    // MARK: - Share Extension Processing

    /// Process a share session handed off from the extension via `occulta://share?session=<uuid>`.
    ///
    /// Reads the encrypted manifest, EXIF-strips images, encrypts via the full FS path,
    /// and presents the resulting `.occ` file for sharing. The entire flow is wrapped in
    /// do/catch — any failure deletes the session directory immediately.
    private func processShareSession(sessionID: String) async {
        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
        else { return }

        let sessionDir = containerURL
            .appendingPathComponent("pending")
            .appendingPathComponent(sessionID)

        do {
            // 1. Read and decrypt manifest
            let manifestURL = sessionDir.appendingPathComponent("manifest.enc")
            let keyManager = ShareIndexKeyManager()
            var manifestData = try keyManager.decrypt(data: Data(contentsOf: manifestURL))
            let manifest = try JSONDecoder().decode(ShareManifest.self, from: manifestData)

            // Zero manifest plaintext — contains contact identifier (relationship metadata)
            _ = manifestData.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            manifestData = Data()

            // 2. Build files — EXIF strip images before encryption (in main app, not extension)
            var files: [Occulta.File] = []

            for entry in manifest.files {
                let fileURL = sessionDir.appendingPathComponent(entry.filename)
                var content = try Data(contentsOf: fileURL)

                // Strip EXIF/GPS/camera metadata from images before encryption.
                // If stripping fails (e.g. unsupported format), the original data is used —
                // metadata stays inside the encrypted payload, visible only to the recipient.
                if UTType(entry.uti)?.conforms(to: .image) == true {
                    if let stripped = self.stripEXIF(from: content, uti: entry.uti) {
                        _ = content.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                        content = stripped
                    }
                }

                let metadata = Occulta.File.Metadata(
                    name: UUID().uuidString,
                    extension: entry.fileExtension
                )
                files.append(Occulta.File(content: content, format: .file(metadata)))
            }

            // 3. Encrypt via the full FS path — same as in-app messages
            let basket = Basket(files: files, date: Date())
            var basketData = try JSONEncoder().encode(basket)

            var shardOps: [OccultaBundle.ShardOperation] = []
            if let distributeOps = try? self.shardCustodyManager.pendingDistributeOperations(for: manifest.contactIdentifier)       { shardOps += distributeOps }
            if let returnOps     = try? self.shardCustodyManager.pendingReturnOperations(for: manifest.contactIdentifier)           { shardOps += returnOps }
            if let ackOps        = try? self.shardCustodyManager.pendingAcknowledgeOperation(for: manifest.contactIdentifier)       { shardOps += ackOps }
            if let ackOps        = try? self.shardCustodyManager.pendingShardAcknowledgeOperations(for: manifest.contactIdentifier) { shardOps += ackOps }
            if let revokeOps     = try? self.shardCustodyManager.pendingRevokeOperations(for: manifest.contactIdentifier, vaultManager: self.vaultManager) { shardOps += revokeOps }
            if let inquireOps    = try? self.vaultManager.pendingInquireOperations(for: manifest.contactIdentifier)                 { shardOps += inquireOps }
            if let notFoundOps   = try? self.shardCustodyManager.pendingNotFoundOperations(for: manifest.contactIdentifier)         { shardOps += notFoundOps }
            let occData = try self.contactManager.encryptBundle(
                data: basketData, for: manifest.contactIdentifier, shardOperations: shardOps.isEmpty ? nil : shardOps
            )

            // Zero all plaintext buffers before deallocation.
            // Swift Data uses COW — if Basket copied the buffers, the originals
            // may not be the same allocation. Best-effort; Swift doesn't guarantee zeroing.
            _ = basketData.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            basketData = Data()
            for i in files.indices {
                _ = files[i].content?.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            }
            files = []

            // 4. Write .occ file
            let occID = UUID().uuidString.components(separatedBy: "-").last ?? "shared"
            let occURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(occID).occ")
            try occData.write(to: occURL)

            // 5. Delete session directory — plaintext no longer needed
            try FileManager.default.removeItem(at: sessionDir)

            // 6. Present share sheet
            self.shareResult = ShareResult(url: occURL)

        } catch {
            // Plaintext cleanup on ANY failure — non-negotiable
            try? FileManager.default.removeItem(at: sessionDir)
            self.errorMessage = "Failed to encrypt shared content. \(error.localizedDescription)"
            self.showError = true
        }
    }

    /// Process an inbound `.occ` file handed off from the share extension via
    /// `occulta://inbound?session=<uuid>`.
    ///
    /// Reads `group.com.occulta.shared/inbound/<uuid>.occ`, feeds the bytes
    /// through the same `buildOwnedBasket` pipeline used for Files.app opens,
    /// then routes the result:
    /// - Non-nil basket → `openedFileContents` (regular message / file sheet).
    /// - Nil → `IdentityChallenge.Coordinator` has taken over presentation.
    /// - Error → surfaces via `showError`.
    ///
    /// The `.occ` file is deleted from the shared container on success or failure.
    private func processInboundSession(sessionID: String) async {
        guard let containerURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
        else { return }

        let fileURL = containerURL
            .appendingPathComponent("inbound")
            .appendingPathComponent("\(sessionID).occ")

        defer { try? FileManager.default.removeItem(at: fileURL) }

        do {
            let data = try Data(contentsOf: fileURL)
            if let basket = try await self.buildOwnedBasket(from: data) {
                self.openedFileContents = basket
            }
            // If nil, IdentityChallenge.Coordinator has taken over via its sheets.
        } catch ContactManager.Errors.messageHasNoData {
            self.errorMessage = "This message contains no data."
            self.showError = true
        } catch ContactManager.Errors.noPublicKeyToEncryptWith {
            self.errorMessage = "Could not find this file's owner's public key. It is either corrupted and you need to update the app and try again or the message was not addressed to you."
            self.showError = true
        } catch {
            self.errorMessage = "There was an error. \(error.localizedDescription)"
            self.showError = true
        }
    }

    /// Strip EXIF, GPS, camera metadata from image data using CGImageSource/CGImageDestination.
    private func stripEXIF(from imageData: Data, uti: String) -> Data? {
        guard let source = CGImageSourceCreateWithData(imageData as CFData, nil) else { return nil }

        let destData = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            destData, uti as CFString, 1, nil
        ) else { return nil }

        // Empty properties dictionary strips all metadata
        CGImageDestinationAddImageFromSource(destination, source, 0, [:] as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { return nil }

        return destData as Data
    }
}

// MARK: - Share Types

private struct ShareResult: Identifiable {
    let id = UUID()
    let url: URL
}

/// Wraps `UIActivityViewController` for SwiftUI. Presents the system share sheet
/// with the encrypted `.occ` file so the user can AirDrop, save, or send it.
private struct ShareActivityView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
