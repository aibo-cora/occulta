//
//  OccultaApp.swift
//  Occulta
//
//  Created by Yura on 10/13/25.
//

import SwiftUI
import SwiftData
import CoreData
import Combine
import ImageIO
import SQLite3
import UniformTypeIdentifiers

// TODO: We don't have the Rotate Key option available right now. However, if it becomes available, we need to consider an edge case where we rotate a key and include a new ID as the message owner, but the recipient would not have this ID on record. We would need to keep track of all our past and current IDs and include them in the message for look up.

@main
struct OccultaApp: App {
    @State private var contactManager: ContactManager
    @State private var identityChallenge = IdentityChallenge.Coordinator()
    @State private var vaultManager: VaultManager
    @State private var shardCustodyManager: ShardCustodyManager
    @State private var security: Manager.Security
    @State private var appManager: Manager.App
    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false
    @Environment(\.scenePhase) private var scenePhase
    
    var sharedModelContainer: ModelContainer
    /// SwiftData store URL. Retained so `reapplyFileProtection()` can stamp
    /// fresh -wal/-shm files that SQLite creates after the initial attributes call.
    private let storeURL: URL

    init() {
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
            PendingShardStatusUpdate.self,
            PotentiallyLostShard.self,
            GlobalShardConfig.self,
            BackupEncryptionKey.self,
            AppLayerConfig.self,
        ])

        let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false, cloudKitDatabase: .none)
        let sharedModelContainer: ModelContainer
        do {
            sharedModelContainer = try ModelContainer(for: schema, configurations: [modelConfiguration])
        } catch {
            fatalError("Could not create ModelContainer: \(error)")
        }
        let url = modelConfiguration.url
        let attrs: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path)
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path + "-wal")
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path + "-shm")

        self.storeURL = url
        Self.applySecureDeletePragma(at: url)

        let contactManager = ContactManager(modelContainer: sharedModelContainer)
        let vaultManager   = VaultManager(modelContainer: sharedModelContainer)

        self.sharedModelContainer = sharedModelContainer
        self.contactManager      = contactManager
        self.vaultManager        = vaultManager
        let security             = Manager.Security(modelContainer: sharedModelContainer,
                                                     storeURL: url,
                                                     enabled: FeatureFlags.isEnabled(.secureMode))
        if FeatureFlags.isEnabled(.secureMode) {
            security.maintainLayerStore()
        }
        self.security            = security
        self.appManager          = Manager.App(contacts: contactManager, vault: vaultManager)
        self.shardCustodyManager = ShardCustodyManager(modelContainer: sharedModelContainer, keyManager: Manager.Key())
        
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
    /// Raw encrypted `.occ` bytes queued while the app is locked.
    /// Held without any processing until the PIN depth is known.
    /// Cleared by onNormal (process) or onDuress (discard).
    @State private var pendingFileData: Data?
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
                    let fileLocation: URL
                    var openedThroughShareExtension = false
                    
                    if url.scheme == "occulta",
                       let components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
                        // Handle share extension handoff (outbound) and inbound .occ routing.
                        
                        guard
                            let rawSessionID = components.queryItems?.first(where: { $0.name == "session" })?.value,
                            let sessionUUID = UUID(uuidString: rawSessionID)
                        else {
                            return
                        }
                        
                        let sessionID = sessionUUID.uuidString  // guaranteed: only [0-9a-fA-F-], no path separators
                        
                        switch url.host {
                        case "inbound":
                            /// Process an inbound `.occ` file handed off from the share extension via
                            /// `occulta://inbound?session=<uuid>`.
                            ///
                            /// Reads `group.com.occulta.shared/inbound/<uuid>.occ`
                            ///
                            guard let containerURL = FileManager.default
                                .containerURL(forSecurityApplicationGroupIdentifier: "group.com.occulta.shared")
                            else { return }

                            let fileURL = containerURL
                                .appendingPathComponent("inbound")
                                .appendingPathComponent("\(sessionID).occ")
                            
                            fileLocation = fileURL
                            openedThroughShareExtension = true
                            
                            break
                        case "share":
                            self.processShareSession(sessionID: sessionID)
                            
                            return
                        default:
                            return  // unknown host — ignore silently
                        }
                    } else {
                        fileLocation = url
                    }
                    
                    Task {
                        defer {
                            if openedThroughShareExtension {
                                try? FileManager.default.removeItem(at: fileLocation)
                            }
                        }
                        /// This is the case when we open occulta files that are located in `Files`
                        /// "file://"
                        let accessing = fileLocation.startAccessingSecurityScopedResource()
                        
                        defer {
                            if accessing {
                                fileLocation.stopAccessingSecurityScopedResource()
                            }
                        }
                        
                        do {
                            /// Contents of the encrypted file we opened.
                            let (data, _) = try await URLSession.shared.data(from: fileLocation)

                            // .occbak — vault backup restore file.
                            if fileLocation.pathExtension == "occbak" {
                                try self.vaultManager.storePendingRestore(data)
                                return
                            }

                            // Secure Mode gate: if the app is locked, queue raw bytes
                            // without any processing. PIN entry determines depth; onNormal
                            // processes the data, onDuress discards it.
                            if self.security.needsPINEntry {
                                self.pendingFileData = data
                                return
                            }

                            await self.processInboundFile(data)
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
                    switch newPhase {
                    case .inactive:
                        self.security.handleInactive(vaultUnlocked: self.vaultManager.isUnlocked)
                        if self.security.requiresPIN, self.security.pinEnabled,
                           self.vaultManager.isUnlocked {
                            self.contactManager.shareIndexAllowedIDs = self.security.safeContactIDs(atDepth: 1)
                            self.contactManager.syncShareIndex()
                        }
                    case .background:
                        self.security.handleBackground()
                    case .active:
                        self.security.handleActive()
                        // Drain any bundle queued while locked on grace-period auto-unlock.
                        // PIN-entry unlock drains via fullScreenCover.onDismiss; this covers
                        // the grace-period path where no cover was ever presented.
                        if !self.security.needsPINEntry, let data = self.pendingFileData {
                            self.pendingFileData = nil
                            Task { await self.processInboundFile(data) }
                        }
                        // Rebuild share index at correct depth for this foreground cycle.
                        if self.security.needsPINEntry || self.security.isRestricted {
                            self.contactManager.shareIndexAllowedIDs = self.security.safeContactIDs(atDepth: 1)
                        } else {
                            self.contactManager.shareIndexAllowedIDs = nil
                        }
                        self.contactManager.syncShareIndex()
                        self.contactManager.cleanupPendingSessions()
                    default:
                        break
                    }
                }
                // Opaque overlay: covers content instantly on lock and during .inactive
                // for screenshot protection (Bug 33/36). Always instant — no fade animation.
                // SwiftUI overlay — does NOT conflict with UIActivityViewController.
                .overlay {
                    Color(.systemBackground)
                        .ignoresSafeArea()
                        .opacity(self.security.isContentHidden ? 1 : 0)
                        .animation(.none, value: self.security.isContentHidden)
                        .allowsHitTesting(false)
                }
                // fullScreenCover rather than overlay: a UIKit modal presentation
                // stacks above any existing sheets, so it cannot be underlapped by
                // conversation or identity-challenge sheets triggered while locked.
                //
                // pendingFileData is drained in onDismiss (not in onNormal) so the
                // message sheet is only presented after the cover has fully dismissed.
                // Presenting a sheet while a fullScreenCover is still animating out
                // creates a UIKit conflict that causes the cover to re-present when
                // the sheet is later dismissed.
                .fullScreenCover(isPresented: Binding(
                    get: { self.security.needsPINEntry },
                    set: { self.security.needsPINEntry = $0 }
                ), onDismiss: {
                    // Cover fully gone — safe to present the message sheet now.
                    // onDuress already cleared pendingFileData; only onNormal leaves it set.
                    if let data = self.pendingFileData {
                        self.pendingFileData = nil
                        Task { await self.processInboundFile(data) }
                    }
                }) {
                    PINEntry(
                        onNormal: { _ in
                            self.security.unlockNormal()
                            self.contactManager.shareIndexAllowedIDs = nil
                            self.contactManager.syncShareIndex()
                            // pendingFileData drain moved to the fullScreenCover's onDismiss.
                        },
                        onDuress: {
                            self.security.unlockDuress()
                            // Discard any file queued while locked — duress depth must
                            // not reveal content from sensitive contacts.
                            if self.pendingFileData != nil {
                                self.pendingFileData = nil
                                self.errorMessage = "This message was not addressed to you."
                                self.showError = true
                            }
                            self.contactManager.shareIndexAllowedIDs = self.security.safeContactIDs()
                            self.contactManager.syncShareIndex()
                        }
                    )
                    .environment(self.security)
                }
                // Key-rotation → two-sided response:
                // Alice's path: mark any shards distributed TO this contact as .lost.
                // Bob's path: mismatch-fingerprint shards are returned via .handback on
                // the next outbound bundle (detected at build time, no scheduling needed).
                .onReceive(self.contactManager.contactKeyRotated) { identifier in
                    self.vaultManager.markShardsLost(forContact: identifier)
                }
                // Reapply .completeFileProtection after every save.
                // SwiftData recreates -wal/-shm sidecar files on WAL merges,
                // migrations, and conflict resolution — outside the app's init
                // lifecycle. Re-stamp each time a context saves so no sidecar
                // can sit with weaker default protection.
                .onReceive(NotificationCenter.default.publisher(
                    for: NSManagedObjectContext.didSaveObjectIDsNotification
                ).receive(on: DispatchQueue.main)) { _ in
                    self.reapplyFileProtection()
                }
                // Rewrite the no-op blob on every save (debounced 30 s) so the
                // blob's Last-Modified timestamp correlates with normal app activity,
                // not with Secure Mode activation. Only rewrites when Secure Mode is
                // inactive — when active the blob holds a real payload that must not
                // be overwritten.
                .onReceive(NotificationCenter.default.publisher(
                    for: NSManagedObjectContext.didSaveObjectIDsNotification
                )
                .receive(on: DispatchQueue.main)
                .debounce(for: .seconds(30), scheduler: DispatchQueue.main)) { [self] _ in
                    guard FeatureFlags.isEnabled(.secureMode) else { return }
                    self.security.rewriteLayerStore()
                }
                .animation(.none, value: self.security.needsPINEntry)
            }
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
        .environment(self.identityChallenge)
        .environment(self.vaultManager)
        .environment(self.shardCustodyManager)
        .environment(self.security)
        .environment(self.appManager)
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
                /// To avoid popping a prekey prematurely, in case this ownerID belongs to a sensitive contact, we are going to run the id through the checkpoint and throw if it is on the list.
                if let ownerID = try self.contactManager.identifyOwner(of: bundle) {
                    try self.passSecurityControl(identifier: ownerID)
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
                
                #if DEBUG
                debugPrint("Manifest: \(sealed.custodyManifest?.description ?? "nil")")
                debugPrint("Expected: \(sealed.expectedShards?.description ?? "nil")")
                #endif

                // Handle shard operations and manifest reconciliation.
                
                if let senderPublicKey = try? self.contactManager.currentPublicKey(forIdentifier: ownerID) {
                    _ = self.shardCustodyManager.handleInbound(
                        sealed:           sealed,
                        senderPublicKey:  senderPublicKey,
                        senderIdentifier: ownerID,
                        vaultManager:     self.vaultManager
                    )
                }

                decrypted = (sealed.message, ownerID)
            case .unsupported:
                throw OccultaBundle.BundleError.unsupportedVersion
            default:
                // Legacy path — nil, v1, v2, or pre-versioned files.
                // Falls back to long-term ECDH trial decryption across all contacts.
                decrypted = try self.contactManager.decrypt(data: fileContents)
                /// If the bundle is in legacy format, make sure it goes through the checkpoint before processing it.
                try self.passSecurityControl(identifier: decrypted.ownerID)
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

    // MARK: - Inbound file processing

    /// Decrypts and displays an inbound `.occ` file.
    ///
    /// Single entry point for all inbound message processing — called from `onOpenURL`
    /// when the app is already unlocked, and from `onNormal` after PIN entry clears
    /// a queued file. Never called from `onDuress` — that path discards.
    ///
    /// All error handling lives here so neither call site needs to repeat it.
    private func processInboundFile(_ data: Data) async {
        do {
            if let ownedBasket = try await self.buildOwnedBasket(from: data) {
                self.openedFileContents = ownedBasket
            }
        } catch ContactManager.Errors.messageHasNoData {
            self.errorMessage = "This message contains no data."
            self.showError = true
        } catch ContactManager.Errors.noPublicKeyToEncryptWith {
            self.errorMessage = "Could not find this file's owner's public key. It is either corrupted and you need to update the app and try again or the message was not addressed to you."
            self.showError = true
        } catch OccultaBundle.BundleError.unsupportedVersion,
                OccultaBundle.BundleError.unsupportedMode {
            self.errorMessage = "Your contact is using a newer version of Occulta. Update the app to open this message."
            self.showError = true
        } catch {
            self.errorMessage = "There was an error. \(error.localizedDescription)"
            self.showError = true
        }
    }
    
    /// Checkpoint A.
    ///
    /// We need to make sure that sensitive contacts' messages are being treated as wrong recipient events.
    /// - Parameter identifier: Contact identifier.
    private func passSecurityControl(identifier: String) throws {
        if self.security.isRestricted && self.security.isSafeContact(identifier) == false {
            throw ContactManager.Errors.noPublicKeyToEncryptWith
        }
    }

    // MARK: - Share Extension Processing

    /// Process a share session handed off from the extension via `occulta://share?session=<uuid>`.
    ///
    /// Reads the encrypted manifest, EXIF-strips images, encrypts via the full FS path,
    /// and presents the resulting `.occ` file for sharing. The entire flow is wrapped in
    /// do/catch — any failure deletes the session directory immediately.
    private func processShareSession(sessionID: String) {
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

            let contactID  = manifest.contactIdentifier
            let contactPub = try? self.contactManager.currentPublicKey(forIdentifier: contactID)
            let shardOps   = try self.shardCustodyManager.buildShardOperations(for: contactID, currentContactPublicKey: contactPub)
            let manifest_  = try? self.shardCustodyManager.buildCustodyManifest(for: contactID)
            let expected   = try? self.shardCustodyManager.buildExpectedShards(for: contactID, vaultManager: self.vaultManager)

            let occData = try self.contactManager.encryptBundle(
                data:            basketData,
                for:             contactID,
                shardOperations: shardOps.isEmpty ? nil : shardOps,
                custodyManifest: manifest_,
                expectedShards:  expected
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

    /// Applies `PRAGMA secure_delete = ON` to the persistent SQLite store.
    ///
    /// Without this pragma, SQLite leaves old content — in this app, old AES-GCM
    /// ciphertext blobs — in its free-list pages when rows are deleted or updated.
    /// That residue persists through WAL checkpoints and is visible in raw disk images.
    /// With `secure_delete = ON`, freed pages are zeroed before release, eliminating
    /// the residue entirely.
    ///
    /// SwiftData does not expose `NSSQLitePragmasOption` through its public API, so we
    /// open a short-lived helper connection via the SQLite3 C API and set the pragma
    /// there. In SQLite 3.12+ (shipped with iOS 12+), `secure_delete` is stored in the
    /// database header and persists across all future connections to the same file —
    /// including SwiftData's own connection. Setting it here, immediately after the store
    /// is created, ensures it takes effect before the first user-triggered write.
    ///
    /// Called once in `init()` after `ModelContainer` creates the store file. Also
    /// applied during Step 4's key-rotation sequence, where it is set explicitly on
    /// the direct SQLite connection used for re-encryption — that path does not rely on
    /// header persistence.
    private static func applySecureDeletePragma(at url: URL) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else { return }
        defer { sqlite3_close(db) }
        sqlite3_exec(db, "PRAGMA secure_delete = ON", nil, nil, nil)
    }

    /// Reapply `.completeFileProtection` to the SwiftData store and its WAL/SHM files.
    ///
    /// SwiftData (via SQLite) can recreate `-wal` and `-shm` sidecar files after
    /// checkpoints, schema migrations, or WAL merges. The initial `setAttributes`
    /// call in `init()` covers the baseline; this method re-stamps every time a
    /// `ModelContext` saves so newly-created sidecar files are always protected.
    ///
    /// Called via `.onReceive(NSManagedObjectContext.didSaveNotification)` in `body`.
    private func reapplyFileProtection() {
        let attrs: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
        let path = self.storeURL.path
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: path)
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: path + "-wal")
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: path + "-shm")
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
