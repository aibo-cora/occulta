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
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    @State private var contactManager: ContactManager
    @State private var identityChallenge = IdentityChallenge.Coordinator()
    @State private var vaultManager: VaultManager
    @State private var shardCustodyManager: ShardCustodyManager
    @State private var security: Manager.Security
    @State private var appManager: Manager.App

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
            Message.Draft.self,
            VaultEntry.self,
            CustodyShard.self,
            ReconstructShard.self,
            PendingShardDistribute.self,
            PendingShardStatusUpdate.self,
            PotentiallyLostShard.self,
            GlobalShardConfig.self,
            BackupEncryptionKey.self,
            AppLayerConfig.self,
            Group.self,
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
        RootView.excludeStoreFromBackup(url: url)

        self.storeURL = url
        Self.applySecureDeletePragma(at: url)
        Self.walCheckpoint(at: url)

        let security = Manager.Security(modelContainer: sharedModelContainer,
                                        storeURL: url,
                                        enabled: FeatureFlags.isEnabled(.secureMode))
        if FeatureFlags.isEnabled(.secureMode) {
            security.maintainLayerStore()
        }
        self.security = security

        let contactManager = ContactManager(modelContainer: sharedModelContainer, security: security)
        let vaultManager   = VaultManager(modelContainer: sharedModelContainer)

        self.sharedModelContainer = sharedModelContainer
        self.contactManager       = contactManager
        self.vaultManager         = vaultManager
        self.appManager          = Manager.App(contacts: contactManager, vault: vaultManager)
        self.shardCustodyManager = ShardCustodyManager(modelContainer: sharedModelContainer, keyManager: Manager.Key())

        self.migrate()
        FileManager.default.clearTemporaryDirectory()
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

        // Independent of the v1→v2 migration above — runs regardless of Secure Mode
        // configuration status, since legacy nil rows can exist either way.
        do {
            try DatabaseMigration.migrateSafeContactVisibilityBackfill(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("visibleThroughDepth backfill error: \(error)")
            #endif
        }

        do {
            try DatabaseMigration.migrateGlobalTrusteeDepthBackfill(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("globalTrusteeDepth backfill error: \(error)")
            #endif
        }

        do {
            try DatabaseMigration.migrateOriginDepthBackfill(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("originDepth backfill error: \(error)")
            #endif
        }

        do {
            try DatabaseMigration.migrateGlobalShardConfigToPerContact(
                modelContext: context, shardCustodyManager: self.shardCustodyManager
            )
        } catch {
            #if DEBUG
            debugPrint("GlobalShardConfig consolidation error: \(error)")
            #endif
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView(storeURL: self.storeURL)
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
        .environment(self.identityChallenge)
        .environment(self.vaultManager)
        .environment(self.shardCustodyManager)
        .environment(self.security)
        .environment(self.appManager)
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

    private static func walCheckpoint(at url: URL) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else { return }
        defer { sqlite3_close(db) }
        sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", nil, nil, nil)
    }
}

// MARK: - Root View

private struct RootView: View {

    let storeURL: URL

    @EnvironmentObject private var appScreen: AppScreen
    @Environment(Manager.Security.self) private var security
    @Environment(ContactManager.self) private var contactManager
    @Environment(IdentityChallenge.Coordinator.self) private var identityChallenge
    @Environment(VaultManager.self) private var vaultManager
    @Environment(ShardCustodyManager.self) private var shardCustodyManager

    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false
    @Environment(\.scenePhase) private var scenePhase

    /// Container with plaintext message or file.
    @State private var openedFileContents: OwnedBasket?
    /// Raw encrypted `.occ` bytes queued while the app is locked.
    /// Held without any processing until a PIN unlocks the app.
    ///
    /// Drained by the shared `.onChange(of: appScreen.phase)` handler on **any** unlock, normal
    /// or duress alike. `onDuress` used to discard this instead — that discard was the last place
    /// duress state produced observably different behaviour from a normal unlock, which made it
    /// part of the detection oracle in
    /// `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`, and it was
    /// removed in `2958593`.
    ///
    /// So reaching `processInboundFile` does **not** imply depth 0. Anything downstream that needs
    /// depth safety has to establish it for itself rather than inferring it from this path.
    @State private var pendingFileData: Data?
    // Error feedback
    @State private var showError = false
    @State private var errorMessage = ""
    /// Encrypted `.occ` file ready for sharing via UIActivityViewController.
    @State private var shareResult: ShareResult?

    // MARK: Body

    var body: some View {
        self.phaseContent
            // No transitions between phases — content must never flash through states.
            .animation(.none, value: self.appScreen.phase)
            // Wire security to AppScreen once, on first appearance.
            .task {
                self.appScreen.wire(security: self.security)

                // Clear Group rows stranded by a pre-`Group.reencrypt` key rotation (Bug 75).
                //
                // Sweep orphaned groups only once a depth is actually known — see
                // `purgeOrphanedGroupsIfAtRealDepth()`. With a PIN gate configured, `wire()`
                // above has just set the phase to `.pinRequired`, so this call is a no-op and
                // the `.onChange` handler below does the work once a PIN has been entered.
                // Without a gate, `wire()` went straight to `.unlocked` and this call is what
                // covers that case. Both may fire; the sweep is idempotent.
                self.purgeOrphanedGroupsIfAtRealDepth()

                // Unconditional, at every depth and on every launch, and deliberately not
                // folded into the purge above: a checkpoint that fired only at depth 0 would
                // make checkpoint timing itself a depth signal — the failure
                // `checkpointStore()`'s own documentation exists to prevent.
                self.security.checkpointStore()

                // Move blob metadata onto the non-rotating SE-derived key (Bug 76). Runs at
                // every depth, unlike the purge above: it writes no delete records, and a
                // still-unmigrated entry would be read as absent by the very next activation —
                // which can happen at a duress depth — silently orphaning a live blob.
                self.security.migrateBlobMetadataKeyIfNeeded()
            }
            // onOpenURL must be on the outermost container so it fires in all phases.
            .onOpenURL { url in self.handleOpenURL(url) }
            .alert("Error", isPresented: self.$showError) {
                Button("OK") { }
            } message: {
                Text(self.errorMessage)
            }
            .sheet(item: self.$openedFileContents) {
                /// Dismiss
            } content: { data in
                let manager = (try? self.contactManager.fileEncryptionKey(for: data.owner))
                    .map { AttachmentManager(contactKey: $0) }
                ComposableMessage.Conversation(mode: .read(messageOwner: data.owner), messages: .constant(data.basket.files), attachmentManager: manager)
                    .onDisappear {
                        data.basket.files.forEach { file in
                            if let url = file.url { try? FileManager.default.removeItem(at: url) }
                        }
                    }
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
            // Drain any file queued while locked when the app unlocks (PIN entry or
            // grace-period auto-unlock). Processes identically regardless of which PIN
            // succeeded — passSecurityControl's removal (Non-Safe-Sender-Rejection-Is-A-
            // Duress-Detection-Oracle.md) means there's no restriction-gated rejection
            // left to differ on, so a duress unlock draining this the same way as a
            // normal one introduces no new signal.
            .onChange(of: self.appScreen.phase) { _, newPhase in
                guard newPhase == .unlocked else { return }
                // `applyVerifyState` sets `currentDepth` before `pinDidSucceed()` flips the
                // phase (PINEntry.swift:253), so the depth read here is the authenticated one.
                self.purgeOrphanedGroupsIfAtRealDepth()

                // Flushes the purge's delete records out of the WAL (`secure_delete` zeroes
                // them on the way), and runs on **every** unlock at every depth even though
                // only a depth-0 unlock can have deleted anything — a checkpoint that followed
                // the deletion would otherwise announce it.
                self.security.checkpointStore()
                if let data = self.pendingFileData {
                    self.pendingFileData = nil
                    Task { await self.processInboundFile(data) }
                }
            }
            .onChange(of: self.scenePhase) { _, newPhase in
                switch newPhase {
                case .active:
                    self.contactManager.cleanupPendingSessions()
                case .inactive:
                    // Defense-in-depth, not a correctness fix — syncShareIndex() already
                    // runs after every contact mutation, unlock/duress-unlock, activate,
                    // and deactivate, which cover every path that changes currentDepth or
                    // isSecureModeActive today. This re-asserts the already-correct index
                    // right before backgrounding, hedging against any future path that
                    // changes security state without going through one of those four.
                    self.contactManager.syncShareIndex()
                default:
                    break
                }
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
    }

    // MARK: Phase content

    @ViewBuilder
    private var phaseContent: some View {
        switch self.appScreen.phase {
        case .covered:
            // UIKit cover is on top; render nothing visible beneath it.
            Color.clear.ignoresSafeArea()
        case .pinRequired:
            PINEntry(
                onAuthenticated: { _ in
                    self.appScreen.pinDidSucceed()
                    self.contactManager.syncShareIndex()
                },
                onDuress: {
                    self.contactManager.syncShareIndex()
                    self.appScreen.pinDidSucceed()
                }
            )
            .environment(self.security)
            // pinViewAppeared() is called here (not inside PINEntry) so the UIKit
            // cover is removed as soon as PINEntry is on screen.
            .onAppear { self.appScreen.pinViewAppeared() }
        case .unlocked:
            if !self.hasCompleted {
                OnboardingView()
            } else {
                self.tabContent
            }
        }
    }

    // MARK: Tab content

    @ViewBuilder
    private var tabContent: some View {
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
    }

    // MARK: URL handling

    private func handleOpenURL(_ url: URL) {
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
                ///
                /// Memory-mapped rather than eagerly read into a heap buffer: this file
                /// can legitimately be large (photo/video attachments, vault backups),
                /// and mapping lets the OS page it in lazily and reclaim pages under
                /// memory pressure instead of committing the whole file to RSS upfront
                /// (SecurityReview2026-07-24, finding #11 — unbounded inbound file read).
                /// Run off the main actor: `RootView` conforms to `View`, which is
                /// `@MainActor`, and while mapping itself is nearly free, touching pages
                /// later (or a cold/on-demand-downloaded file) can still block briefly.
                let data = try await Task.detached(priority: .userInitiated) {
                    try Data(contentsOf: fileLocation, options: .mappedIfSafe)
                }.value

                // .occbak — vault backup restore file.
                if fileLocation.pathExtension == "occbak" {
                    try self.vaultManager.storePendingRestore(data)
                    return
                }

                // Secure Mode gate: if the app is locked, queue raw bytes without any
                // processing. Both unlock paths then drain it identically — see
                // `pendingFileData`; a duress unlock no longer discards it.
                if self.appScreen.phase != .unlocked {
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

    // MARK: Inbound file processing

    /// Decrypts and displays an inbound `.occ` file.
    ///
    /// Single entry point for all inbound message processing — called from `onOpenURL`
    /// when the app is already unlocked, and from onChange(of: appScreen.phase) after
    /// any PIN entry (normal or duress) clears a queued file — both unlock paths drain
    /// and process identically.
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
        // ⚠️ One string for both, and it must stay that way. Splitting them is a duress oracle.
        //
        // `senderSignatureCapabilityUnknown` fires only when this device's record of the
        // sender's version is present but undecryptable, which happens only after a local DB
        // key rotation that predates `maxBundleVersion` joining `reencryptAllFields` — i.e.
        // only on an install that activated Secure Mode while running 1.10.0 or 1.10.1.
        // `missingSenderEphemeralSignature` fires when that record reads fine. So two distinct
        // strings let anyone who can deliver one unsigned forward-secret bundle read off
        // whether this device has ever used Secure Mode, by opening the file and looking at the
        // alert. That is the shape of oracle removed in `b1f9045`, and a deactivation does not
        // undo it: the stranded ciphertext is preserved on purpose (see Bug 80), so the tell
        // outlives the feature it reveals.
        //
        // **This is not a clear win, and the losses are real.**
        //
        // Bug 81 argued for the split and the argument was sound: "ask this contact to update"
        // is actionable, and the overwhelmingly likely cause of a refusal is a contact still on
        // 1.9.x rather than an attack. That advice is now gone, and every benign
        // old-contact refusal reads as a security event. Alarm fatigue is the mild version of
        // the cost; the sharp version is a user coming to distrust a contact who did nothing
        // wrong, and withdrawing from a channel that was safe.
        //
        // The advice is not gone from the app, only from here: the group-eligibility screen
        // still says "Needs to update Occulta" for exactly these contacts, which is where a
        // user goes when they want to know why someone is unreachable.
        //
        // Note this resolves *opposite* to the same question on that screen, which collapses
        // toward the innocuous label rather than the alarming one. Not an inconsistency — the
        // failure modes differ. There, the alternative contradicts message history the user can
        // see on the device. Here, the alternative tells the victim of an impersonation attempt
        // that their friend needs a software update, which is the attacker's cover story
        // repeated back by the app. So each side collapses away from its own worse outcome.
        //
        // What this does not close: `.unrecorded` still accepts an unsigned bundle rather than
        // refusing it, so open-versus-refuse remains observable. That distinguishes a contact
        // this device has never heard from, not one it is hiding — and a contact who has never
        // sent anything holds no prekey of ours and cannot send forward-secret traffic at all.
        // No duress state is recoverable from it.
        } catch GroupDecryptError.senderSignatureCapabilityUnknown,
                GroupDecryptError.missingSenderEphemeralSignature {
            self.errorMessage = "Occulta couldn't confirm this message came from this contact, so it wasn't opened."
            self.showError = true
        } catch {
            self.errorMessage = "There was an error. \(error.localizedDescription)"
            self.showError = true
        }
    }

    /// Clears `Group` rows stranded by a pre-1.10.2 key rotation (Bug 75), but only once the
    /// current depth is genuinely established and is 0.
    ///
    /// The distinction matters and the first version of this got it wrong. `currentDepth` is
    /// declared `= 0` and is only populated from `persistedDepth` when the PIN gate is down
    /// (`Manager+Security.swift:245`), so with a PIN configured it reads 0 at launch no matter
    /// which PIN is about to be entered. Gating on the value alone therefore meant "nobody has
    /// authenticated yet", not "the real user is here" — and a launch under coercion would run
    /// the sweep, writing row deletions before the duress PIN was entered. Requiring
    /// `.unlocked` as well is what makes the depth reading trustworthy.
    ///
    /// Safe to call from both the launch task and the unlock transition: the sweep is
    /// idempotent, and finds nothing once clean.
    ///
    /// The key is derived here and passed in. `purgeUnreadableGroups` judges every row against
    /// it, so a failed derivation must stop the sweep rather than reach it as a nil that would
    /// condemn the whole table.
    @MainActor
    private func purgeOrphanedGroupsIfAtRealDepth() {
        guard self.appScreen.phase == .unlocked,
              self.security.currentDepth == 0,
              let key = try? Manager.Key().createHybridLocalEncryptionKey()
        else { return }

        try? self.contactManager.purgeUnreadableGroups(using: key)
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
            var decodedBundleVersion: OccultaBundle.Version = .v3fs

            switch bundle?.version {
            case .v3fs, .v4:
                guard let bundle else {
                    throw ContactManager.Errors.messageHasNoData
                }
                let knownOwnerID = try self.contactManager.identifyOwner(of: bundle)

                // ⚠️ The envelope's presence reflects the **sender's view of us**, not the
                // sender's own capability. `encryptBundle` picks the format from
                // `resolveTargetVersion(for: recipient)`, so a current build sends the
                // *non-group* format to anyone it resolves below `.groupCapable` — including
                // every contact whose marker it has stranded, which is the whole Bug 77/80
                // population. A non-group bundle therefore says nothing about how old the
                // sender is, and no check here may infer that it does.
                //
                // Consequence worth knowing: `openGroup`'s sender-signature gate has no
                // counterpart on the branch below, because `senderEphemeralSignature` lives on
                // `RecipientPayload` and the non-group format has no such field. That asymmetry
                // grants nothing today — the prekey store and the identity key sit behind
                // identical access control (`.privateKeyUsage`, device-unlocked, no biometric),
                // so anyone able to build a legacy FS bundle can equally sign a group one — but
                // do not read the gate as covering both paths.
                if bundle.group != nil {
                    // Group bundle — all sends to a recipient the sender resolves as 1.9.0+
                    // (messages, shards, custody ops) use this path. Shard-only bundles signal
                    // "no basket" via an empty message field.
                    let (sealed, ownerID, _, recipShardOps, recipManifest, recipExpected) =
                        try self.contactManager.openGroup(bundle: bundle, ownerID: knownOwnerID)
                    decodedBundleVersion = bundle.version

                    // Identity-challenge traffic inside a group bundle.
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

                    // Shard/custody ops. Per-recipient fields take priority; falling back
                    // to the shared sealed payload's own fields keeps the already-shipped
                    // 1:1-via-group-envelope shard path (single-recipient encryptBundle,
                    // which has no per-recipient content to pad) working unchanged.
                    if let senderPublicKey = try? self.contactManager.currentPublicKey(forIdentifier: ownerID) {
                        _ = self.shardCustodyManager.handleInbound(
                            shardOperations:  recipShardOps ?? sealed.shardOperations,
                            custodyManifest:  recipManifest ?? sealed.custodyManifest,
                            expectedShards:   recipExpected ?? sealed.expectedShards,
                            senderPublicKey:  senderPublicKey,
                            senderIdentifier: ownerID,
                            vaultManager:     self.vaultManager
                        )
                    }

                    // Shard-only bundle (empty message) — ops handled above, no basket.
                    guard !sealed.message.isEmpty else { return nil }
                    decrypted = (sealed.message, ownerID)
                } else {
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
                            shardOperations:  sealed.shardOperations,
                            custodyManifest:  sealed.custodyManifest,
                            expectedShards:   sealed.expectedShards,
                            senderPublicKey:  senderPublicKey,
                            senderIdentifier: ownerID,
                            vaultManager:     self.vaultManager
                        )
                    }

                    decodedBundleVersion = bundle.version
                    decrypted = (sealed.message, ownerID)
                }
            case .unsupported:
                throw OccultaBundle.BundleError.unsupportedVersion
            default:
                // Legacy path — nil, v1, v2, or pre-versioned files.
                // Falls back to long-term ECDH trial decryption across all contacts.
                decrypted = try self.contactManager.decrypt(data: fileContents)
            }

            let basket: Basket
            if decodedBundleVersion == .v4 {
                basket = try WireHandle.decode(basket: decrypted.plaintext)
            } else {
                basket = try JSONDecoder().decode(Basket.self, from: decrypted.plaintext)
            }

            // ── Write file attachments, photos, videos to temp directory ─────────────────

            var processed: [Occulta.File] = []
            let tempDir         = FileManager.default.temporaryDirectory
            let attachmentManager = (try? self.contactManager.fileEncryptionKey(for: decrypted.ownerID))
                .map { AttachmentManager(contactKey: $0) }

            for file in basket.files {
                switch file.format {
                case .file(let metadata):
                    // metadata.name/.extension come from the decrypted, sender-controlled
                    // Basket — never trusted for path construction. The name is dropped
                    // entirely in favor of a fresh UUID (matching the outbound share-extension
                    // path's existing discipline); the extension is validated by
                    // sanitizedFilesystemExtension since a crafted value like
                    // "../../etc/passwd" could otherwise steer the write outside tempDir.
                    // Rejecting anything unsafe doesn't lose real data — the file's display
                    // name/extension in the UI still comes from the untouched `metadata` in
                    // `file.format` below, only the on-disk path changes.
                    let fileURL = tempDir
                        .appendingPathComponent(UUID().uuidString)
                        .appendingPathExtension(Occulta.File.Metadata.sanitizedFilesystemExtension(metadata.extension))
                    let content = file.content ?? Data()

                    group.addTask {
                        if let manager = attachmentManager {
                            try manager.encrypt(content, to: fileURL)
                        } else {
                            try content.writeProtected(to: fileURL)
                        }
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

    // MARK: Share Extension Processing

    private enum ShareSessionError: Error, LocalizedError {
        case staleSession

        var errorDescription: String? {
            switch self {
            case .staleSession: return "This share session has expired. Please share the content again."
            }
        }
    }

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

            // Reject stale sessions — same 1-hour cutoff cleanupPendingSessions uses.
            // Correctness/robustness, not a security boundary (the session directory
            // only exists inside this app's own App Group container): guards against a
            // stale or already-processed session being unexpectedly reprocessed, e.g. a
            // re-tapped notification or duplicate deep-link delivery
            // (SecurityReview2026-07-24, finding #11).
            guard manifest.createdAt > Date().addingTimeInterval(-3600) else {
                throw ShareSessionError.staleSession
            }

            // Zero manifest plaintext — contains contact identifier (relationship metadata)
            _ = manifestData.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            manifestData = Data()

            // 2. Build files — EXIF strip images before encryption (in main app, not extension)
            var files: [Occulta.File] = []
            // Safety net for every exit from this do block, not just the success path
            // below: a throw anywhere after files starts accumulating decrypted content
            // (encryptBundle, a later loop iteration's decrypt/EXIF-strip) previously left
            // that plaintext un-zeroed on the heap — the catch block only deleted the
            // on-disk session directory. A defer here runs on the success path too (right
            // after the explicit zero below, so it finds an already-empty array — harmless)
            // and on any throw, whatever files currently holds.
            defer {
                for i in files.indices {
                    _ = files[i].content?.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                }
            }

            for entry in manifest.files {
                let fileURL = sessionDir.appendingPathComponent(entry.filename)
                var ciphertext = try Data(contentsOf: fileURL)
                var content = try keyManager.decrypt(data: ciphertext)
                _ = ciphertext.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                ciphertext = Data()

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
            let basket    = Basket(files: files, date: Date())
            let contactID = manifest.contactIdentifier
            let contactPub = try? self.contactManager.currentPublicKey(forIdentifier: contactID)
            let shardOps   = try self.shardCustodyManager.buildShardOperations(for: contactID, currentContactPublicKey: contactPub)
            let manifest_  = try? self.shardCustodyManager.buildCustodyManifest(for: contactID)
            let expected   = try? self.shardCustodyManager.buildExpectedShards(for: contactID, vaultManager: self.vaultManager)

            let occData = try self.contactManager.encryptBundle(
                basket:          basket,
                for:             contactID,
                shardOperations: shardOps.isEmpty ? nil : shardOps,
                custodyManifest: manifest_,
                expectedShards:  expected
            )
            for i in files.indices {
                _ = files[i].content?.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            }
            files = []

            // 4. Write .occ file
            let occID = UUID().uuidString.components(separatedBy: "-").last ?? "shared"
            let occURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(occID).occ")
            try occData.writeProtected(to: occURL)

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
        Self.excludeStoreFromBackup(url: self.storeURL)
    }

    /// Marks the SQLite store and its WAL/SHM sidecars as excluded from iTunes/Finder backup.
    /// Prevents lockout-counter reset via backup-restore-to-same-device attack.
    /// Called at init and on every reapplyFileProtection (sidecar files may be recreated by SQLite).
    static func excludeStoreFromBackup(url: URL) {
        for suffix in ["", "-wal", "-shm"] {
            var sidecar = URL(fileURLWithPath: url.path + suffix)
            var rv = URLResourceValues()
            rv.isExcludedFromBackup = true
            try? sidecar.setResourceValues(rv)
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

// MARK: - Tabs

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
