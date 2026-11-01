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
import OccultaFormats

// TODO: We don't have the Rotate Key option available right now. However, if it becomes available, we need to consider an edge case where we rotate a key and include a new ID as the message owner, but the recipient would not have this ID on record. We would need to keep track of all our past and current IDs and include them in the message for look up.

@main
struct OccultaApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    @State private var contactManager: ContactManager
    @State private var identityChallenge: IdentityChallenge.Coordinator
    @State private var vaultManager: VaultManager
    @State private var shardCustodyManager: ShardCustodyManager
    @State private var security: Manager.Security
    @State private var appManager: Manager.App

    var sharedModelContainer: ModelContainer
    /// SwiftData store URL. Retained so `reapplyFileProtection()` can stamp
    /// fresh -wal/-shm files that SQLite creates after the initial attributes call.
    private let storeURL: URL
    /// The app, or the storage error of a blocked launch (Bug 171, Stage 2c).
    private let launchScreen: LaunchScreen

    /// Every persisted model. Extracted from `init()` as its own static property rather than
    /// left inline, so it can be read (not just constructed) from outside `init()` — load-bearing
    /// by construction: the app cannot launch without it, so a new model cannot be added to the
    /// store without appearing here.
    static let schema = Schema([
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
        // Retired, kept permanently, migration-only — see ReconstructShard+Model.swift's
        // own header for why this can't just be deleted like the BEK array's old type was.
        ReconstructShard.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self,
        PotentiallyLostShard.self,
        GlobalShardConfig.self,
        BackupEncryptionKey.self,
        AppLayerConfig.self,
        Group.self,
        Vault.self,
        PendingShamirSecretRestore.self,
    ])

    init() {
        let schema = Self.schema

        // A test host skips the launch sequence below, so its process stays on the legacy keys, which a store the sequence
        // has resealed doesn't open (Bug 191). It is never given the real store: it gets an empty one in memory, as a
        // blocked launch does.
        #if DEBUG
        let hostsTests = NSClassFromString("XCTestCase") != nil
        #else
        let hostsTests = false
        #endif

        let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: hostsTests, cloudKitDatabase: .none)
        let realContainer: ModelContainer
        do {
            realContainer = try ModelContainer(for: schema, configurations: [modelConfiguration])
        } catch {
            fatalError("Could not create ModelContainer: \(error)")
        }
        // The file-level calls below (attributes, pragma, checkpoint) open the path they are given and never create it, so
        // a test host points them at a file that doesn't exist rather than at the real store.
        let url = hostsTests
            ? FileManager.default.temporaryDirectory.appendingPathComponent("occulta-test-host.store")
            : modelConfiguration.url
        let attrs: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
        
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path)
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path + "-wal")
        try? FileManager.default.setAttributes(attrs, ofItemAtPath: url.path + "-shm")
        
        RootView.excludeStoreFromBackup(url: url)

        self.storeURL = url
        Self.applySecureDeletePragma(at: url)
        Self.walCheckpoint(at: url)

        // The key reseal and the migration passes (Bug 171, Stage 2), before anything reads the store or derives a key:
        // `Manager.Security.init` reads `persistedDepth` and `pinEnabledPerDepth`, and has to read them under the key
        // they are sealed under. The sequence also tells the process which keys tier U's accessors return.
        //
        // Not in a test host (`#if DEBUG` above): tests run in this process, and the sequence would decide its keys from
        // the Simulator's real store, which keeps an epoch from run to run. The tests that bind no key manager of their
        // own expect the default, the legacy keys. The sequence has its own tests.
        var launch: LaunchSequence.Report?
        if !hostsTests {
            launch = LaunchSequence.run(context: ModelContext(realContainer), locations: .production(store: url), staging: ShareStagingKeyManager())
        }
        let screen = launch?.screen ?? .app

        // A blocked launch (a reseal that stopped partway, Stage 2c) builds everything below over an empty in-memory
        // store, with Secure Mode off, so that nothing it constructs can read, write or create a key. `RootView` shows
        // the storage error and goes no further.
        let sharedModelContainer: ModelContainer
        do {
            sharedModelContainer = try launch?.container(real: realContainer) ?? realContainer
        } catch {
            fatalError("Could not create ModelContainer: \(error)")
        }

        let security = Manager.Security(modelContainer: sharedModelContainer,
                                        storeURL: url,
                                        enabled: FeatureFlags.isEnabled(.secureMode) && screen == .app)

        self.security = security

        let contactManager = ContactManager(modelContainer: sharedModelContainer, security: security)
        let vaultManager   = VaultManager(modelContainer: sharedModelContainer)

        self.sharedModelContainer = sharedModelContainer
        self.launchScreen         = screen
        self.contactManager       = contactManager
        self.identityChallenge    = IdentityChallenge.Coordinator(ledger: contactManager, sealer: contactManager)
        self.vaultManager         = vaultManager
        self.appManager          = Manager.App(contacts: contactManager, vault: vaultManager)
        self.shardCustodyManager = ShardCustodyManager(modelContainer: sharedModelContainer, keyManager: Manager.Key())

        FileManager.default.clearTemporaryDirectory()
    }

    var body: some Scene {
        WindowGroup {
            RootView(storeURL: self.storeURL, launchScreen: self.launchScreen)
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

    static func walCheckpoint(at url: URL) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else { return }
        defer { sqlite3_close(db) }
        sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", nil, nil, nil)
    }
}

// MARK: - Root View

struct RootView: View {

    let storeURL: URL
    let launchScreen: LaunchScreen

    @EnvironmentObject private var appScreen: AppScreen
    @Environment(Manager.Security.self) private var security
    @Environment(ContactManager.self) private var contactManager
    @Environment(IdentityChallenge.Coordinator.self) private var identityChallenge
    @Environment(VaultManager.self) private var vaultManager
    @Environment(ShardCustodyManager.self) private var shardCustodyManager

    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false
    /// Last release notes the user acknowledged. Persisted, not `@State`, so `WhatsNew` stays a
    /// function of state that is the same at every depth and there is nothing for `endSession()`
    /// to clear.
    @AppStorage(WhatsNew.lastSeenKey) private var whatsNewLastSeen = ""
    @Environment(\.scenePhase) private var scenePhase

    /// Container with plaintext message or file.
    @State private var openedFileContents: OwnedBasket?
    /// A raw encrypted `.occ` queued while the app is locked: its mapped bytes, or for a streamed bundle the
    /// open file, unlinked already and readable only through the handle. Held without any processing until a
    /// PIN unlocks the app.
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
    @State private var pendingFileData: InboundFile?
    // Error feedback
    @State private var showError = false
    @State private var errorMessage = ""
    // Session state (`bugs.md` Bug 140). Everything below that a session creates, and the
    // identity challenge's presentations, is cleared by `endSession()` when the session ends:
    // on leaving `.unlocked`, and on an in-place depth change (`Manager.Security.sessionID`).
    // Exempt on purpose, because it is input queued before anyone authenticated and is
    // delivered after whichever PIN is entered, the same at every depth: `pendingFileData`,
    // `pendingShareSession`, and a `.occbak` staged while `.pinRequired` (staged after the
    // reset, so it reaches the prompt). New state goes in one list or the other.

    /// Which tab is showing. Held here, above the unlocked tree keyed by the session, so a
    /// depth change in Settings doesn't drop the user on the first tab; not sensitive.
    @State private var selectedTab: Tabs = .contacts
    /// Advanced by `endSession()`. Work that outlives a suspension compares it before
    /// presenting, so a result finishing after the session ended is dropped (Bug 148).
    @State private var sessionEpoch = 0
    /// A `.occbak` held in memory until the user confirms or cancels. Never written to disk.
    @State private var pendingRestoreFile: Data?
    @State private var showRestoreConfirmation = false
    @State private var showNothingRestored = false
    /// Encrypted `.occ` file ready for sharing via UIActivityViewController.
    @State private var shareResult: ShareResult?
    /// A share-extension session staged in the App Group, waiting for the user to pick who it
    /// gets encrypted for.
    ///
    /// Queued intent, not a presentation: it is set straight from `onOpenURL` at any phase and
    /// is deliberately **not** cleared when the app re-locks, so a share that arrives while the
    /// PIN gate is up presents its picker once the PIN is answered. Nothing is decrypted and no
    /// key material moves until a recipient is chosen — which is the whole of Bug 84 Part A.
    @State private var pendingShareSession: PendingShareSession?
    /// An introduction card that arrived as a file, waiting in the import sheet. Session state: cleared by
    /// `endSession()`, unlike `pendingFileData`, which is the raw bytes queued before anyone authenticated.
    @State private var cardImport: CardImportData?
    /// Set when an import asks to open a contact; `ContactsV2` consumes it.
    @State private var contactOpenRequest: ContactOpenRequest?

    // MARK: Body

    @ViewBuilder
    var body: some View {
        switch self.launchScreen {
        case .storageError:
            // Before the PIN flow, and without any of what the app view below does at launch: none of its tasks,
            // handlers or observers is attached to this.
            StorageErrorView()
        case .app:
            self.appBody
        }
    }

    private var appBody: some View {
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
                self.sweepPrekeysIfUnlocked()
                self.identityChallenge.sweepExpired()

                // Unconditional, at every depth and on every launch, and deliberately not
                // folded into the purge above: a checkpoint that fired only at depth 0 would
                // make checkpoint timing itself a depth signal — the failure
                // `checkpointStore()`'s own documentation exists to prevent.
                self.security.checkpointStore()
            }
            // onOpenURL must be on the outermost container so it fires in all phases.
            .onOpenURL { url in self.handleOpenURL(url) }
            // Drain any file queued while locked when the app unlocks (PIN entry or
            // grace-period auto-unlock). Processes identically regardless of which PIN
            // succeeded — passSecurityControl's removal (Non-Safe-Sender-Rejection-Is-A-
            // Duress-Detection-Oracle.md) means there's no restriction-gated rejection
            // left to differ on, so a duress unlock draining this the same way as a
            // normal one introduces no new signal.
            .onChange(of: self.appScreen.phase) { oldPhase, newPhase in
                guard newPhase == .unlocked else {
                    // Leaving .unlocked (grace expired on a warm return) tears down the
                    // branch that owns the presentations, dismissing anything on screen.
                    // Their item state outlives the branch, so end the session here —
                    // otherwise the next unlock, at whatever depth, re-presents what this
                    // session left behind (Bug 140). Only when actually leaving it: a cold
                    // launch goes .covered → .pinRequired with no session to end, and may
                    // already have staged the file that launched the app.
                    if oldPhase == .unlocked { self.endSession() }
                    return
                }
                // `applyVerifyState` sets `currentDepth` before `pinDidSucceed()` flips the
                // phase (PINEntry.swift:253), so the depth read here is the authenticated one.
                self.purgeOrphanedGroupsIfAtRealDepth()
                self.sweepPrekeysIfUnlocked()
                self.identityChallenge.sweepExpired()

                // Flushes the purge's and the sweep's delete records out of the WAL (`secure_delete` zeroes
                // them on the way), and runs on **every** unlock at every depth even though
                // only a depth-0 unlock can purge groups — a checkpoint that followed
                // the deletion would otherwise announce it.
                self.security.checkpointStore()
                if let file = self.pendingFileData {
                    self.pendingFileData = nil
                    Task { await self.processInboundFile(file) }
                }
            }
            // A depth change while unlocked (`deactivateSecureMode` from Settings) has no PIN
            // screen to tear anything down; the unlocked tree is rebuilt by its `.id`, and the
            // state held here ends too (Bug 140).
            .onChange(of: self.security.sessionID) {
                self.endSession()
            }
            .onChange(of: self.scenePhase) { _, newPhase in
                switch newPhase {
                case .active:
                    self.contactManager.cleanupPendingSessions()
                    self.identityChallenge.sweepExpired()
                case .background:
                    // Every file delivered to the app has been read by now (Bug 101).
                    FileManager.default.clearInboxes()
                default:
                    break
                }
            }
            // Key-rotation → two-sided response:
            // Alice's path: re-send this depth's backup-key pieces (Bug 141). Other depths
            // notice at their own unlock, from the trustee's next manifest.
            // Bob's path: mismatch-fingerprint shards are returned via .handback on
            // the next outbound bundle (detected at build time, no scheduling needed).
            .onReceive(self.contactManager.contactKeyRotated) { identifier in
                self.reconcileBackupPieces(keyChangedFor: identifier)
            }
            // A deleted trustee's piece shows as lost at once (Bug 144).
            .onReceive(self.contactManager.contactDeleted) { _ in
                self.reconcileBackupPieces()
            }
            // A depth's backup-key pieces are checked when its vault unlocks (Bug 141).
            .onChange(of: self.vaultManager.isUnlocked) { _, isUnlocked in
                if isUnlocked { self.reconcileBackupPieces() }
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
                onAuthenticated: { _ in self.appScreen.pinDidSucceed() },
                onDuress:        { self.appScreen.pinDidSucceed() }
            )
            .environment(self.security)
            // pinViewAppeared() is called here (not inside PINEntry) so the UIKit
            // cover is removed as soon as PINEntry is on screen.
            .onAppear { self.appScreen.pinViewAppeared() }
        case .unlocked:
            SwiftUI.Group {
                if !self.hasCompleted {
                    OnboardingView()
                        // A fresh install has nothing new to read. Stamping here, not when
                        // onboarding finishes, keeps it from looking like an update afterwards.
                        .onAppear { self.whatsNewLastSeen = Bundle.main.appVersion }
                } else if let release = WhatsNew.release(for: Bundle.main.appVersion, lastSeen: self.whatsNewLastSeen) {
                    // In the tree, like onboarding, and not a `.sheet`: a file, share or challenge
                    // sheet can present at the moment of unlock, and a second modal would be
                    // dropped, losing whatever it carried. Those present over this instead.
                    WhatsNewView(release: release) {
                        self.whatsNewLastSeen = release.version
                    }
                } else {
                    self.tabContent
                }
            }
            // Every modal presentation lives here, inside the .unlocked branch, and not on
            // the outer view. A `.sheet` or `.alert` attached above this switch attaches to
            // the same host as PINEntry, and a UIKit modal renders over it — which is how
            // Bug 1's "messages visible over the PIN lock" came back as Bug 84 Part B once
            // `8b95ee5` replaced the fullScreenCover with this in-tree branch. Do not move
            // these back out, and do not reintroduce the cover: its async presentation
            // window is what caused Bug 56.
            .alert("Error", isPresented: self.$showError) {
                Button("OK") { }
            } message: {
                Text(self.errorMessage)
            }
            // Wording is load-bearing two ways. It names no mechanism — "trustees" and
            // "shards" would tell whoever raised this prompt that a distributed-secret scheme
            // exists and that other people hold pieces, which is a lead a coercer does not
            // otherwise get from this screen. And it leads with the consequence rather than the
            // process, because the risk is that an unrequested file plants someone else's
            // entries and hands its author a key to every future backup. Tapping Accept
            // restores now if enough pieces have arrived; otherwise nothing is kept, and the
            // file can be opened again later.
            .alert("Restore from this backup?", isPresented: self.$showRestoreConfirmation) {
                Button("Cancel", role: .cancel) { self.pendingRestoreFile = nil }
                Button("Accept", role: .destructive) { self.restoreConfirmedFile() }
            } message: {
                Text("""
                    This adds the contents of this file to your vault if enough recovery pieces \
                    have arrived. If nothing changes, open it again later. Only continue if you \
                    requested it.
                    """)
            }
            .alert("Nothing was restored", isPresented: self.$showNothingRestored) {
                Button("OK") { }
            } message: {
                Text(VaultRestoreView.nothingRestoredMessage)
            }
            .sheet(item: self.$openedFileContents) {
                /// Dismiss
            } content: { data in
                let manager = self.contactManager.receivedAttachmentKey(for: data.owner)
                    .map { AttachmentManager(contactKey: $0) }
                // Messages on Bob's card get W-08 around them, the same at every depth; any other sender's don't.
                CardFirstMessageFrame(owner: data.owner) {
                    ComposableMessage.Conversation(
                        mode: .read(messageOwner: data.owner),
                        messages: .constant(data.receive?.files ?? data.basket.files),
                        attachmentManager: manager,
                        incomingIDs: data.receive?.incoming ?? [],
                        receiveFailed: data.receive?.failed ?? false
                    )
                }
                .onDisappear {
                    // Stops pass 2 if it is running, and deletes what it wrote (STREAMING_SPEC §5.3).
                    data.receive?.cancel()
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
            // Recipient choice for a staged share-extension session. Reachable only from
            // here, which is why it cannot run before the PIN.
            .sheet(item: self.$pendingShareSession) { session in
                ShareSessionEntry(sessionID: session.id) { recipient in
                    self.pendingShareSession = nil
                    self.encryptShareSession(session.id, to: recipient)
                } onCancel: {
                    self.pendingShareSession = nil
                    if let container = ShareSession.sharedContainer {
                        ShareSession.delete(id: session.id, in: container)
                    }
                } onCardFinished: { request in
                    self.pendingShareSession = nil
                    self.finishCardImport(request)
                }
                .environment(self.security)
            }
            // An introduction card that arrived as a file.
            .sheet(item: self.$cardImport) { card in
                CardImportSheet(data: card.data) { request in
                    self.cardImport = nil
                    self.finishCardImport(request)
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
            // One unlocked tree per session: an in-place depth change rebuilds it, dropping
            // every pushed screen, sheet and cached `@State` from the old depth (Bug 140).
            .id(self.security.sessionID)
        }
    }

    /// After the import sheet: opens the contact it asked for, in the Contacts tab.
    private func finishCardImport(_ request: ContactOpenRequest?) {
        guard let request else { return }
        self.selectedTab         = .contacts
        self.contactOpenRequest  = request
    }

    /// Ends the session's state held above the unlocked tree (`bugs.md` Bug 140): what this
    /// session presented or staged, and the vault's unlocked session, so a new depth needs its
    /// own Face ID. Queued pre-authentication input is left alone (see the list above).
    /// Reconcile the current depth's backup-key pieces with what trustees have reported,
    /// re-sending any a trustee no longer has (`ShardCustodyManager.reconcileBackupPieces`,
    /// `bugs.md` Bug 141). No-op while the vault is locked.
    private func reconcileBackupPieces(keyChangedFor contact: String? = nil) {
        let liveContacts = Set(((try? self.contactManager.fetchAllContacts()) ?? []).map(\.identifier))
        self.shardCustodyManager.reconcileBackupPieces(
            currentDepth:   self.security.currentDepth,
            keyChangedFor:  contact,
            liveContacts:   liveContacts,
            vaultManager:   self.vaultManager
        )
    }

    private func endSession() {
        self.sessionEpoch           += 1
        // A message still decrypting its attachments stops, and its files are deleted (STREAMING_SPEC §5.3).
        self.openedFileContents?.receive?.cancel()
        self.openedFileContents      = nil
        self.shareResult             = nil
        self.pendingRestoreFile      = nil
        self.showRestoreConfirmation = false
        self.showNothingRestored     = false
        self.showError               = false
        self.identityChallenge.outboundShare       = nil
        self.identityChallenge.incomingChallenge   = nil
        self.identityChallenge.verificationOutcome = nil
        self.cardImport              = nil
        self.contactOpenRequest      = nil
        self.vaultManager.lock()
    }

    // MARK: Tab content

    @ViewBuilder
    private var tabContent: some View {
        TabView(selection: self.$selectedTab) {
            ContactsV2(openRequest: self.$contactOpenRequest)
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
                // Queue only. The extension has staged encrypted files and a manifest that
                // no longer names a recipient; nothing here reads them. The picker sheet is
                // attached to the .unlocked branch, so a session arriving at the PIN gate
                // waits there instead of running the outbound pipeline pre-authentication
                // (Bug 84 Part A).
                self.pendingShareSession = PendingShareSession(id: sessionID)
                return

            default:
                return  // unknown host — ignore silently
            }
        } else {
            fileLocation = url
        }

        Task {
            // Also delete the copy iOS makes in our own container for "Open in Occulta"
            // (Bug 101). An original opened in place from Files lies outside it and is kept.
            // Safe after reading: the bytes are memory-mapped, and unlinking a mapped file
            // leaves the mapping valid.
            defer {
                if openedThroughShareExtension || FileManager.default.isInsideAppContainer(fileLocation) {
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
                //
                // A streamed bundle (wire version 0x0A) is opened as a read handle instead and never mapped
                // (STREAMING_SPEC §5.1): it is read a chunk at a time, so it need not fit in memory.
                let inbound = try await Task.detached(priority: .userInitiated) {
                    try InboundFile.open(fileLocation)
                }.value

                // Bug 101 for a streamed bundle: the copy iOS made in our container is unlinked as soon as the
                // handle is open, and the open handle keeps it readable. The `defer` above covers everything else.
                if case .streamed = inbound,
                   openedThroughShareExtension || FileManager.default.isInsideAppContainer(fileLocation) {
                    try? FileManager.default.removeItem(at: fileLocation)
                }

                // .occbak — vault backup restore file. Opening one only stages it in memory;
                // the restore happens in `restoreConfirmedFile`, behind the confirmation below.
                if fileLocation.pathExtension == "occbak", case .mapped(let data) = inbound {
                    // Confirm before restoring. A layer with no backup key of its own will
                    // reconstruct whatever key the file's shards rebuild and import its entries,
                    // and nothing in the file authenticates who authored it.
                    //
                    // At every depth. The prompt is raised before `restoreBackup` runs, so it
                    // cannot vary with the outcome — identical text, identical buttons, whatever
                    // the file turns out to be. Showing it only at depth 0 would be the leak: its
                    // *absence* would tell whoever is holding the phone that they are in a duress
                    // layer.
                    self.pendingRestoreFile = data
                    self.showRestoreConfirmation = true
                    return
                }

                // Secure Mode gate: if the app is locked, queue raw bytes without any
                // processing. Both unlock paths then drain it identically — see
                // `pendingFileData`; a duress unlock no longer discards it.
                if self.appScreen.phase != .unlocked {
                    self.pendingFileData = inbound
                    return
                }

                await self.processInboundFile(inbound)
            } catch {
                self.errorMessage = "There was an error. \(error.localizedDescription)"
                self.showError = true
            }
        }
    }

    /// Restores from the confirmed `.occbak`: one attempt, at the current depth, against the
    /// shards already banked (`RECOVERY_BUFFER_LAYERING.md` §9.4).
    ///
    /// The vault is usually locked here — it locks whenever the app goes to the background,
    /// which opening a file from Files does — so this asks for Face ID first, the same prompt
    /// the Vault tab uses. The prompt depends only on the vault's lock state, never on depth.
    /// Cancelling it does nothing, like any failed attempt.
    private func restoreConfirmedFile() {
        guard let pending = self.pendingRestoreFile else { return }
        self.pendingRestoreFile = nil

        self.vaultManager.whenUnlocked { self.restoreBackup(from: pending) }
    }

    /// A successful import is visible where it happened: the entries appear, and the vault tab
    /// shows the post-restore prompt. **Every failure shows the same message at every depth**,
    /// whatever the cause — this depth already has a backup key, too few pieces, no match — so
    /// it never reveals which one happened. The acknowledgment removed for Bug 93 was unsafe
    /// because depth 0 checked its own backup key while duress couldn't; every depth now checks
    /// its own state (`RECOVERY_BUFFER_LAYERING.md` §4 row 6).
    ///
    /// A malformed file still reports an error at every depth. That branch turns on the file's
    /// own bytes, not on vault state or depth, so it distinguishes nothing about the session.
    ///
    /// Depth is read once, so the visible-contact set and the restore depth always agree.
    private func restoreBackup(from data: Data) {
        let depth = self.security.currentDepth
        do {
            let imported = try self.vaultManager.restoreBackup(
                from: data, currentDepth: depth,
                visibleContactIdentifiers: self.contactManager.visibleContactIdentifiers(atDepth: depth)
            )
            if !imported { self.showNothingRestored = true }
        } catch {
            self.errorMessage = "There was an error. \(error.localizedDescription)"
            self.showError = true
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
    ///
    /// Nothing is presented, basket or error, if the session ended while the file was being
    /// decrypted (Bug 148): `endSession()` has already run, so a result set now would
    /// survive into the next session, after whichever PIN is entered. The result is dropped
    /// rather than the bytes re-queued: a forward-secret bundle's prekey is spent by now, so a
    /// second attempt would only fail. Reachable only if the app is backgrounded past the grace
    /// period mid-decryption; `AppScreen.lockIfGracePeriodExpired` closes the common case. Losing
    /// the message then is an accepted cost (`Docs/General/decisions.md`).
    private func processInboundFile(_ file: InboundFile) async {
        let epoch = self.sessionEpoch
        let result: Result<OwnedBasket?, Error>
        switch file {
        case .mapped(let data):
            // An introduction card goes to the import sheet, before any bundle decoding (SPEC §2). A card is exactly
            // 1,768 bytes with a valid signature, which no bundle is, and a mismatch costs one length check.
            if IntroductionCard.recognize(data) != nil {
                guard self.appScreen.phase == .unlocked else { return }
                self.cardImport = CardImportData(data: data)
                return
            }
            do {
                result = .success(try await self.buildOwnedBasket(from: data))
            } catch {
                result = .failure(error)
            }
        case .streamed(let reader):
            do {
                result = .success(try await self.buildStreamedMessage(from: reader))
            } catch {
                result = .failure(error)
            }
        }

        guard self.appScreen.phase == .unlocked, self.sessionEpoch == epoch else {
            // Nothing is shown, so nothing will read the attachments: release the file and write none.
            if case .success(let basket?) = result { basket.receive?.cancel() }
            return
        }

        do {
            if let ownedBasket = try result.get() {
                self.openedFileContents = ownedBasket
                // The message is on screen; now its attachments (STREAMING_SPEC §5.2 step 8).
                ownedBasket.receive?.start()
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
        // Names no contact and no depth, and says the same at every depth (STREAMING_SPEC §7).
        } catch OccultaBundle.BundleError.tooLargeForDevice {
            self.errorMessage = "This message is too large to open on this iPhone."
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
        // **The advice lives inside the single string (restored 2026-08-16).**
        //
        // Bug 81 argued for splitting the strings so the UI could say "ask this contact to
        // update" — actionable, and describing the overwhelmingly likely cause of a refusal: a
        // contact still on 1.9.x rather than an attack. The collapse took that advice out along
        // with the oracle, and the cost was real — every benign old-contact refusal read as a
        // security event. Alarm fatigue is the mild version; the sharp version is a user coming
        // to distrust a contact who did nothing wrong and withdrawing from a channel that was
        // safe.
        //
        // The leak was the two cases producing *different* text, not the mention of updates. One
        // string carries both meanings, so the advice returns without reopening anything: the
        // sentence below is emitted identically whether the marker was unreadable or the
        // signature was simply absent, and an observer learns nothing from seeing it.
        //
        // It is deliberately diagnostic rather than explanatory. Followed in the benign case it
        // ends the problem — one message from that contact once they are on 1.10.0+ repairs the
        // marker permanently. Followed against a forgery it returns "I'm already on the latest
        // version", which is information the user did not have, arriving without the app having
        // accused anyone. Both suggested actions work against a 1.9.x contact, since the
        // identity challenge rides on `.v3fs`/`.longTermFallback`.
        //
        // The group-eligibility screen carries the same advice for exactly these contacts, which
        // is where a user goes when they want to know why someone is unreachable.
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
        //
        // The body-digest refusals (`bugs.md` Bug 165) share it too: each says the same thing, that the
        // message can't be tied to this contact, and a separate string would only add a third to tell apart.
        } catch GroupDecryptError.senderSignatureCapabilityUnknown,
                GroupDecryptError.missingSenderEphemeralSignature,
                GroupDecryptError.bodyDigestMismatch,
                GroupDecryptError.missingBodyDigest {
            self.errorMessage = "Occulta couldn't confirm this message came from this contact, so it wasn't opened. They may be using an older version — ask them to update, or verify them another way."
            self.showError = true
        // A bundle whose structure or chunks don't hold together. One string for every way that can happen:
        // none of them depends on the depth, and none is worth telling apart to whoever holds the phone.
        } catch OccultaBundle.BundleError.malformedBundle, is BodyStream.StreamError {
            self.errorMessage = "This message couldn't be opened."
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
              let key = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey()
        else { return }

        try? self.contactManager.purgeUnreadableGroups(using: key)
    }

    /// Deletes prekeys past their grace period (D1, Bug 156), for the contacts visible at the authenticated depth.
    /// Gated on the phase for the reason `purgeOrphanedGroupsIfAtRealDepth()` gives; runs at every depth.
    private func sweepPrekeysIfUnlocked() {
        guard self.appScreen.phase == .unlocked else { return }
        // The launch pass again, which does nothing once it has succeeded. A launch while the local DB key was
        // unavailable, such as in the background before the first unlock, leaves rows it has yet to convert.
        try? DatabaseMigration.migratePrekeyRecords(modelContext: self.contactManager.modelContext)
        try? DatabaseMigration.migrateCardFields(modelContext: self.contactManager.modelContext)
        try? DatabaseMigration.migrateChallengeFields(modelContext: self.contactManager.modelContext)
        try? self.contactManager.sweepPrekeys(visibleAtDepth: self.security.currentDepth)
        // Introduction cards (SPEC §6.4): every contact at every depth, unlike the prekey sweep above.
        try? self.contactManager.sweepCards()
    }

    /// Stage 3 (RECOVERY_BUFFER_LAYERING.md §2.1): drop every shard op — `.distribute`,
    /// `.replace`, `.handback` alike — from a sender not visible at the current depth,
    /// before any of them reach `ShardCustodyManager`. Safe for all three kinds: each one
    /// already retries automatically if dropped, so nothing is lost, only delayed until
    /// the sender is visible again — `.handback` via `mismatchHandbackOps` (retried on
    /// the trustee's every subsequent bundle), `.distribute`/`.replace` via
    /// `PendingShardDistribute`, which persists until the trustee's own `custodyManifest`
    /// confirms receipt (`queueDistribute`'s own doc comment, confirmed directly against
    /// `processInboundManifest` — the row is not deleted on send).
    ///
    /// Fails closed: an unresolvable sender or an unavailable local DB key is treated as
    /// not visible, so an ambiguous case drops the ops rather than processing them.
    ///
    /// Not unit-testable in isolation — constructing an `OccultaApp` instance builds a
    /// real, on-disk `ModelContainer` and runs live migrations, so this is verified by
    /// manual/integration checks instead, the same limitation already true of the
    /// visibility resolution this folds in.
    private func filterShardOperations(
        _ ops: [OccultaBundle.ShardOperation]?,
        from senderIdentifier: String
    ) -> [OccultaBundle.ShardOperation]? {
        guard
            let sender   = try? self.contactManager.fetchContact(by: senderIdentifier),
            let localKey = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey(),
            sender.isVisible(atDepth: self.security.currentDepth, usingKey: localKey)
        else { return nil }
        return ops
    }

    /// What a group bundle's manifest asks of the app before any basket is shown: an identity challenge goes
    /// to its coordinator, shard and custody operations to the shard manager. Returns the message bytes, or nil
    /// when there is nothing to show (a challenge, or a shard-only bundle, whose message is empty).
    ///
    /// The same for both layouts: it sees only the opened manifest.
    private func routeGroupOpening(_ opened: ContactManager.GroupOpening) -> Data? {
        let (sealed, ownerID) = (opened.sealed, opened.ownerID)

        // Identity-challenge traffic inside a group bundle, already authenticated by `openGroup`
        // (prekey continuity §3.4). It sets `challenge` whenever the body carries one.
        if let challenge = opened.challenge {
            if let sender = try? self.contactManager.fetchContact(by: ownerID) {
                _ = self.identityChallenge.handleAuthenticatedChallenge(challenge, sender: sender)
            }
            return nil
        }

        // Shard/custody ops. Per-recipient fields take priority; falling back
        // to the shared sealed payload's own fields keeps the already-shipped
        // 1:1-via-group-envelope shard path (single-recipient encryptBundle,
        // which has no per-recipient content to pad) working unchanged.
        if let senderPublicKey = try? self.contactManager.currentPublicKey(forIdentifier: ownerID) {
            _ = self.shardCustodyManager.handleInbound(
                shardOperations:  self.filterShardOperations(
                    opened.recipientShardOperations ?? sealed.shardOperations,
                    from: ownerID
                ),
                custodyManifest:  opened.recipientCustodyManifest ?? sealed.custodyManifest,
                senderPublicKey:  senderPublicKey,
                senderIdentifier: ownerID,
                vaultManager:     self.vaultManager
            )
            // Only a manifest can change a piece's status.
            if (opened.recipientCustodyManifest ?? sealed.custodyManifest) != nil { self.reconcileBackupPieces() }
        }

        // Shard-only bundle (empty message) — ops handled above, no basket.
        return sealed.message.isEmpty ? nil : sealed.message
    }

    /// The streamed layout (`STREAMING_SPEC.md` §5.2), steps 1 to 7: open the manifest and return the message
    /// with a placeholder for each streamed file. The attachments are not decrypted yet; `StreamedReceive.start`
    /// does that, once the message is on screen.
    ///
    /// Nothing here depends on the depth, and a failure before step 5 has recorded no prekey as used.
    private func buildStreamedMessage(from reader: NoCacheFile.Reader) async throws -> OwnedBasket? {
        // 1–6. Parse, identify the sender, open our slot, check the digest and the header, open the manifest,
        // and run every check `openGroup` runs on it.
        let (body, opened) = try await self.contactManager.openStreamedBundle(reader)

        guard let message = self.routeGroupOpening(opened) else { return nil }

        // 7. The message: the inline files, and a placeholder for each streamed one.
        let receive = try StreamedReceive.prepare(
            message: message, opened: opened, body: body,
            key: self.contactManager.receivedAttachmentKey(for: opened.ownerID)
        )
        return OwnedBasket(basket: receive.basket, owner: opened.ownerID, receive: receive)
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
        // Before the bundle is decoded, a key derived or a prekey touched: every layout still opens in
        // memory, and a refusal must change nothing. The file's length bounds the body's (STREAMING_SPEC §7).
        try MemoryGuard.system.checkReceive(bundleLength: fileContents.count)

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
                let opened = try self.contactManager.openGroup(bundle: bundle, body: .inline(bundle), ownerID: knownOwnerID)
                decodedBundleVersion = bundle.version

                guard let message = self.routeGroupOpening(opened) else { return nil }
                decrypted = (message, opened.ownerID)
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
                #endif

                // Handle shard operations and manifest reconciliation.

                if let senderPublicKey = try? self.contactManager.currentPublicKey(forIdentifier: ownerID) {
                    _ = self.shardCustodyManager.handleInbound(
                        shardOperations:  self.filterShardOperations(
                            sealed.shardOperations,
                            from: ownerID
                        ),
                        custodyManifest:  sealed.custodyManifest,
                        senderPublicKey:  senderPublicKey,
                        senderIdentifier: ownerID,
                        vaultManager:     self.vaultManager
                    )
                    // Only a manifest can change a piece's status.
                    if sealed.custodyManifest != nil { self.reconcileBackupPieces() }
                }

                decodedBundleVersion = bundle.version
                decrypted = (sealed.message, ownerID)
            }
        case .unsupported:
            throw OccultaBundle.BundleError.unsupportedVersion
        case .streamedBodyCapable:
            // A streamed bundle is opened through its file handle (`buildStreamedMessage`), never from bytes in memory.
            throw OccultaBundle.BundleError.malformedBundle
        default:
            // Legacy path — nil, v1, v2, or pre-versioned files.
            // Falls back to long-term ECDH trial decryption across all contacts.
            decrypted = try self.contactManager.decrypt(data: fileContents)
        }

        let basket: Basket
        if decodedBundleVersion == .v4 {
            basket = try WireHandle.decode(basket: decrypted.plaintext)
        } else {
            basket = try BoundedJSON.decode(Basket.self, from: decrypted.plaintext)
        }

        // ── Write file attachments, photos, videos to temp directory ─────────────────

        return try await self.contactManager.sealReceivedFiles(of: basket, owner: decrypted.ownerID)
    }

    // MARK: Share Extension Processing

    /// Encrypt a staged share session for the recipient the user just picked, and present the
    /// result for transport.
    ///
    /// Runs only from `ShareRecipientPicker`'s selection callback, which is reachable only from
    /// the `.unlocked` phase. Before Bug 84 this body ran straight off `onOpenURL`, so
    /// `encryptBundle`'s prekey pop and its `modelContext.save()` committed at whatever depth the
    /// process happened to hold — depth 0 on a cold launch — with no PIN entered.
    private func encryptShareSession(_ sessionID: String, to recipient: ShareRecipientPicker.Recipient) {
        guard let container = ShareSession.sharedContainer else { return }

        // Covers the success path and every throw below. `ShareSession.load` also deletes on its
        // own failures; deleting twice is harmless, and neither caller may skip it.
        defer { ShareSession.delete(id: sessionID, in: container) }

        do {
            // Read, not decrypted: a file the extension staged as `.eatt` stays on disk and is streamed from there.
            var staged = try ShareSession.staged(
                id: sessionID, in: container, keyManager: ShareStagingKeyManager()
            )

            // Whatever is held in memory — an image, whose EXIF is stripped, or a file staged by the build before
            // this one — is zeroed on every exit from here on, the success path included, where it is dead the
            // moment the bundle is sealed.
            defer {
                for i in staged.files.indices {
                    _ = staged.files[i].content?.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                }
            }

            let basket = Basket(files: staged.files, date: Date())
            let occID  = UUID().uuidString.components(separatedBy: "-").last ?? "shared"
            let occURL = FileManager.default.temporaryDirectory.appendingPathComponent("\(occID).occ")
            // The layout is the recipient's to choose, and a file is read into memory only if it is inline,
            // under the guard (STREAMING_SPEC §3, §7).
            let output = BundleOutput.file(destination: occURL, attachments: staged.attachments, memoryGuard: .system)

            switch recipient {
            case .contact(let contactID):
                let contactPub = try? self.contactManager.currentPublicKey(forIdentifier: contactID)
                let isCard     = try self.contactManager.isCardContact(identifier: contactID)
                let shardOps   = try self.shardCustodyManager.buildShardOperations(for: contactID, currentContactPublicKey: contactPub, isCardContact: isCard)
                let custody    = try? self.shardCustodyManager.buildCustodyManifest(for: contactID, isCardContact: isCard)

                try self.contactManager.encryptBundle(
                    basket:          basket,
                    for:             contactID,
                    shardOperations: shardOps.isEmpty ? nil : shardOps,
                    custodyManifest: custody,
                    output:          output
                )

            case .group(let groupID):
                // Depth filtering of the membership is encryptGroupBundle's own — it reads
                // members(atDepth: currentDepth) and re-filters by each member's isVisible.
                try self.contactManager.encryptGroupBundle(
                    basket:              basket,
                    groupID:             groupID,
                    shardCustodyManager: self.shardCustodyManager,
                    output:              output
                )
            }

            self.shareResult = ShareResult(url: occURL)
        } catch {
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

}

// MARK: - InboundFile

/// A file handed to the app, as it is held until it is processed.
enum InboundFile {
    /// Memory-mapped bytes: every layout but the streamed one, and every other kind of file.
    case mapped(Data)
    /// A streamed bundle, open for positioned reads and never mapped (STREAMING_SPEC §5.1).
    case streamed(NoCacheFile.Reader)

    /// Opens `url`: as a read handle when it is a streamed bundle, which its first bytes say, otherwise mapped.
    ///
    /// Memory-mapped rather than eagerly read into a heap buffer: a file can legitimately be large (photo/video
    /// attachments, vault backups), and mapping lets the OS page it in lazily and reclaim pages under memory
    /// pressure instead of committing the whole file to RSS upfront (SecurityReview2026-07-24, finding #11 —
    /// unbounded inbound file read).
    nonisolated static func open(_ url: URL) throws -> InboundFile {
        if url.pathExtension != "occbak",
           let reader = try? NoCacheFile.reader(url),
           reader.size >= UInt64(WireHandle.headerLength),
           let head = try? reader.read(at: 0, count: WireHandle.headerLength), head.count == WireHandle.headerLength,
           head.prefix(WireHandle.magic.count).elementsEqual(WireHandle.magic),
           head[4] == WireHandle.streamedVersionByte {
            return .streamed(reader)
        }
        return .mapped(try Data(contentsOf: url, options: .mappedIfSafe))
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

/// A staged share-extension session awaiting a recipient. `id` is the session UUID string,
/// already validated as a UUID by `handleOpenURL` before it reaches a path component.
private struct PendingShareSession: Identifiable {
    let id: String
}

/// What a staged share session opens: the recipient picker, or the card import sheet when the one file shared
/// is an introduction card (it has no extension, so the extension can't route it). Checked here, after the PIN,
/// since reading a staged file needs the share staging key; nothing is decrypted before the session is unlocked.
private struct ShareSessionEntry: View {
    let sessionID: String
    let onSelect: (ShareRecipientPicker.Recipient) -> Void
    let onCancel: () -> Void
    let onCardFinished: (ContactOpenRequest?) -> Void

    private enum Phase {
        case checking
        case picker
        case card(Data)
    }

    @State private var phase = Phase.checking

    var body: some View {
        switch self.phase {
        case .checking:
            ProgressView()
                .task { self.check() }
        case .picker:
            ShareRecipientPicker(onSelect: self.onSelect, onCancel: self.onCancel)
        case .card(let data):
            CardImportSheet(data: data, onFinish: self.onCardFinished)
        }
    }

    private func check() {
        guard
            let container = ShareSession.sharedContainer,
            let data = ShareSession.introductionCard(id: self.sessionID, in: container, keyManager: ShareStagingKeyManager())
        else {
            self.phase = .picker
            return
        }
        // The card is held in memory now; the staged copy has no further use.
        ShareSession.delete(id: self.sessionID, in: container)
        self.phase = .card(data)
    }
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
