//
//  LaunchSequence.swift
//  Occulta
//
//  What runs at launch, in order, before any UI reads the store: the key reseal's bootstrap (Bug 171, Stage 2), the
//  key reseal itself, then the migration passes that used to live in `OccultaApp.migrate()`, in their old order.
//
//  A function of its own, taking a `ModelContext` and a key manager, so that a test can run the whole sequence on an
//  in-memory store, and so that the order is written down in one place. (Not a `static` member of `OccultaApp`: one
//  inside the `@main` struct is invisible to `@testable import`, `decisions.md`.)
//
//  Called from `OccultaApp.init()` before `Manager.Security(...)`: its init reads `persistedDepth` and
//  `pinEnabledPerDepth`, and has to read them under the key they are sealed under.
//
//  Once the reseal has run, the sequence decides which keys tier U's three accessors return for the rest of the
//  process (`Manager.Ambient.tierUKeys`): the Enclave-bound ones if the epoch exists, the legacy ones if it doesn't.
//  A pass that aborted or didn't finish therefore leaves the whole process on the legacy keys, consistent with a
//  store that is still sealed under them, and the next launch retries. The passes below then run on data they can
//  read.
//
//  After it, the PIN verifier wrap (Bug 171, Stage 3), then the process is told whether to write wrapped verifiers
//  (`Manager.Ambient.pinVerifiers`), by the sizes in the store, before `Manager.Security` reads or writes one.
//
//  Share staging's secret and PQ record (Bug 171, Stage 5) are created here too, if a `staging` manager is passed and
//  the extension hasn't made them already: after the blocked check, because a blocked launch writes nothing, and
//  independent of the store.
//
//  A pass that committed at least one batch and ended without its epoch (Stage 2c) leaves the store a mix of both keys
//  while the process is on the legacy ones. The sequence then reports `blocked` and stops: no verifier wrap, no
//  migration, and `OccultaApp` shows a storage-error screen instead of the PIN prompt and builds the rest of the app
//  over a scratch store. The next launch runs the pass again and finishes it. A pass that stopped before it wrote
//  anything is not blocked: the store is not mixed.
//

import Foundation
import SwiftData

/// What the window shows first, decided from the launch before any PIN prompt.
enum LaunchScreen: Equatable {
    case app
    /// A neutral storage error, in place of the PIN prompt (`StorageErrorView`).
    case storageError
}

enum LaunchSequence {

    /// What the first two steps did. Nothing reads it in production: the passes after them each log and carry on, as
    /// they always have. A test reads it to see an interruption or an abort.
    struct Report {
        var bootstrap: Result<KeyReseal.BootstrapReport, any Error>
        var reseal: Result<KeyReseal.Report, any Error>
        /// The PIN verifier wrap. `.notRun` if the reseal threw, which keeps it from running.
        var verifiers: Result<KeyReseal.VerifierReport, any Error> = .success(KeyReseal.VerifierReport())
        /// The tier U pass committed at least one batch and ended without the epoch, so the store is a mix of both keys
        /// (or all new, with the epoch's own save failing) while the process is on the legacy ones. Nothing after the
        /// pass ran.
        var blocked = false
        /// Whether the share-staging tier's `r_S` and PQ record exist after this launch (Stage 5). nil if no staging
        /// manager was passed, or the launch was blocked.
        var staging: Result<Void, any Error>?
    }

    /// Runs the sequence on `context`, suspending autosave for all of it, as `migrate()` always did.
    @discardableResult
    static func run(
        context: ModelContext,
        keyManager: any KeyManagerProtocol = Manager.Ambient.keyManager,
        locations: KeyReseal.Locations = .production,
        batchSize: Int = KeyReseal.defaultBatchSize,
        staging: ShareStagingKeyManager? = nil
    ) -> Report {
        // Every migration below relies on its own explicit save() being the only write it
        // makes — `migrateDepthFieldsToFixedWidth` accumulates into `didChange` and saves
        // once at the end precisely so a failure part-way leaves the original bytes for the
        // next launch. A RunLoop- or backgrounding-triggered autosave breaks that: it can
        // commit a partially-applied pass before the function decides whether to.
        //
        // Same idiom and same reason as `activateSecureMode`, `deactivateSecureMode` and
        // `Message.Draft`'s purge, all of which suspend autosave for a multi-step sequence
        // and restore it after. Doing it once here covers every migration rather than asking
        // each to defend itself.
        context.autosaveEnabled = false
        defer { context.autosaveEnabled = true }

        // Legacy and plain until the passes say otherwise; nothing derives before this returns.
        Manager.Ambient.setTierUKeys(.legacy)
        Manager.Ambient.setPINVerifiers(.plain)
        // The vault's key is decided by its own unlock (`VaultManager.unlock`), which reads the vault epoch; until then legacy.
        Manager.Ambient.setVaultKeys(.legacy)

        let bootstrap = Result { try KeyReseal.bootstrap(context: context, keyManager: keyManager) }

        // Its own context: a batch that failed is rolled back there and cannot be committed by a pass below.
        let resealContext = ModelContext(context.container)
        resealContext.autosaveEnabled = false
        // The run's report is lost if it throws, so how many batches it committed is read from here.
        let progress = KeyReseal.Progress()
        let reseal = Result {
            try KeyReseal.run(context: resealContext, keyManager: keyManager, locations: locations, batchSize: batchSize, progress: progress)
        }

        // Decided once, from the store: the epoch is the record of what the data is under.
        let epochExists = KeyReseal.epochExists(in: ModelContext(context.container))
        Manager.Ambient.setTierUKeys(epochExists ? .enclaveBound : .legacy)

        #if DEBUG
        if case .failure(let error) = bootstrap { debugPrint("Key reseal bootstrap error: \(error)") }
        if case .failure(let error) = reseal { debugPrint("Key reseal error: \(error)") }
        #endif

        // Stage 2c. Values were moved and the epoch is missing: nothing below may run, and nothing may open or write the
        // store in this launch. Not set for a pass that stopped before writing: those leave the store as it was.
        if !epochExists, progress.committedBatches > 0 {
            return Report(bootstrap: bootstrap, reseal: reseal, blocked: true)
        }

        // Share staging's secret and record (Stage 5): created here if the extension hasn't made them, or by the extension on
        // its first share if the app gets there first. Independent of the store, so it doesn't wait on the pass. A
        // failure (a locked device) costs nothing: the extension creates them on first use.
        let stagingResult = staging.map { manager in Result { try manager.createTierItemsIfAbsent() } }
        #if DEBUG
        if case .failure(let error)? = stagingResult { debugPrint("Share staging items error: \(error)") }
        #endif

        // The PIN verifiers, after the tier U pass and before `Manager.Security` reads them. Skipped if that pass threw.
        var verifiers = Result<KeyReseal.VerifierReport, any Error>.success(KeyReseal.VerifierReport())
        if case .success = reseal {
            let wrapContext = ModelContext(context.container)
            wrapContext.autosaveEnabled = false
            verifiers = Result { try KeyReseal.wrapVerifiers(context: wrapContext, keyManager: keyManager, locations: locations) }
            #if DEBUG
            if case .failure(let error) = verifiers { debugPrint("PIN verifier wrap error: \(error)") }
            #endif
        }

        // Decided once, from the store: wrapped only if every verifier is.
        Manager.Ambient.setPINVerifiers(KeyReseal.verifiersAreWrapped(in: ModelContext(context.container)) ? .wrapped : .plain)

        // A pass that threw (a failed save) may have committed some batches: the store is then a mix of both keys
        // while the process is on the legacy ones. The passes below open what they can and rewrite what they can't
        // (an unreadable prekey record starts over, a soft-deleted row's stamps are randomised), so they wait for the
        // next launch, which finishes the pass first. A kill never gets here.
        if case .failure = reseal { return Report(bootstrap: bootstrap, reseal: reseal, verifiers: verifiers, staging: stagingResult) }

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
            try DatabaseMigration.migrateRetireGlobalTrustees(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("Global Trustees retirement error: \(error)")
            #endif
        }

        do {
            try DatabaseMigration.migrateOriginDepthBackfill(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("originDepth backfill error: \(error)")
            #endif
        }

        // Must run after the three backfills above: they own the nil case, and this pass
        // deliberately leaves nil alone rather than manufacturing a value of its own.
        do {
            try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("depth field fixed-width normalisation error: \(error)")
            #endif
        }

        // After the fixed-width pass, not before: that pass converts what it can read, and
        // this one scrubs what is left on rows whose content is already erased (Bug 89).
        do {
            try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("soft-deleted depth stamp scrub error: \(error)")
            #endif
        }


        // Before the reseal of contacts per depth, whenever that ships (`migratePrekeyRecords`), and after
        // `migrateToV2`, whose rows it skips until they're converted.
        do {
            try DatabaseMigration.migratePrekeyRecords(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("prekey record migration error: \(error)")
            #endif
        }

        // Introduction cards, stage A: the card field is never nil either.
        do {
            try DatabaseMigration.migrateCardFields(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("card field migration error: \(error)")
            #endif
        }

        // Entries created before `VaultEntry.deletionToken` existed read as orphaned until
        // this runs (Bug 133). Independent of every pass above.
        do {
            try DatabaseMigration.migrateVaultEntryDeletionTokens(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("VaultEntry deletionToken backfill error: \(error)")
            #endif
        }

        do {
            try DatabaseMigration.migrateDeleteGlobalShardConfig(modelContext: context)
        } catch {
            #if DEBUG
            debugPrint("GlobalShardConfig deletion error: \(error)")
            #endif
        }

        return Report(bootstrap: bootstrap, reseal: reseal, verifiers: verifiers, staging: stagingResult)
    }
}

extension LaunchSequence.Report {

    var screen: LaunchScreen {
        self.blocked ? .storageError : .app
    }

    /// The store the rest of the app is built over. The real one, unless the launch is blocked: then an empty one in
    /// memory, so that nothing the app constructs at launch (`VaultManager` tops up its filler rows when it is built,
    /// for one) can read or write the real store, whose contents are a mix of two keys.
    func container(real: ModelContainer) throws -> ModelContainer {
        guard self.blocked else { return real }

        let schema = OccultaApp.schema
        return try ModelContainer(for: schema, configurations: ModelConfiguration(schema: schema, isStoredInMemoryOnly: true))
    }
}
