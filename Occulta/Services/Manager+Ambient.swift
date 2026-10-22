//
//  Manager+Ambient.swift
//  Occulta
//

import Foundation

extension Manager {
    /// The one key manager for keys every part of the app must agree on — above all the local
    /// DB key. A row one class seals, another opens, so they cannot each hold their own key
    /// manager: `VaultManager.Backup`'s doc comment (`Vault+Manager+Backup.swift`) explains what
    /// breaks when they do. Derive those keys through here, never through an injected
    /// `keyManager`.
    ///
    /// Release builds return `Manager.Key()`, exactly what every call site constructed before.
    /// Debug builds let a test bind a `TestKeyManager` for the duration of a task, so tests that
    /// touch these keys can run without a Secure Enclave. A task-local, not a global, because
    /// Swift Testing runs tests in parallel in one process. It follows `await`s, actor hops and
    /// `Task {}`, but not `Task.detached` or framework delegate callbacks: code reached that way
    /// gets the real key, and fails loudly where there is no Enclave.
    enum Ambient {
        #if DEBUG
        /// A test's replacement key manager, and a count of real `Manager.Key`s constructed
        /// while it was bound. Each one is a path the override did not reach: it passes on a
        /// host with an Enclave and fails on CI, so a test that means to run without an
        /// Enclave checks this is zero.
        final class Override {
            let keyManager: any KeyManagerProtocol
            private(set) var realKeyConstructions = 0

            /// This test's `tierUKeys`, in place of the process-wide one.
            var tierUKeys = TierUKeys.legacy

            init(_ keyManager: any KeyManagerProtocol) {
                self.keyManager = keyManager
            }

            func recordRealKeyConstruction() {
                self.realKeyConstructions += 1
            }
        }

        @TaskLocal static var override: Override?
        #endif

        static var keyManager: any KeyManagerProtocol {
            #if DEBUG
            if let override = Self.override { return override.keyManager }
            #endif
            return Manager.Key()
        }

        // MARK: - Which keys tier U's accessors return (Bug 171, Stage 2)

        /// Which derivation `createHybridLocalEncryptionKey()`, `deriveShardCustodyKey()` and
        /// `deriveRestoreVaultKey()` return.
        enum TierUKeys {
            /// The derivations of the releases before the fix (`legacyKey(_:)`).
            case legacy
            /// The Enclave-bound ones (`enclaveBoundKey(_:)`).
            case enclaveBound
        }

        private static var process = TierUKeys.legacy

        /// The keys tier U's three accessors return: the key the tier's epoch says the data is under.
        ///
        /// Decided once per process, by `LaunchSequence`, after the key reseal and before anything else derives, and
        /// never changed after. It is `.enclaveBound` only when `AppLayerConfig.keyEpoch` exists, so a pass that
        /// aborted or didn't finish leaves the whole process on the legacy keys, consistent with a store that is
        /// still sealed under them. The default is `.legacy`: a process that never runs the launch sequence derives
        /// what it always did. There is no retry mid-session, because a key derived before the switch could write
        /// legacy ciphertext after the epoch is set, and the pass would never see it.
        ///
        /// Process state and not a fetch per derivation: it is read on every `String.decrypt()`. A test binds its own
        /// with the key manager (`Override.tierUKeys`), for the same reason `override` is a task-local.
        static var tierUKeys: TierUKeys {
            #if DEBUG
            if let override = Self.override { return override.tierUKeys }
            #endif
            return Self.process
        }

        /// Only `LaunchSequence` (and `KeyReseal.bootstrap`, for the one row it seals) calls this.
        static func setTierUKeys(_ keys: TierUKeys) {
            #if DEBUG
            if let override = Self.override {
                override.tierUKeys = keys
                return
            }
            #endif
            Self.process = keys
        }

        /// Runs `body` with `tierUKeys` set to `keys`, and restores what it was.
        static func withTierUKeys<R>(_ keys: TierUKeys, _ body: () throws -> R) rethrows -> R {
            let previous = Self.tierUKeys
            Self.setTierUKeys(keys)
            defer { Self.setTierUKeys(previous) }
            return try body()
        }
    }
}
