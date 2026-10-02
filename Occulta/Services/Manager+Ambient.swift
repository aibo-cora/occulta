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
    }
}
