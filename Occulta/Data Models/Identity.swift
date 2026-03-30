//
//  Identity+Model.swift
//  Occulta
//
//  Created by Yura on 3/18/26.
//

import Foundation
import SwiftData

// MARK: - Identity

enum Identity { }

extension Identity {

    /// The local device's cryptographic identity.
    ///
    /// There is exactly one instance of this model in the store, created on
    /// first launch and never duplicated. Access it via `IdentityManager`.
    ///
    /// Properties are grouped by feature. Add new features as new `// MARK:` sections
    /// rather than scattering unrelated fields together.
    @Model
    final class Profile {

        // MARK: - Master Key

        /// The keychain application tag used to store and retrieve the P-256
        /// identity private key in the Secure Enclave.
        ///
        /// Matches the tag passed to `SecKeyCreateRandomKey` in `Manager.Key`.
        /// Stored here so it is persisted, auditable, and not silently hardcoded.
        var masterKeyTag: String = ""

        /// Date the identity (master key) was first created.
        var identityCreatedAt: Date = Date()

        // MARK: - Init

        init(masterKeyTag: String) {
            self.masterKeyTag      = masterKeyTag
            self.identityCreatedAt = Date()
        }
    }
}
