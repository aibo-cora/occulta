//
//  MemoryGuard.swift
//  Occulta
//
//  Refuses inline-layout work that cannot fit in memory, before any of it starts.
//  STREAMING_SPEC §7, Bug 183.
//

import Foundation
import os
import OccultaFormats

/// The inline bundle layout holds whole bodies in memory. Before the one-shot work, this compares
/// an estimate of what it needs with what the process may still allocate.
///
/// The guard refuses outright; there is no "try anyway". A refusal changes nothing: no prekey is
/// taken and nothing is written, so it is safe to call before either. It reads only the size of the
/// work and the process's memory, never a contact or a depth, and its messages name neither.
struct MemoryGuard: Sendable {

    /// What the process needs on top of the bundle's own copies: the UI, the database and the rest.
    nonisolated static let headroom = 64 * 1024 * 1024

    /// Bytes this process can still allocate. Injected so a test can pose any amount.
    let availableMemory: @Sendable () -> Int

    /// Production: `os_proc_available_memory()`.
    ///
    /// The Simulator is the exception: it reports 0, which would refuse every inline bundle in a
    /// Simulator run. There the figure is unmeasurable, so nothing is refused. A device build has no
    /// such branch.
    nonisolated static let system = MemoryGuard {
        #if targetEnvironment(simulator)
        Int.max
        #else
        Int(os_proc_available_memory())
        #endif
    }

    /// Receive: opening an inline body holds the ciphertext and the plaintext, 2*T*, plus headroom.
    nonisolated func checkReceive(bundleLength: Int) throws {
        guard self.availableMemory() >= 2 * bundleLength + Self.headroom else {
            throw OccultaBundle.BundleError.tooLargeForDevice
        }
    }

    /// Send: sealing an inline body holds the plaintext, its copy in the basket encoding, the
    /// ciphertext and the encoded bundle, 4*P*, plus headroom.
    nonisolated func checkSend(plaintextLength: Int) throws {
        guard self.availableMemory() >= 4 * plaintextLength + Self.headroom else {
            throw SendRefusal.tooLargeToSend
        }
    }

    enum SendRefusal: LocalizedError {
        case tooLargeToSend

        var errorDescription: String? {
            "This message is too large to send until the recipient updates Occulta."
        }
    }
}
