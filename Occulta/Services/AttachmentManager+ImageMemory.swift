//
//  AttachmentManager+ImageMemory.swift
//  Occulta
//
//  Bug 219. `AttachmentManager.image(at:)` decrypts a sealed file whole, into one `Data` and a copy of it, to draw its
//  thumbnail. A streamed message carries files of any size, and the bubble is chosen by the extension the sender gave, so a
//  large file labelled `.jpg` reached it. In the app target only: `MemoryGuard` is not part of the share extension.
//

import UIKit

/// One full-size image decrypting at a time. Each bubble checks the memory guard for its own file, so several bubbles
/// opened together each saw the whole budget free and all decrypted at once; here they take turns, and each is checked
/// when its turn comes, against the memory the ones before it have given back.
actor ImageDecryptionGate {

    static let shared = ImageDecryptionGate()

    private var busy = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    private var inFlight = 0

    /// The most that were ever past `acquire()` at once. For tests.
    private(set) var peakInFlight = 0

    func acquire() async {
        if self.busy {
            await withCheckedContinuation { self.waiting.append($0) }
        }
        // Resumed with the gate handed over, or the gate was free: either way it is this caller's.
        self.busy = true
        self.inFlight += 1
        self.peakInFlight = max(self.peakInFlight, self.inFlight)
    }

    func release() {
        self.inFlight -= 1
        if self.waiting.isEmpty {
            self.busy = false
        } else {
            self.waiting.removeFirst().resume()
        }
    }
}

extension AttachmentManager {

    /// The thumbnail of a sealed image, refused first if the process couldn't hold the file: the header's plaintext size is
    /// checked against `memoryGuard`, as an inline bundle's is on receive, before a byte is decrypted. One image at a time
    /// goes through (`ImageDecryptionGate`), so the check holds for the whole of what is in memory.
    ///
    /// - Throws: `OccultaBundle.BundleError.tooLargeForDevice` for a file above the budget; the caller shows the generic
    ///   file bubble instead, which opens the file through a chunked reader.
    func displayImage(
        at url: URL, memoryGuard: MemoryGuard = .system, gate: ImageDecryptionGate = .shared
    ) async throws -> UIImage {
        await gate.acquire()
        do {
            try memoryGuard.checkReceive(bundleLength: try self.plaintextSize(at: url))
            let image = try await self.image(at: url)
            await gate.release()
            return image
        } catch {
            await gate.release()
            throw error
        }
    }
}
