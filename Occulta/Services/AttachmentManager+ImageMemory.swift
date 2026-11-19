//
//  AttachmentManager+ImageMemory.swift
//  Occulta
//
//  Bug 219. `AttachmentManager.image(at:)` decrypts a sealed file whole, into one `Data` and a copy of it, to draw its
//  thumbnail. A streamed message carries files of any size, and the bubble is chosen by the extension the sender gave, so a
//  large file labelled `.jpg` reached it. In the app target only: `MemoryGuard` is not part of the share extension.
//

import UIKit

extension AttachmentManager {

    /// The thumbnail of a sealed image, refused first if the process couldn't hold the file: the header's plaintext size is
    /// checked against `memoryGuard`, as an inline bundle's is on receive, before a byte is decrypted.
    ///
    /// - Throws: `OccultaBundle.BundleError.tooLargeForDevice` for a file above the budget; the caller shows the generic
    ///   file bubble instead, which opens the file through a chunked reader.
    func displayImage(at url: URL, memoryGuard: MemoryGuard = .system) async throws -> UIImage {
        try memoryGuard.checkReceive(bundleLength: try self.plaintextSize(at: url))
        return try await self.image(at: url)
    }
}
