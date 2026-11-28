//
//  ImageGuard.swift
//  Occulta
//
//  The check an image passes before ImageIO sees it (`bugs.md` Bug 187). ImageIO's cost is set by what an image
//  declares, not by how many bytes it has: a 79-byte PNG that declares a 2 GB chunk makes it allocate 2 GB when it
//  reads the header, and a file of a few kilobytes that declares 30,000 by 30,000 pixels takes 1.6 GB to decode.
//
//  Two checks, both before anything is decoded:
//  - `pngChunkOverruns` walks a PNG's chunks by their length fields, a few comparisons and no decoding.
//  - `source(for:)` refuses an image whose declared width times height is over `maxPixels`.
//
//  One implementation for every image from outside: the share extension's staging (`ShareSession`), and a
//  contact's attachment shown in a message (`AttachmentManager`). A refusal is a thrown `Refusal`; each caller turns
//  it into the failure its own undecodable images already produce, so a refused image can't be told from a damaged one.
//

import Foundation
import ImageIO

nonisolated enum ImageGuard {

    /// The most pixels of an image the app will decode. Decoding allocates width times height, not the file's size: a
    /// 107 KB PNG that declares 30,000 by 30,000 one-bit pixels took 1.6 GB and four seconds on a Mac. 100 megapixels
    /// is about twice what an iPhone's 48-megapixel camera takes. An open decision, not a measured limit.
    static let maxPixels = 100_000_000

    enum Refusal: Error {
        /// An image whose declared size is more than `maxPixels`.
        case tooLarge
        /// A PNG with a chunk that declares more bytes than the file holds, which ImageIO allocates before it finds out.
        case malformed
    }

    /// Whether `data` is a PNG with a chunk that runs past its end, or declares a length the format doesn't allow.
    /// A well-formed PNG, truncated or not, never does: every chunk's length is the bytes that follow its header.
    /// False for anything that isn't a PNG.
    static func pngChunkOverruns(_ data: Data) -> Bool {
        let signature: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        guard data.count >= signature.count, data.prefix(signature.count).elementsEqual(signature) else { return false }

        let base = data.startIndex
        var offset = signature.count
        // A chunk is length (4), type (4), data, CRC (4).
        while offset + 12 <= data.count {
            let length = (0..<4).reduce(0) { $0 << 8 | Int(data[base + offset + $1]) }
            guard length <= 0x7FFF_FFFF, offset + 12 + length <= data.count else { return true }
            offset += 12 + length
        }
        return false
    }

    /// An image source for `data`, or nil if ImageIO can't parse it, after both checks. Nothing is decoded: the declared
    /// size comes from the header. A header that gives none can't be decoded either.
    ///
    /// - Throws: `Refusal.malformed` before ImageIO has read a byte of the chunks, `Refusal.tooLarge` after it has read
    ///   the header and no further.
    static func source(for data: Data) throws -> CGImageSource? {
        // Before ImageIO sees a byte of the chunks: it allocates a chunk's declared length when it reads the header
        // of one, and reads the properties of a 79-byte PNG that declares 2 GB with 1.9 GB.
        guard !Self.pngChunkOverruns(data) else { throw Refusal.malformed }

        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }

        if let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
           let width = (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.int64Value,
           let height = (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.int64Value {
            let (pixels, overflow) = width.multipliedReportingOverflow(by: height)
            if overflow || pixels > Int64(Self.maxPixels) { throw Refusal.tooLarge }
        }
        return source
    }
}
