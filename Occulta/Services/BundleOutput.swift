//
//  BundleOutput.swift
//  Occulta
//
//  Where a send puts its bundle, and what that does to its basket. STREAMING_SPEC §3, §8.3 and §10.2.
//

import Foundation
import OccultaFormats

/// Which layout a send used.
enum BundleLayout: Equatable {
    /// The body is one AES-GCM seal, held in memory whole.
    case inline
    /// The body is a chunk stream, written to the destination as it was sealed.
    case streamed
}

/// What a send does with its bundle.
enum BundleOutput {
    /// The inline layout, returned as `Data`. For callers with no files to stream.
    case memory

    /// Written to `destination`. The streamed layout when every recipient can read it (§10.2), otherwise the
    /// inline one, under the memory guard.
    ///
    /// The basket's `.file` entries may carry a `url` to a staged `.eatt` file in place of their content, and
    /// `attachments` opens them. Nothing reads them until the layout is chosen, so a streamed send never holds one.
    case file(destination: URL, attachments: AttachmentManager?, memoryGuard: MemoryGuard)

    var destination: URL? {
        if case .file(let destination, _, _) = self { return destination }
        return nil
    }

    /// The inline layout's bytes, delivered: returned for `.memory`, written (protected) for `.file`.
    func deliver(_ encoded: Data) throws -> SentBundle {
        guard let destination else { return SentBundle(data: encoded, layout: .inline) }
        try encoded.writeProtected(to: destination)
        return SentBundle(data: nil, layout: .inline)
    }

    /// The basket for the inline layout: every staged file read into memory. Refused up front, before anything is
    /// read or any prekey taken, if the body wouldn't fit (§7). A basket sent in memory is returned as it is.
    func inlineBasket(_ basket: Basket?) throws -> Basket? {
        guard case .file(_, let attachments, let memoryGuard) = self, var basket else { return basket }

        var total = 0
        for file in basket.files {
            if let url = file.url {
                guard let attachments else { throw ImportError.stagingKeyUnavailable }
                total += try attachments.plaintextSize(at: url)
            } else {
                total += file.content?.count ?? 0
            }
        }
        try memoryGuard.checkSend(plaintextLength: total)

        basket.files = try basket.files.map { file in
            guard let url = file.url, let attachments else { return file }
            return OccultaFormats.File(
                id: file.id, content: try attachments.plaintextBlocking(at: url), format: file.format, date: file.date
            )
        }
        return basket
    }

    /// The streamed layout's parts: the basket as the manifest carries it, and the files that follow.
    ///
    /// Every `.file` is streamed, and nothing else is (§4.4). A file with a staged `url` is read from it a chunk at
    /// a time; one that only has content is fed from memory.
    func streamedParts(_ basket: Basket?) throws -> (message: Data?, files: StreamedFiles) {
        guard case .file(let destination, let attachments, _) = self else { throw ImportError.stagingKeyUnavailable }
        guard let basket else { return (nil, StreamedFiles(destination: destination, sources: [])) }

        var lengths: [UInt64?] = []
        var sources: [StreamedFileSource] = []
        for file in basket.files {
            guard case .file = file.format else { lengths.append(nil); continue }

            if let url = file.url {
                guard let attachments else { throw ImportError.stagingKeyUnavailable }
                let length = UInt64(try attachments.plaintextSize(at: url))
                lengths.append(length)
                sources.append(StreamedFileSource(length: length) { emit in
                    try attachments.forEachChunk(at: url, emit)
                })
            } else {
                let content = file.content ?? Data()
                lengths.append(UInt64(content.count))
                sources.append(StreamedFileSource(length: UInt64(content.count)) { emit in
                    if !content.isEmpty { try emit(content) }
                })
            }
        }
        return (
            try WireHandle.encode(basket: basket, streamedLengths: lengths),
            StreamedFiles(destination: destination, sources: sources)
        )
    }
}

/// The outcome of a send: the bytes when they were returned in memory, and the layout either way.
struct SentBundle {
    let data: Data?
    let layout: BundleLayout
}
