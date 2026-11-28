//
//  ReceivedImageRegressionTests.swift
//  OccultaTests
//
//  Bug 187, residual 2: an image that comes from a contact goes through the same check as one the user shares in.
//  The exact hostile inputs of the bug, on the path a received image takes: a sealed attachment, opened by the message
//  bubble (`displayImage`, then `image(at:)`, then `thumbnail(of:)`, where `ImageGuard` reads the header).
//
//  A refusal has to look like any other undecodable image. The bubble shows its spinner for any error but
//  `tooLargeForDevice`, so that means the same error, `invalidImageData`, from the same call; and nothing written,
//  which is checked on the directory the sealed file is in. `AttachmentManager` is built from a key alone and nothing
//  here reads a depth, so the outcome can't differ by depth: the type has no input that could make it.
//

import Testing
import CryptoKit
import Foundation
import ImageIO
import UIKit
import UniformTypeIdentifiers
@testable import Occulta
@testable import OccultaFormats

@Suite("Bug 187 — an image from a contact is checked before ImageIO decodes it", .serialized)
@MainActor
struct ReceivedImageRegressionTests {

    private static func scratch() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("received-image-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// `image` sealed as a received attachment is, in `directory`, named for the extension the sender gave.
    private static func sealed(_ image: Data, in directory: URL, key: SymmetricKey, ext: String = "png") throws -> URL {
        let url = directory.appendingPathComponent("\(UUID().uuidString).\(ext)")
        try AttachmentManager(contactKey: key).encrypt(image, to: url)
        return url
    }

    private static func listing(_ directory: URL) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []).sorted()
    }

    /// The bubble's own call. A thrown error is what leaves the spinner up.
    private static func draw(_ url: URL, key: SymmetricKey) async throws -> UIImage {
        try await AttachmentManager(contactKey: key).displayImage(at: url, memoryGuard: MemoryGuard { Int.max })
    }

    private static let hostile: [(name: String, bytes: Data)] = [
        ("79-byte PNG declaring a 2 GB chunk", ImageSizeRegressionTests.declares2GB),
        ("574-byte PNG the fuzzer found, an iTXt length of 1,676,476,820", ImageSizeRegressionTests.fuzzFound),
        ("PNG declaring 30,000 by 30,000 pixels", ImageSizeRegressionTests.png(width: 30_000, height: 30_000)),
    ]

    @Test("the hostile inputs are the bug's: 79 bytes declaring 2 GB, and a small file declaring 900 megapixels")
    func inputsAreTheBugs() throws {
        #expect(ImageSizeRegressionTests.declares2GB.count == 79)
        #expect(ImageGuard.pngChunkOverruns(ImageSizeRegressionTests.declares2GB))

        let big = ImageSizeRegressionTests.png(width: 30_000, height: 30_000)
        #expect(big.count < 1_000_000, "the bomb should be small: \(big.count) bytes")
        let source = try #require(CGImageSourceCreateWithData(big as CFData, nil))
        let properties = try #require(CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any])
        #expect((properties[kCGImagePropertyPixelWidth] as? Int) == 30_000)
        #expect((properties[kCGImagePropertyPixelHeight] as? Int) == 30_000)
    }

    @Test("each is refused with invalidImageData, the error a damaged image gives, and leaves nothing behind")
    func refusedLikeADamagedImage() async throws {
        let directory = try Self.scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let key = SymmetricKey(size: .bits256)

        // The reference: bytes that are not an image at all.
        let damaged = try Self.sealed(Data("not an image".utf8), in: directory, key: key)
        let reference = await #expect(throws: AttachmentError.self) { _ = try await Self.draw(damaged, key: key) }
        #expect(reference == .invalidImageData)

        for input in Self.hostile {
            let url = try Self.sealed(input.bytes, in: directory, key: key)
            let before = Self.listing(directory)

            let refusal = await #expect(throws: AttachmentError.self, "\(input.name)") { _ = try await Self.draw(url, key: key) }
            #expect(refusal == reference, "\(input.name): refused differently from a damaged image")
            #expect(Self.listing(directory) == before, "\(input.name): the refusal changed the directory")
        }
    }

    @Test("the check is what refuses the 2 GB chunk, before ImageIO reads it: its own error, not an outcome ImageIO would reach")
    func guardRefusesBeforeImageIO() throws {
        // ImageIO fails on the 79 bytes either way, so the outcome above can't show the guard ran. The guard's own answer does.
        #expect(throws: ImageGuard.Refusal.malformed) { try ImageGuard.source(for: ImageSizeRegressionTests.declares2GB) }
        #expect(throws: ImageGuard.Refusal.malformed) { try ImageGuard.source(for: ImageSizeRegressionTests.fuzzFound) }
        #expect(throws: ImageGuard.Refusal.tooLarge) { try ImageGuard.source(for: ImageSizeRegressionTests.png(width: 30_000, height: 30_000)) }
        // As a slice that starts past 0.
        let wide = Data(repeating: 0xAB, count: 9) + ImageSizeRegressionTests.declares2GB
        #expect(throws: AttachmentError.invalidImageData) { try AttachmentManager.thumbnail(of: wide[9...]) }
    }

    @Test("the limit is the share path's, unchanged: 100 megapixels is let through, a little over it is not")
    func limitIsTheSharePathsLimit() throws {
        #expect(ImageGuard.maxPixels == 100_000_000)
        #expect(ShareSession.maxImagePixels == ImageGuard.maxPixels, "one limit for both paths")

        #expect(try ImageGuard.source(for: ImageSizeRegressionTests.png(width: 10_000, height: 10_000)) != nil)
        #expect(throws: ImageGuard.Refusal.tooLarge) { try ImageGuard.source(for: ImageSizeRegressionTests.png(width: 100_001, height: 1_000)) }
    }

    @Test("a well-formed PNG and an ordinary JPEG are still drawn")
    func ordinaryImagesDraw() async throws {
        let directory = try Self.scratch(); defer { try? FileManager.default.removeItem(at: directory) }
        let key = SymmetricKey(size: .bits256)

        let png = try Self.sealed(ImageSizeRegressionTests.wellFormed, in: directory, key: key)
        #expect(try await Self.draw(png, key: key).size.width > 0)

        let jpeg = try Self.sealed(try #require(ShareSessionTarget.image(as: .jpeg)), in: directory, key: key, ext: "jpg")
        #expect(try await Self.draw(jpeg, key: key).size.width > 0)
    }
}
