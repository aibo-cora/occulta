//
//  ShareExtensionActivationTests.swift
//  OccultaTests
//
//  The share extension's activation rule decides whether Occulta shows in the system share
//  sheet at all. Photos offers a video as a movie type, not a file URL, so without the movie
//  key the extension is hidden for videos.
//

import Testing
import Foundation
import UniformTypeIdentifiers

struct ShareExtensionActivationTests {

    private func activationRule() throws -> [String: Any] {
        let plist = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // ShareExtension
            .deletingLastPathComponent()   // OccultaTests
            .deletingLastPathComponent()   // repo root
            .appendingPathComponent("ShareExtension/Info.plist")

        let data = try Data(contentsOf: plist)
        let root = try #require(
            PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        )
        let ext = try #require(root["NSExtension"] as? [String: Any])
        let attributes = try #require(ext["NSExtensionAttributes"] as? [String: Any])
        return try #require(attributes["NSExtensionActivationRule"] as? [String: Any])
    }

    @Test func activationRuleCoversFilesImagesAndMovies() throws {
        let rule = try self.activationRule()

        #expect(rule["NSExtensionActivationSupportsFileWithMaxCount"] as? Int == 20)
        #expect(rule["NSExtensionActivationSupportsImageWithMaxCount"] as? Int == 20)
        #expect(rule["NSExtensionActivationSupportsMovieWithMaxCount"] as? Int == 20)
    }

    @Test(arguments: [
        ("com.apple.quicktime-movie", "mov"),
        ("public.mpeg-4", "mp4")
    ])
    func movieTypesYieldSensibleExtensions(uti: String, expected: String) throws {
        let type = try #require(UTType(uti))

        #expect(type.conforms(to: .movie))
        #expect(type.preferredFilenameExtension == expected)
    }
}
