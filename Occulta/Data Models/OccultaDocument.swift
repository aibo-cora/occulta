//
//  OccultaDocument.swift
//  Occulta
//
//  Created by Yura on 12/14/25.
//


import SwiftUI
internal import UniformTypeIdentifiers

struct OccultaDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.maverick] }  // Optional: only needed if you ever want to import
    
    var fileURL: URL  // Points to your temporary file with the full data
    
    init(fileURL: URL) {
        self.fileURL = fileURL
    }
    
    init(configuration: ReadConfiguration) throws {
        // Not needed for export-only, but required by protocol
        throw CocoaError(.fileReadUnsupportedScheme)
    }
    
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        // This reads your full temp file and returns it for export
        let data = try Data(contentsOf: fileURL)
        return FileWrapper(regularFileWithContents: data)
    }
}

extension UTType {
    static let maverick = UTType(exportedAs: "com.ghafla.aibo-cora.maverick")
}
