//
//  File.swift
//  Maverick
//
//  Created by Yura on 12/29/25.
//

import Foundation
import SwiftUI
internal import UniformTypeIdentifiers

struct ImportedFile: Identifiable {
    var id: UUID = UUID()
    
    let file: File
    let owner: String
}


struct File: Identifiable, Codable {
    var id = UUID()
    
    let content: Data?
    let format: Format?
    
    var date: String?
    
    struct Metadata: Codable {
        var name: String?
        var `extension`: String?
    }

    enum Format: Codable {
        case contacts, text, file(Metadata), link
    }
}

struct FileTransferable: Transferable {
    let data: Data
    let fileName: String
    
    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .data) { file in
            file.data
        }
        .suggestedFileName { file in
            file.fileName
        }
    }
}

struct EncryptedFile: Transferable, Identifiable {
    var id: UUID = UUID()
    let data: Data
    
    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .data) { file in
            let id = UUID().uuidString.components(separatedBy: "-").last ?? "encrypted.file"
            let tempURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(id).maverick")
            
            try file.data.write(to: tempURL)
            
            return SentTransferredFile(tempURL)
        }
    }
}
