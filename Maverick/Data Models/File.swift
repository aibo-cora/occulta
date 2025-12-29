//
//  File.swift
//  Maverick
//
//  Created by Yura on 12/29/25.
//

import Foundation
import SwiftUI
internal import UniformTypeIdentifiers


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
