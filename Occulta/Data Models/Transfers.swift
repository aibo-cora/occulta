//
//  File.swift
//  Occulta
//
//  Created by Yura on 12/29/25.
//

import Foundation
import SwiftUI
internal import UniformTypeIdentifiers

/// `Basket` with an identified owner.
struct OwnedBasket: Identifiable, Equatable, Codable {
    static func == (lhs: OwnedBasket, rhs: OwnedBasket) -> Bool {
        lhs.id == rhs.id
    }
    
    var id: UUID = UUID()
    
    let basket: Basket
    let owner: String
}

/// Container holding multiple messages, photos or documents delivered all together.
///
/// The contents are encrypted and stored in a file for transport.
struct Basket: Identifiable, Codable {
    var id: UUID = UUID()
    
    /// Collection of files in the basket. Could be of different types.
    var files: [File] = []
    /// Creation date.
    var date: Date?
    /// Owner of this basket. Hash of public key.
    var owner: Data?
}


/// Container with plaintext content.
struct File: Identifiable, Codable, Hashable {
    var id = UUID()
    
    let content: Data?
    let format: Format?
    
    struct Metadata: Codable, Equatable, Hashable {
        var name: String?
        var `extension`: String?
        /// Message accompanying the file.
        var note: String?
    }

    enum Format: Codable, Equatable, Hashable {
        case contacts, text, file(Metadata), link
    }
}

/// Importing a file to `Files` with the original name and extension.
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

/// Container with encrypted contents.
struct EncryptedFile: Transferable, Identifiable {
    var id: UUID = UUID()
    let content: Data
    
    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .data) { file in
            let id = UUID().uuidString.components(separatedBy: "-").last ?? "encrypted.file"
            let tempURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(id).occ")
            
            try file.content.write(to: tempURL)
            
            return SentTransferredFile(tempURL)
        }
    }
}
