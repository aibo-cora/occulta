//
//  File.swift
//  Occulta
//
//  Created by Yura on 12/29/25.
//

import Foundation
import SwiftUI
import UniformTypeIdentifiers
import OccultaCore

/// `Basket` with an identified owner.
struct OwnedBasket: Identifiable, Equatable, Codable {
    static func == (lhs: OwnedBasket, rhs: OwnedBasket) -> Bool {
        lhs.id == rhs.id
    }
    
    var id: UUID = UUID()
    
    let basket: Basket
    let owner: String
}

struct FileURL: Transferable {
    let url: URL

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(contentType: .data) { data in
            SentTransferredFile(data.url)
        } importing: { received in
            Self(url: received.file)
        }
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

