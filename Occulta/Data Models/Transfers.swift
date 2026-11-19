//
//  File.swift
//  Occulta
//
//  Created by Yura on 12/29/25.
//

import Foundation
import SwiftUI
import UniformTypeIdentifiers
import OccultaFormats

/// `Basket` with an identified owner.
struct OwnedBasket: Identifiable, Equatable, Codable {
    static func == (lhs: OwnedBasket, rhs: OwnedBasket) -> Bool {
        lhs.id == rhs.id
    }
    
    var id: UUID = UUID()
    
    let basket: Basket
    let owner: String

    /// Set when the message's attachments are still being decrypted from a streamed bundle. The sheet
    /// reads `receive.files` in place of `basket.files`. Never encoded.
    var receive: StreamedReceive? = nil

    private enum CodingKeys: String, CodingKey { case id, basket, owner }

    /// Deletes the sealed attachment files of `basket`: the message sheet's `onDisappear`, and a result that is dropped
    /// because the session ended while the file was being opened, which nothing will ever show (Bug 217).
    func removeSealedFiles() {
        for file in self.basket.files {
            if let url = file.url { try? FileManager.default.removeItem(at: url) }
        }
    }
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

