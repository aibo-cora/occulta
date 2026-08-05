//
//  File.swift
//  Occulta
//
//  Created by Yura on 12/29/25.
//

import Foundation
import SwiftUI
import UniformTypeIdentifiers

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
    
    var url: URL?
    var content: Data?
    let format: Format?
    var date: Date? = .now
    
    struct Metadata: Codable, Equatable, Hashable {
        var name: String?
        var `extension`: String?
        /// Message accompanying the file.
        var note: String?

        init(name: String? = nil, extension ext: String? = nil, note: String? = nil) {
            self.name = name
            self.extension = ext?.lowercased()
            self.note = note
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.name = try container.decodeIfPresent(String.self, forKey: .name)
            self.extension = try container.decodeIfPresent(String.self, forKey: .extension)?.lowercased()
            self.note = try container.decodeIfPresent(String.self, forKey: .note)
        }

        /// Validates a (potentially attacker-supplied) file extension for safe use in
        /// path construction. On the inbound message path, `extension` comes from
        /// decrypted, sender-controlled data — never trusted verbatim in an
        /// `.appendingPathExtension` call, since a crafted value could otherwise smuggle
        /// path-traversal characters into the resulting file path. Falls back to "bin"
        /// for anything that isn't a short, plain ASCII alphanumeric string — real file
        /// extensions are always exactly that; anything else is rejected, not modified.
        static func sanitizedFilesystemExtension(_ raw: String?) -> String {
            guard let raw, !raw.isEmpty, raw.count <= 10,
                  raw.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) })
            else { return "bin" }
            return raw
        }
    }

    enum Format: Codable, Equatable, Hashable {
        case contacts, text, file(Metadata), link
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

