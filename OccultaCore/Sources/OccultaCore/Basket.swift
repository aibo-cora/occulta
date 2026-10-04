//
//  Basket.swift
//  OccultaCore
//
//  The plaintext a bundle carries: a basket of files, with their metadata.
//

import Foundation

/// Container holding multiple messages, photos or documents delivered all together.
///
/// The contents are encrypted and stored in a file for transport.
public struct Basket: Identifiable, Codable {
    public var id: UUID = UUID()
    
    /// Collection of files in the basket. Could be of different types.
    public var files: [File] = []
    /// Creation date.
    public var date: Date?
    /// Owner of this basket. Hash of public key.
    public var owner: Data?

    public init(id: UUID = UUID(), files: [File] = [], date: Date? = nil, owner: Data? = nil) {
        self.id    = id
        self.files = files
        self.date  = date
        self.owner = owner
    }
}


/// Container with plaintext content.
public struct File: Identifiable, Codable, Hashable {
    public var id = UUID()
    
    public var url: URL?
    public var content: Data?
    public let format: Format?
    public var date: Date? = .now

    public init(id: UUID = UUID(), url: URL? = nil, content: Data? = nil, format: Format?, date: Date? = .now) {
        self.id      = id
        self.url     = url
        self.content = content
        self.format  = format
        self.date    = date
    }

    public struct Metadata: Codable, Equatable, Hashable {
        public var name: String?
        public var `extension`: String?
        /// Message accompanying the file.
        public var note: String?

        public init(name: String? = nil, extension ext: String? = nil, note: String? = nil) {
            self.name = name
            self.extension = ext?.lowercased()
            self.note = note
        }

        public init(from decoder: Decoder) throws {
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
        public static func sanitizedFilesystemExtension(_ raw: String?) -> String {
            guard let raw, !raw.isEmpty, raw.count <= 10,
                  raw.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) })
            else { return "bin" }
            return raw
        }
    }

    public enum Format: Codable, Equatable, Hashable {
        case contacts, text, file(Metadata), link
    }
}
