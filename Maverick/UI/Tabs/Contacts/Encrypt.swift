//
//  Encrypt.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//

import SwiftUI
import SwiftData
internal import UniformTypeIdentifiers
import PhotosUI

struct Encrypt: View {
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    @State private var textToEncrypt: String = ""
    
    let identifier: String
    let filename = "message.maverick"
    
    private enum Mode: Hashable {
        case message, file
    }
    
    @State private var mode: Mode = .message
    @State private var exportEncryptedMessage = false
    
    @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
    
    init(identifier: String) {
        self.identifier = identifier
        
        let predicate = #Predicate<Contact.Profile> {
            $0.identifier == identifier
        }
        
        self._contacts = Query(filter: predicate)
    }
    
    struct EncryptedFile: Transferable {
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
    
    var body: some View {
        VStack {
            Picker("What would you like to encrypt?", selection: self.$mode) {
                Text("Message")
                    .tag(Mode.message)
                
                Text("Document")
                    .tag(Mode.file)
            }
            .pickerStyle(.segmented)
            
            switch self.mode {
            case .message:
                Message(textToEncrypt: self.$textToEncrypt, identifier: self.identifier)
            case .file:
                Encrypt.File(identifier: self.identifier)
                    .padding(.top)
            }
        }
    }
    
    struct Message: View {
        @Environment(ContactManager.self) private var contactManager: ContactManager?
        @Binding var textToEncrypt: String
        
        let identifier: String
        
        var body: some View {
            VStack {
                TextEditor(text: self.$textToEncrypt)
                    .foregroundStyle(.secondary)
                    .frame(height: 200)
                    .border(Color.gray, width: 1)
                    .padding()
                
                if self.textToEncrypt.isEmpty == false {
                    HStack(alignment: .lastTextBaseline, spacing: 20) {
                        let message = (try? self.contactManager?.encrypt(message: self.textToEncrypt, for: self.identifier))
                        let fileContents = Maverick.File(content: message, format: .text)
                        
                        if let encodedFileContents = try? JSONEncoder().encode(fileContents) {
                            ShareLink(item: EncryptedFile(data: encodedFileContents), subject: nil, message: nil, preview: SharePreview("Encrypted Message", image: Image(systemName: "doc.text.fill"), icon: Image(systemName: "link"))) {
                                VStack {
                                    Image(systemName: "square.and.arrow.up")
                                }
                            }
                        }
                        
                        Button {
                            self.textToEncrypt = ""
                        } label: {
                            VStack {
                                Image(systemName: "trash")
                            }
                        }
                    }
                    .font(.system(size: 25))
                    
                    Text("Share this encrypted file with your contact.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding()
                }
            }
        }
    }
    
    struct File: View {
        @State private var isImporting = false
        @State private var name: String?
        
        @State private var encryptedFile: EncryptedFile?
        @State private var selection: PhotosPickerItem? = nil
        
        let identifier: String
        
        @Environment(ContactManager.self) private var contactManager: ContactManager?
        
        var body: some View {
            VStack(spacing: 20) {
                HStack {
                    Button {
                        self.isImporting = true
                    } label: {
                        Image(systemName: "doc")
                    }
                    
                    PhotosPicker(selection: self.$selection) {
                        Image(systemName: "photo")
                    }
                    .pickerStyle(.inline)
                    .onChange(of: self.selection) { _, newValue in
                        do {
                            try self.handleImport(photo: newValue)
                        } catch {
                            debugPrint("Could not handle photo selection, error: \(error)")
                        }
                    }
                }
                .font(.system(size: 25))
                
                if let name = self.name, let encryptedFile {
                    HStack {
                        Text("Selected File")
                            .bold()
                        Text(name)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    HStack(alignment: .lastTextBaseline, spacing: 20) {
                        ShareLink(item: encryptedFile, preview: SharePreview("Encrypted File", image: Image(systemName: "doc.text.fill"), icon: Image(systemName: "link"))) {
                            VStack {
                                Image(systemName: "square.and.arrow.up")
                            }
                        }
                        
                        Button {
                            self.selection = nil
                            self.name = nil
                            self.encryptedFile = nil
                        } label: {
                            VStack {
                                Image(systemName: "trash")
                            }
                        }
                    }
                    .font(.system(size: 25))
                    
                    Text("Share this encrypted file with your contact.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .fileImporter(isPresented: self.$isImporting, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    do {
                        try self.handleImport(urls: urls)
                    } catch {
                        
                    }
                case .failure(let failure):
                    debugPrint("Error importing file, \(failure)")
                }
            }
        }
        
        private func handleImport(urls: [URL]) throws {
            guard
                let url = urls.first,
                url.startAccessingSecurityScopedResource()
            else {
                debugPrint("Could not read file contents while importing")
                
                return
            }
            
            defer { url.stopAccessingSecurityScopedResource() }
            
            let data = try Data(contentsOf: url)
            
            let name = url.deletingPathExtension().lastPathComponent
            let fileExtension = url.pathExtension
            
            let file = try self.encrypt(data: data, name: name, fileExtension: fileExtension)
            
            self.encryptedFile = file
            self.name = url.lastPathComponent
        }
        
        private func handleImport(photo: PhotosPickerItem?) throws {
            guard
                let photo
            else {
                debugPrint("No photo selected for encryption")
                
                return
            }
            
            Task {
                if let data = try await photo.loadTransferable(type: Data.self) {
                    let name = photo.itemIdentifier?.components(separatedBy: ".").first ?? "image"
                    let fileExtension = photo.itemIdentifier?.components(separatedBy: ".").last ?? "png"
                    
                    self.encryptedFile = try self.encrypt(data: data, name: name, fileExtension: fileExtension)
                    self.name = photo.itemIdentifier ?? "image.png"
                }
            }
        }
        
        private func encrypt(data: Data, name: String, fileExtension: String) throws -> EncryptedFile? {
            let encryptedContent = try self.contactManager?.encrypt(data: data, for: self.identifier)
            
            let encryptedName = try self.contactManager?.encrypt(message: name, for: self.identifier)?.base64EncodedString()
            let encryptedFileExtension = try self.contactManager?.encrypt(message: fileExtension, for: self.identifier)?.base64EncodedString()
            
            let date = self.contactManager?.dateFormatter.string(from: .now) ?? ""
            let encryptedDate = try self.contactManager?.encrypt(message: date, for: self.identifier)?.base64EncodedString()
            
            let fileContents = Maverick.File(content: encryptedContent, format: .document(Maverick.File.Metadata(name: encryptedName, extension: encryptedFileExtension)), date: encryptedDate)
            
            let encoded = try JSONEncoder().encode(fileContents)
            let encryptedFile = EncryptedFile(data: encoded)
            
            return encryptedFile
        }
    }
}

#Preview {
    Encrypt(identifier: UUID().uuidString)
}

#Preview {
    Encrypt.File(identifier: UUID().uuidString)
}
