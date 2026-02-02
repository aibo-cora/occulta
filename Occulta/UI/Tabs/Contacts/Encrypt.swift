//
//  Encrypt.swift
//  Occulta
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
    let filename = "message.occulta"
    
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
    
    var body: some View {
        VStack(spacing: 20) {
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
        .padding(.horizontal)
    }
    
    struct Message: View {
        @Environment(ContactManager.self) private var contactManager: ContactManager?
        @Binding var textToEncrypt: String
        
        let identifier: String
        
        var body: some View {
            VStack {
                TextField("Message to Encrypt", text: self.$textToEncrypt, axis: .vertical)
                    .lineLimit(1...6)
                    .padding()
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                
                if self.textToEncrypt.isEmpty == false, let payload = self.textToEncrypt.data(using: .utf8) {
                    HStack(alignment: .lastTextBaseline, spacing: 20) {
                        let fileContents = Occulta.File(content: payload, format: .text)
                        let basket = Basket(files: [fileContents])
                        let encodedBasketContents = (try? JSONEncoder().encode(basket)) ?? Data()
                        let encryptedBasketContents = try? self.contactManager?.encrypt(data: encodedBasketContents, for: self.identifier)
                        
                        if let encryptedBasketContents {
                            ShareLink(item: EncryptedFile(content: encryptedBasketContents), subject: nil, message: nil, preview: SharePreview("Encrypted Message", image: Image(systemName: "doc.text.fill"), icon: Image(systemName: "link"))) {
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
        
        @State private var selection: PhotosPickerItem? = nil
        
        let identifier: String
        
        @Environment(ContactManager.self) private var contactManager: ContactManager?
        
        private enum Status {
            case initial, importing, encrypting(String), encrypted(String, EncryptedFile), failure(Error)
        }
        
        @State private var status: Status = .initial
        
        var body: some View {
            VStack(spacing: 20) {
                switch self.status {
                case .initial:
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
                            self.handleImport(photo: newValue)
                        }
                    }
                    .font(.system(size: 25))
                case .importing:
                    ProgressView("Importing file...This might take a while for large files.")
                case .encrypting(let filename):
                    HStack {
                        Text("Imported File")
                            .bold()
                        Text(filename)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    ProgressView("Encrypting file...")
                case .encrypted(let filename, let encryptedFile):
                    HStack {
                        Text("Imported File")
                            .bold()
                        Text(filename)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    Text("We created an encrypted file with contents of the file you imported.")
                        .multilineTextAlignment(.center)
                    
                    HStack(alignment: .lastTextBaseline, spacing: 20) {
                        ShareLink(item: encryptedFile, preview: SharePreview("Encrypted File", image: Image(systemName: "doc.text.fill"), icon: Image(systemName: "link"))) {
                            VStack {
                                Image(systemName: "square.and.arrow.up")
                            }
                        }
                        
                        Button {
                            self.status = .initial
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
                case .failure(let error):
                    Text("Something went wrong. Error: \(error.localizedDescription)")
                }
            }
            .fileImporter(isPresented: self.$isImporting, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    do {
                        try self.handleImport(urls: urls)
                    } catch {
                        self.status = .failure(error)
                    }
                case .failure(let failure):
                    debugPrint("Error importing file, \(failure)")
                    
                    self.status = .failure(failure)
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
            
            self.status = .importing
            
            defer { url.stopAccessingSecurityScopedResource() }
            
            let data = try Data(contentsOf: url)
            
            let name = url.deletingPathExtension().lastPathComponent
            let fileExtension = url.pathExtension
            
            self.status = .encrypting(url.lastPathComponent)
            
            let file = try self.encrypt(data: data, name: name, fileExtension: fileExtension)
            
            self.status = .encrypted(url.lastPathComponent, file)
        }
        
        private func handleImport(photo: PhotosPickerItem?) {
            guard
                let photo
            else {
                debugPrint("No photo selected for encryption")
                
                return
            }
            
            Task {
                do {
                    self.status = .importing
                    
                    if let data = try await photo.loadTransferable(type: Data.self) {
                        if let utType = photo.supportedContentTypes.first {
                            let fileExtension = utType.preferredFilenameExtension ?? "unknown"
                            let _ = utType.preferredMIMEType
                            
                            let name = UUID().uuidString.components(separatedBy: "-").last ?? "library.asset"
                            let filename = "\(name).\(fileExtension)"
                            
                            self.status = .encrypting(filename)
                            
                            let encryptedFile = try self.encrypt(data: data, name: name, fileExtension: fileExtension)
                            
                            self.status = .encrypted(filename, encryptedFile)
                        }
                    } else {
                        
                    }
                } catch {
                    self.status = .failure(error)
                }
            }
        }
        
        private func encrypt(data: Data, name: String, fileExtension: String) throws -> EncryptedFile {
            let fileContents = Occulta.File(content: data, format: .file(Occulta.File.Metadata(name: name, extension: fileExtension)))
            let basket = Basket(files: [fileContents])
            
            let encoded = try JSONEncoder().encode(basket)
            let encrypted = try self.contactManager?.encrypt(data: encoded, for: self.identifier) ?? Data()
            
            let encryptedFile = EncryptedFile(content: encrypted)
            
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
