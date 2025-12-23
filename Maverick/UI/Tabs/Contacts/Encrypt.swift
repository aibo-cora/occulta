//
//  Encrypt.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//

import SwiftUI
import SwiftData
internal import UniformTypeIdentifiers

struct Encrypt: View {
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    @State private var textToEncrypt: String = ""
    
    let identifier: String
    let filename = "message.maverick"
    
    private enum Mode: Hashable {
        case message, document
    }
    
    @State private var mode: Mode = .message
    /// Encrypted document with metdata
    @State private var document: MaverickDocument?
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
                let tempURL = FileManager.default.temporaryDirectory
                    .appendingPathComponent("message.maverick")
                
                try file.data.write(to: tempURL)
                
                return SentTransferredFile(tempURL)
            }
        }
    }
    
    var body: some View {
        VStack {
            Picker(selection: self.$mode) {
                Text("Message")
                    .tag(Mode.message)
                
                Text("Document")
                    .tag(Mode.document)
            } label: {
                Label {
                    Text("Encryption Mode")
                } icon: {
                    Image(systemName: "lock")
                }
            }
            .pickerStyle(.segmented)
            
            switch self.mode {
            case .message:
                TextEditor(text: self.$textToEncrypt)
                    .foregroundStyle(.secondary)
                    .frame(height: 200)
                    .border(Color.gray, width: 1)
                    .padding()
            case .document:
                Text("Coming Soon...")
                    .padding()
            }
            
            if self.textToEncrypt.isEmpty == false {
                HStack(alignment: .lastTextBaseline, spacing: 20) {
                    let message = (try? self.contactManager?.encrypt(message: self.textToEncrypt, for: self.identifier)) ?? Data()
                    let fileContents = File(content: message, format: .text)
                    
                    if let encodedFileContents = try? JSONEncoder().encode(fileContents) {
                        ShareLink(item: EncryptedFile(data: encodedFileContents), subject: nil, message: nil, preview: SharePreview("Encrypted Message", image: Image(systemName: "doc.text.fill"), icon: Image(systemName: "link"))) {
                            VStack {
                                Image(systemName: "square.and.arrow.up.fill")
                                    .font(.system(size: 25))
                                
                                Text("Share")
                            }
                        }
                    }
                    
                    Button {
                        self.textToEncrypt = ""
                    } label: {
                        VStack {
                            Image(systemName: "trash.fill")
                                .font(.system(size: 25))
                            
                            Text("Reset")
                        }
                    }
                }
            }
        }
    }
}

#Preview {
    Encrypt(identifier: UUID().uuidString)
}
