//
//  Import+View.swift
//  Maverick
//
//  Created by Yura on 12/15/25.
//

import SwiftUI
internal import UniformTypeIdentifiers

struct Import: View {
    let imported: ImportedFile
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
    @State private var passphrase: String = ""
    
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            switch self.imported.file.format {
            case .contacts:
                VStack {
                    VStack {
                        Text("Enter the passphrase that was used to encrypt this file")
                        
                        TextField("Passphrase", text: self.$passphrase, prompt: Text("Required"))
                            .textFieldStyle(.roundedBorder)
                            .font(.custom("Courier", size: 20))
                    }
                    .padding()
                    
                    Button {
                        do {
                            try self.contactManager.import(data: self.imported.file.content, using: self.passphrase)
                            
                            self.dismiss()
                        } catch {
                            debugPrint("Could not import contacts: \(error).")
                        }
                    } label: {
                        Text("Import Contacts")
                    }
                    .prominentButtonStyle()
                    .disabled(self.passphrase.isEmpty)
                }
            case .text:
                let message = String(data: self.imported.file.content ?? Data(), encoding: .utf8)
                
                if let message {
                    VStack(spacing: 20) {
                        Contact.Info(identifier: self.imported.owner)
                        
                        Text(message)
                    }
                } else {
                    Text("This message is not meant for you.")
                        .task {
                            debugPrint("Owner: \(self.imported.owner)")
                        }
                }
            case .file(let metadata):
                let filename = [metadata.name, metadata.extension].compactMap { $0 }.joined(separator: ".")
                
                if let fileContents = self.imported.file.content {
                    VStack(spacing: 20) {
                        Contact.Info(identifier: self.imported.owner)
                     
                        HStack {
                            Text("Received File")
                                .bold()
                            
                            Text(filename)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        ShareLink(item: FileTransferable(data: fileContents, fileName: filename), preview: SharePreview(Text(filename), image: Image(systemName: "doc.fill"))) {
                            Label("Export File", systemImage: "square.and.arrow.up")
                        }
                    }
                }
            case .link:
                EmptyView()
            case .none:
                EmptyView()
            }
        }
    }
}

#Preview {
    Import(imported: ImportedFile(file: File(content: Data(), format: .contacts), owner: UUID().uuidString))
        .environment(ContactManager.preview)
}
