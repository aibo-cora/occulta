//
//  Encrypt.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//

import SwiftUI

struct Encrypt: View {
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    @State private var encryptedTextToShare = ""
    @State private var textToEncrypt: String = ""
    
    let identifier: String
    
    private enum Mode: Hashable {
        case message, document
    }
    
    @State private var mode: Mode = .message
    
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
                Image(systemName: "document")
            }
            
            if self.textToEncrypt.isEmpty == false {
                HStack(alignment: .lastTextBaseline, spacing: 20) {
                    Button {
                        
                    } label: {
                        ShareLink(item: self.encryptedTextToShare) {
                            VStack {
                                Image(systemName: "square.and.arrow.up.fill")
                                    .font(.system(size: 25))
                                Text("Share")
                            }
                        }
                    }
                    .onChange(of: self.textToEncrypt) { _, newValue in
                        if newValue.isEmpty == false {
                            let encrypted = try? self.contactManager?.encrypt(message: newValue, for: self.identifier)
                            self.encryptedTextToShare = encrypted ?? ""
                        }
                    }
                    
                    Button {
                        withAnimation {
                            UIPasteboard.general.string = self.encryptedTextToShare
                        }
                    } label: {
                        VStack {
                            Image(systemName: "doc.on.doc.fill")
                                .font(.system(size: 25))
                            Text("Copy To Clipboard")
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
