//
//  Contact+Detail.swift
//  Maverick
//
//  Created by Yura on 11/7/25.
//

import SwiftUI
import SwiftData

struct ContactDetail: View {
    let identifier: String
    
    @Environment(\.modelContext) var modelContext
    @Query(sort: \Contact.familyName) var contacts: [Contact]
    
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    /// First name of the contact
    var name: String {
        self.contacts.first?.givenName.decrypt() ?? "Anonymous"
    }
    /// Phone number of the contact
    var phone: String {
        self.contacts.first?.phoneNumbers.first?.value.decrypt() ?? "No phone number"
    }
    /// Email of the contact
    var email: String {
        self.contacts.first?.emailAddresses.first?.value.decrypt() ?? "No email"
    }
    /// If we do not have a public key from our contact, we need to start an exchange.
    var needsExchange: Bool {
        self.contacts.first?.contactPublicKeys.isEmpty ?? true
    }
    
    init(identifier: String) {
        self.identifier = identifier
        
        let predicate = #Predicate<Contact> {
            $0.identifier == identifier
        }
        
        self._contacts = Query(filter: predicate)
    }
    
    var body: some View {
        VStack {
            Group {
                Text(self.name)
                    .font(.title)
                    .fontWeight(.bold)
                Text(self.email)
                    .font(.footnote)
                Text(self.phone)
                    .font(.footnote)
            }
            
            if self.needsExchange {
                KeyExchange(identifier: self.identifier)
            } else {
                KeyAvailable(identifier: self.identifier)
            }
            
            Spacer()
        }
    }
}

struct KeyAvailable: View {
    let identifier: String
    
    @State private var textToEncrypt: String = ""
    @State private var mode = Mode.encrypt
    
    @State private var encryptedTextToShare = ""
    @State private var decryptedTextToShow: String = ""
    
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    private enum Mode: Int, Hashable {
        case encrypt = 0, decrypt, sign
    }
    
    var body: some View {
        Picker("Mode", selection: self.$mode) {
            Text("Encrypt")
                .tag(Mode.encrypt)
            Text("Decrypt")
                .tag(Mode.decrypt)
        }
        .pickerStyle(.segmented)
        .padding()
        
        switch self.mode {
        case .encrypt:
            TextEditor(text: self.$textToEncrypt)
                .foregroundStyle(.secondary)
                .frame(height: 200) // Set a minimum height for the editor
                .border(Color.gray, width: 1) // Add a border for visual clarity
                .padding()
            
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
                        let encrypted = try? self.contactManager?.encrypt(message: newValue, for: self.identifier)
                        self.encryptedTextToShare = encrypted ?? ""
                    }
                    
                    Button {
                        UIPasteboard.general.string = self.textToEncrypt
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
                            
                            Text("Delete")
                        }
                    }
                }
            }
        case .decrypt:
            VStack(spacing: 20) {
                Button {
                    do {
                        let pastedTextToDecrypt = UIPasteboard.general.string ?? ""
                        let decrypted = try self.contactManager?.decrypt(message: pastedTextToDecrypt, for: self.identifier)
                        
                        self.decryptedTextToShow = decrypted ?? "No text was produced after decryption"
                    } catch {
                        
                    }
                } label: {
                    Text("Paste From Clipboard")
                }
                .buttonStyle(.borderedProminent)
                
                if self.decryptedTextToShow.isEmpty == false {
                    VStack(spacing: 10) {
                        Text("Decrypted Message")
                            .bold()
                        
                        Text(self.decryptedTextToShow)
                            .multilineTextAlignment(.leading)
                            .lineLimit(nil)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        default:
            EmptyView()
        }
    }
}

struct ExchangeDisclaimer: View {
    var body: some View {
        
    }
}

#Preview {
    KeyAvailable(identifier: UUID().uuidString)
}
