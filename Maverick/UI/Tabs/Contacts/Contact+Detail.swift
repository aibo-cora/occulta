//
//  Contact+Detail.swift
//  Maverick
//
//  Created by Yura on 11/7/25.
//

import SwiftUI
import SwiftData

extension Contact {
    struct Details: View {
        let identifier: String
        
        @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
        
        @Environment(\.modelContext) var modelContext
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
            
            let predicate = #Predicate<Contact.Profile> {
                $0.identifier == identifier
            }
            
            self._contacts = Query(filter: predicate)
        }
        
        @State private var editing: Bool = false
        @State private var displayingInfo: Bool = false
        
        var body: some View {
            VStack(spacing: 20) {
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
                    
                    Spacer()
                } else {
                    Encrypt(identifier: self.identifier)
                    
                    Spacer()
                    
                    VStack {
                        Button("Revoke Key", role: .destructive) {
                            try? self.contactManager?.reset(identity: self.identifier)
                        }
                        .prominentButtonStyle()
                        
                        HStack(alignment: .firstTextBaseline) {
                            Button {
                                self.displayingInfo.toggle()
                            } label: {
                                Image(systemName: "info.bubble")
                            }
                            
                            Text("Data we encrypt here is only visible to you and this contact.")
                                .font(.footnote)
                                .multilineTextAlignment(.center)
                        }
                        .padding()
                        
                        if self.displayingInfo {
                            Text("We use **AES GCM 256** encryption, with a key derived from your private key and this contacts public key, to secure data. The key is **never** stored or transmitted anywhere.")
                                .font(.caption)
                                .padding()
                        }
                    }
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        self.editing = true
                    } label: {
                        Text("Edit")
                    }
                }
            }
            .sheet(isPresented: self.$editing) {
                
            } content: {
                Contact.Form(mode: .edit(identifier: self.identifier))
            }
        }
    }
}



#Preview {
    Contact.Details(identifier: UUID().uuidString)
        .environment(ContactManager.preview)
}
