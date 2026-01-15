//
//  Contact+Detail.swift
//  Maverick
//
//  Created by Yura on 11/7/25.
//

import SwiftUI
import SwiftData

extension Contact {
    struct Info: View {
        let identifier: String
        
        @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
        
        @Environment(\.modelContext) var modelContext
        
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
        
        init(identifier: String) {
            self.identifier = identifier
            
            let predicate = #Predicate<Contact.Profile> {
                $0.identifier == identifier
            }
            
            self._contacts = Query(filter: predicate)
        }
        
        var body: some View {
            VStack {
                Text(self.name)
                    .font(.title)
                    .fontWeight(.bold)
                Text(self.email)
                    .font(.footnote)
                Text(self.phone)
                    .font(.footnote)
            }
        }
    }
}

extension Contact {
    struct Details: View {
        let identifier: String
        
        @Environment(ContactManager.self) private var contactManager: ContactManager?
        @Environment(\.dismiss) private var dismiss
        
        @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
        
        /// If we do not have a public key from our contact, we need to start an exchange.
        var needsExchange: Bool {
            self.contacts.first?.contactPublicKeys.isEmpty ?? true
        }
        /// Was this contact verified by this device?
        var verified: Bool {
            let encryptedOwner = self.contacts.first?.contactPublicKeys.first?.owner
            let decryptedOwnerHash = try? Manager.Crypto().decrypt(data: encryptedOwner)
            let ourIdentity = try? Manager.Key().retrieveIdentity()
            let ourIdentityHash = ourIdentity?.sha256
            
            guard
                let decryptedOwnerHash, let ourIdentityHash,
                decryptedOwnerHash.isEmpty == false, ourIdentityHash.isEmpty == false
            else {
                return false
            }
            
            return ourIdentityHash == decryptedOwnerHash
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
        @State private var displayingVerificationInfo : Bool = false
        
        var body: some View {
            VStack {
                ScrollView {
                    VStack(spacing: 20) {
                        Contact.Info(identifier: self.identifier)
                        
                        if self.needsExchange {
                            KeyExchange(identifier: self.identifier)
                        } else {
                            Encrypt(identifier: self.identifier)
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
                        Contact.Form(mode: .edit(identifier: self.identifier)) {
                            self.dismiss()
                        }
                    }
                }
                .scrollIndicators(.hidden)
                .scrollDismissesKeyboard(.interactively)
                
                if self.verified == false && self.needsExchange == false {
                    VStack {
                        HStack(alignment: .firstTextBaseline) {
                            Button {
                                self.displayingVerificationInfo.toggle()
                            } label: {
                                Image(systemName: "info.bubble")
                            }
                            
                            Text("This contact's key is not verified.")
                                .font(.footnote)
                                .multilineTextAlignment(.center)
                                .foregroundStyle(.yellow)
                        }
                        .padding()
                        
                        if self.displayingVerificationInfo {
                            Text("Not being verified means that this contact was shared with you or transferred from another device. You can encrypt data for the contact, but since we did not do the key exchange on this device, we cannot guarantee who the owner of the key is. In the future, when this contact is in vicinity, revoke this key in the **Edit** mode and do another key exchange to verify identity.")
                                .font(.caption)
                                .padding()
                        }
                    }
                }
                
                VStack {
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
    }
}



#Preview {
    Contact.Details(identifier: UUID().uuidString)
        .environment(ContactManager.preview)
}
