//
//  KeyExchange.swift
//  Occulta
//
//  Created by Yura on 11/25/25.
//

import SwiftData
import SwiftUI
import Combine

struct KeyExchange: View {
    @State private var exchangeManager: ExchangeManager = .init()
    @State private var displayingInfo: Bool = true
    
    @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
    
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    init(identifier: String) {
        let predicate = #Predicate<Contact.Profile> {
            $0.identifier == identifier
        }
        
        self._contacts = Query(filter: predicate)
    }
    
    /// First name of the contact
    var name: String {
        self.contacts.first?.givenName.decrypt() ?? "Anonymous"
    }
    
    var identifier: String {
        self.contacts.first?.identifier ?? ""
    }
    
    @State private var receivedIdentityKey: Contact.Draft.Key?
    
    var body: some View {
        if self.exchangeManager.inProgress {
            VStack {
                StartingSession(withContact: self.identifier)
                
                Button {
                    self.exchangeManager.finish()
                } label: {
                    Text("Cancel")
                }
                .buttonStyle(.borderedProminent)
            }
            .onReceive(self.exchangeManager.receivedIdentity) { received in
                if let contactsIdentity = received, let myIdentity = try? Manager.Key().retrieveIdentity() {
                    /// I am the owner of this key.
                    ///
                    print("Received identity: \(contactsIdentity), displaying result...")
                    
                    let date = String(Date.now.timeIntervalSince1970)
                    
                    self.receivedIdentityKey = Contact.Draft.Key(material: contactsIdentity, owner: myIdentity, date: date)
                }
            }
            .sheet(item: self.$receivedIdentityKey, onDismiss: {
                /// The session was already invalidated.
                self.exchangeManager.receivedIdentity.send(nil)
                self.exchangeManager.finish()
            }) { key in
                let (isDuplicate, owner) = self.checkDuplicate(key: key)
                
                if isDuplicate == false {
                    ExchangeResult(identifier: self.identifier, receivedKey: key)
                } else {
                    DuplicateKey(identifier: owner)
                }
            }
        } else {
            if self.exchangeManager.isExchangePossible {
                VStack {
                    if self.displayingInfo {
                        VStack {
                            Text("To begin communicating with **\(self.name)**, first, we need to exchange **public** keys.")
                                
                            Divider()
                            
                            VStack(alignment: .leading, spacing: 20) {
                                HStack {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.yellow)
                                    Text("Allow **Nearby Interaction** if prompted.")
                                }
                                
                                HStack {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.yellow)
                                    Text("Allow **Finding and Connecting** to devices on local network if prompted.")
                                }
                            }
                            
                            Divider()
                            
                            Text("Press **Exchange Keys** to start a secure session.")
                        }
                        .padding()
                    }
                    
                    HStack {
                        Button {
                            self.exchangeManager.start()
                        } label: {
                            HStack {
                                Text("Exchange Keys")
                                Image(systemName: "key.horizontal")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        
                        Button {
                            self.displayingInfo.toggle()
                        } label: {
                            Image(systemName: "info.bubble")
                        }
                        .padding(.leading, 20)
                    }
                }
            } else {
                Text("Key exchange is not supported by your device's hardware capabilities. Device must have UWB chip.")
                    .padding()
                    .foregroundStyle(.red)
            }
        }
    }
    
    private struct DuplicateKey: View {
        let owner: String
        
        @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
        
        @Environment(ContactManager.self) private var contactManager: ContactManager?
        
        init(identifier: String?) {
            let contactID = identifier ?? ""
            
            let predicate = #Predicate<Contact.Profile> {
                $0.identifier == contactID
            }
            
            self.owner = contactID
            self._contacts = Query(filter: predicate)
        }
        
        var body: some View {
            VStack(spacing: 20) {
                Text("A contact with this public key already exists. Only one key per contact is supported.")
                
                VStack(spacing: 20) {
                    Text("Contact with a matching key")
                    
                    Contact.Info(identifier: self.owner)
                }
            }
            .padding(.horizontal)
        }
    }
    
    /// Check the last active key of each contact against the key that we just go through exchange to make sure that we don't already have it to avoid confusion.
    ///
    /// Confusion can happen if multilpe contacts are added with the same public key.
    /// - Parameter key: Key from the exchange session.
    /// - Returns: Do we already have it?
    private func checkDuplicate(key: Contact.Draft.Key) -> (Bool, String?) {
        let cryptoOps = Manager.Crypto()
        let contacts = (try? self.contactManager?.fetchAllContacts()) ?? []
        
        for contact in contacts {
            if let publicKey = contact.contactPublicKeys?.last {
                /// We have a key.
                debugPrint("We found a contact with a key, contact = \(contact.givenName.decrypt())")
                
                if contact.contactPublicKeys?.last?.expiredOn == nil {
                    /// the key is active.
                    debugPrint("The last key is not expired")
                    
                    if let decrypted = try? cryptoOps.decrypt(data: publicKey.material), decrypted == key.material {
                        return (true, contact.identifier)
                    }
                }
            }
        }
        
        debugPrint("No duplicates found...")
        
        return (false, nil)
    }
}

#Preview {
    KeyExchange(identifier: UUID().uuidString)
}
