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
    
    @Query(Contact.Profile.descriptor) var contacts: [Contact.Profile]
    
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    @Environment(\.dismiss) private var dismiss
    
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
    @State private var failureAlert: Bool = false

    var body: some View {
        Group {
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
                .onReceive(self.exchangeManager.completedExchange, perform: { quantumExchange in
                    let myIdentity = try? Manager.Key().retrieveIdentity()
                    
                    #if DEBUG
                    debugPrint("Received quantum exchange: \(String(describing: quantumExchange)), my identity = \(String(describing: myIdentity)), setting key.,.")
                    #endif
                    if let quantumExchange = quantumExchange, let myIdentity = myIdentity {
                        /// I am the owner of this key.
                        ///
                        print("Received identity: \(quantumExchange.peerP256PublicKey), with quantum material, displaying result...")
                        
                        let date = String(Date.now.timeIntervalSince1970)
                        let quantum = QuantumKeyMaterial(encapsulatedSecret: quantumExchange.mlkemSecret1, decapsulatedSecret: quantumExchange.mlkemSecret2, ourCiphertext: quantumExchange.ourCiphertext, peerCiphertext: quantumExchange.peerCiphertext)
                        
                        self.receivedIdentityKey = Contact.Draft.Key(material: quantumExchange.peerP256PublicKey, owner: myIdentity, date: date, quantumKeyMaterial: quantum)
                    }
                })
                .onReceive(self.contactManager?.contactKeyUpdated ?? PassthroughSubject<String, Never>(), perform: { identifier in
                    if identifier == self.identifier {
                        self.dismiss()
                    }
                })
                .onReceive(self.exchangeManager.exchangeFailed) { reason in
                    if reason == .uwbUnavailable {
                        self.failureAlert = true
                    }
                }
                .sheet(item: self.$receivedIdentityKey, onDismiss: {
                    self.exchangeManager.finish()
                }) { key in
                    let (isDuplicate, owner) = self.checkDuplicate(key: key)
                    
                    if isDuplicate == false {
                        ExchangeResult(identifier: self.identifier, receivedKey: key, exchangeResult: self.exchangeManager.completedExchange.value)
                            .environment(self.exchangeManager)
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
        .alert("Exchange couldn't complete", isPresented: self.$failureAlert) {
            Button("OK") { }
        } message: {
            Text("We couldn't measure the distance to your contact. This could mean Ultra Wideband isn't available right now.\n\nOn both devices, try:\n\n1. Settings → Privacy & Security → Location Services → System Services → toggle 'Networking & Wireless' off, then on\n2. Restart both devices\n3. Try the exchange again")
        }
    }
    
    private struct DuplicateKey: View {
        let owner: String
        
        @Query(Contact.Profile.descriptor) var contacts: [Contact.Profile]
        
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
