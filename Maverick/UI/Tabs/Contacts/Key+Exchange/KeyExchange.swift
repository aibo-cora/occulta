//
//  KeyExchange.swift
//  Maverick
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
                if let received {
                    print("Received identity: \(received), displaying result...")
                    /// I am the owner of this key.
                    let identity = (try? Manager.Key().retrieveIdentity()) ?? Data()
                    
                    self.receivedIdentityKey = Contact.Draft.Key(material: received, owner: identity)
                }
            }
            .sheet(item: self.$receivedIdentityKey, onDismiss: {
                /// The session was already invalidated.
                self.exchangeManager.receivedIdentity.send(nil)
                self.exchangeManager.finish()
            }) { key in
                ExchangeResult(identifier: self.identifier, receivedKey: key)
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
}

#Preview {
    KeyExchange(identifier: UUID().uuidString)
}
