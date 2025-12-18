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
    @State private var displayingInfo: Bool = false
    
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
    @State var wordsMatch = false
    
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
            .onReceive(self.exchangeManager.receivedIdentity) { identity in
                if let identity {
                    print("Received identity: \(identity)")
                    
                    self.receivedIdentityKey = Contact.Draft.Key(material: identity)
                    /// We received a key. Stop the exchange.
                    self.exchangeManager.finish()
                }
            }
            .sheet(item: self.$receivedIdentityKey, onDismiss: {
                
            }) { key in
                ExchangeResult(identifier: self.identifier, receivedKeyingMaterial: key.material!)
            }
        } else {
            VStack {
                if self.displayingInfo {
                    Text("To begin communicating with \(self.name), first, you'll need to exchange keys. To facilitate a secure exchange, bring your phones together after pressing the **Exchange Keys** button on both devices.")
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
        }
    }
}

#Preview {
    KeyExchange(identifier: UUID().uuidString)
}
