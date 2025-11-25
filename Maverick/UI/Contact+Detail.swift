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
    
    /// First name of the contact
    var name: String {
        "\(self.contacts.first?.givenName ?? "Unknown")"
    }
    /// Phone number of the contact
    var phone: String {
        self.contacts.first?.phoneNumbers.first?.value ?? "No phone number"
    }
    /// Email of the contact
    var email: String {
        self.contacts.first?.emailAddresses.first?.value ?? "No email"
    }
    /// If we do not have a public key from our contact, we need to start an exchange.
    var needsExchange: Bool {
        self.contacts.first?.contactPublicKey == nil
    }
    
    init(identifier: String) {
        self.identifier = identifier
        
        let predicate = #Predicate<Contact> {
            $0.identifier == identifier
        }
        
        self._contacts = Query(filter: predicate)
    }
    
    var body: some View {
        if self.needsExchange {
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
                    Text("To begin communicating with \(self.name), first, you'll need to exchange keys. To facilitate a secure exchange, bring your phones together after pressing the **Exchange Keys** button on both devices.")
                        .padding()
                    
                    HStack {
                        Button {
                            
                        } label: {
                            HStack {
                                Text("Exchange Keys")
                                Image(systemName: "key.horizontal")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        
                        Image(systemName: "info.bubble")
                    }
                }
            }
        } else {
            
        }
    }
}

struct ExchangeDisclaimer: View {
    var body: some View {
        
    }
}

#Preview {
    ContactDetail(identifier: UUID().uuidString)
}
