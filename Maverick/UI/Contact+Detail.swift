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
                
                Spacer()
            } else {
                Text("We have a key, let's start communicating!")
            }
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
