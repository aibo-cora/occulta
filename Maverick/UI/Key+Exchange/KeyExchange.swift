//
//  KeyExchange.swift
//  Maverick
//
//  Created by Yura on 11/25/25.
//

import SwiftData
import SwiftUI


struct KeyExchange: View {
    @State private var displayingInfo: Bool = false
    @State private var exchangeInProgress: Bool = false
    
    @Query(sort: \Contact.familyName) var contacts: [Contact]
    
    init(identifier: String) {
        let predicate = #Predicate<Contact> {
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
    
    var body: some View {
        if self.exchangeInProgress {
            VStack {
                StartingSession(withContact: self.identifier)
                
                Button {
                    self.exchangeInProgress.toggle()
                } label: {
                    Text("Cancel")
                }
                .buttonStyle(.borderedProminent)
            }
        } else {
            VStack {
                if self.displayingInfo {
                    Text("To begin communicating with \(self.name), first, you'll need to exchange keys. To facilitate a secure exchange, bring your phones together after pressing the **Exchange Keys** button on both devices.")
                        .padding()
                }
                
                HStack {
                    Button {
                        self.exchangeInProgress.toggle()
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
