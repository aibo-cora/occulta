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
    
    init(identifier: String) {
        self.identifier = identifier
        
        let predicate = #Predicate<Contact> {
            $0.identifier == identifier
        }
        
        self._contacts = Query(filter: predicate)
    }
    
    var body: some View {
        Text("Hello, \(self.contacts.first?.givenName ?? "Unknown")!")
    }
}

#Preview {
    ContactDetail(identifier: UUID().uuidString)
}
