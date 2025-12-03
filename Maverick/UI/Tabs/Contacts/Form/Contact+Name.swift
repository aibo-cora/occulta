//
//  Contact+Name.swift
//  Maverick
//
//  Created by Yura on 12/3/25.
//


import SwiftUI

extension Contact {
    struct Name: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            TextField("First name", text: self.$contact.givenName)
            TextField("Last name", text: self.$contact.familyName)
            TextField("Middle name", text: self.$contact.middleName)
            TextField("Prefix", text: self.$contact.namePrefix)
                .autocapitalization(.words)
            TextField("Suffix", text: self.$contact.nameSuffix)
                .autocapitalization(.words)
            TextField("Nickname", text: self.$contact.nickname)
        }
    }
}
