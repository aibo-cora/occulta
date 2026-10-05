//
//  Contact+Name.swift
//  Occulta
//
//  Created by Yura on 12/3/25.
//


import SwiftUI

extension Contact {
    struct Name: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            TextField("First name", text: self.$contact.givenName)
                .autocorrectionDisabled()
            TextField("Last name", text: self.$contact.familyName)
                .autocorrectionDisabled()
            TextField("Middle name", text: self.$contact.middleName)
                .autocorrectionDisabled()
            TextField("Prefix", text: self.$contact.namePrefix)
                .autocapitalization(.words)
                .autocorrectionDisabled()
            TextField("Suffix", text: self.$contact.nameSuffix)
                .autocapitalization(.words)
                .autocorrectionDisabled()
            TextField("Nickname", text: self.$contact.nickname)
                .autocorrectionDisabled()
        }
    }
}
