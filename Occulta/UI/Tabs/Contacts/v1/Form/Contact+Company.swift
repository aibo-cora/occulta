//
//  Contact+Organization.swift
//  Occulta
//
//  Created by Yura on 12/3/25.
//

import SwiftUI

extension Contact {
    struct Company: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            TextField("Company", text: self.$contact.organizationName)
                .autocorrectionDisabled()
            TextField("Department", text: self.$contact.departmentName)
                .autocorrectionDisabled()
            TextField("Job title", text: self.$contact.jobTitle)
                .autocorrectionDisabled()
        }
    }
}

#Preview {
    Contact.Company(contact: .constant(Contact.Draft(identifier: UUID().uuidString)))
}
