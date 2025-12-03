//
//  Contact+Organization.swift
//  Maverick
//
//  Created by Yura on 12/3/25.
//

import SwiftUI

extension Contact {
    struct Company: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            TextField("Company", text: self.$contact.organizationName)
            TextField("Department", text: self.$contact.departmentName)
            TextField("Job title", text: self.$contact.jobTitle)
        }
    }
}

#Preview {
    Contact.Company(contact: .constant(Contact.Draft(identifier: UUID().uuidString)))
}
