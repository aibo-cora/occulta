//
//  Contacts.swift
//  Maverick
//
//  Created by Yura on 10/22/25.
//

import SwiftUI
import ContactsUI
import SwiftData

struct Contacts: View {
    /// Whatever the user is currently looking for
    @State private var searchText = ""
    
    @Environment(\.modelContext) private var modelContext
    
    @State private var contactManager: ContactManager?
    /// Stored contacts.
    @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]

    /// Results from our existing contacts list
    var filteredContacts: [Contact.Profile] {
        if self.searchText.isEmpty {
            self.contacts
        } else {
            self.contacts.filter {
                $0.givenName.decrypt().localizedStandardContains(self.searchText)
                || $0.familyName.decrypt().localizedStandardContains(self.searchText)
            }
        }
    }
    
    @State private var creatingNewContact = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                List(self.filteredContacts) { contact in
                    NavigationLink(value: contact.identifier) {
                        HStack {
                            if let thumbnail = contact.thumbnailImageData {
                                Image(uiImage: (UIImage(data: thumbnail) ?? UIImage()))
                                    .resizable()
                                    .frame(width: 50, height: 50)
                            } else {
                                Image(systemName: "person.circle.fill")
                                    .resizable()
                                    .frame(width: 50, height: 50)
                            }
                            
                            Text(contact.familyName.decrypt() + " " + contact.givenName.decrypt())
                        }
                    }
                }
                .searchable(text: self.$searchText, prompt: "Search Contacts")
                .navigationDestination(for: String.self) {
                    ContactDetail(identifier: $0)
                }
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button {
                            self.creatingNewContact = true
                        } label: {
                            Image(systemName: "plus")
                        }
                    }
                }
                .sheet(isPresented: self.$creatingNewContact, onDismiss: {
                    /// On dismiss
                }, content: {
                    ContactForm(mode: .create)
                })

                // This will automatically show a contact if one is matched, or a Search button otherwise
                ContactAccessButton(queryString: self.searchText) { identifiers in
                    self.fetchContacts(with: identifiers)
                }
                .contactAccessButtonCaption(.phone)
                .contactAccessButtonStyle(ContactAccessButton.Style(imageWidth: 30))
                .padding()
            }
            .navigationTitle("Contacts")
        }
        .task {
            self.contactManager = ContactManager(modelContainer: self.modelContext.container)
        }
        .environment(self.contactManager)
    }
    /// Prepare the Contacts system to return the names of matching people
    let keys = [
        CNContactFormatter.descriptorForRequiredKeys(for: .fullName),
        CNContactIdentifierKey as any CNKeyDescriptor,
        CNContactGivenNameKey as any CNKeyDescriptor,
        CNContactFamilyNameKey as any CNKeyDescriptor,
        CNContactMiddleNameKey as any CNKeyDescriptor,
        CNContactImageDataKey as any CNKeyDescriptor,
        CNContactImageDataAvailableKey as any CNKeyDescriptor,
        CNContactThumbnailImageDataKey as any CNKeyDescriptor,
        CNContactEmailAddressesKey as CNKeyDescriptor,
        CNContactPhoneNumbersKey as CNKeyDescriptor,
        CNContactPostalAddressesKey as CNKeyDescriptor,
        CNContactUrlAddressesKey as CNKeyDescriptor,
        CNContactNamePrefixKey as CNKeyDescriptor,
        CNContactNameSuffixKey as CNKeyDescriptor,
        CNContactOrganizationNameKey as CNKeyDescriptor,
        CNContactDepartmentNameKey as CNKeyDescriptor,
        CNContactJobTitleKey as CNKeyDescriptor,
        CNContactNicknameKey as CNKeyDescriptor,
        CNContactBirthdayKey as CNKeyDescriptor,
    ]

    /// Converts an array of contact identifiers into actual contacts
    func fetchContacts(with identifiers: [String]) {
        Task {
            let fetchRequest = CNContactFetchRequest(keysToFetch: self.keys)
            
            fetchRequest.predicate = CNContact.predicateForContacts(withIdentifiers: identifiers)
            
            // Store new contacts in this array
            var newContacts = [CNContact]()

            try CNContactStore().enumerateContacts(with: fetchRequest) { contact, _ in
                newContacts.append(contact)
            }

            // Load is completed, so add the new contacts to our existing list
            try self.contactManager?.createContacts(from: newContacts)
        }
    }
}

#Preview {
    Contacts()
}
