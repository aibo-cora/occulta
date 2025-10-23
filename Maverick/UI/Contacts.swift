//
//  Contacts.swift
//  Maverick
//
//  Created by Yura on 10/22/25.
//

import SwiftUI
import ContactsUI

struct Contacts: View {
    /// We hold all our loaded contacts here
    @State private var allContacts = [CNContact]()

    /// Whatever the user is currently looking for
    @State private var searchText = ""

    /// Results from our existing contacts list
    var filteredContacts: [CNContact] {
        if self.searchText.isEmpty {
            self.allContacts
        } else {
            self.allContacts.filter {
                $0.givenName.localizedStandardContains(self.searchText)
                || $0.familyName.localizedStandardContains(self.searchText)
            }
        }
    }

    var body: some View {
//        NavigationStack {
//            VStack {
//                List(self.filteredContacts) { contact in
//                    HStack {
//                        if let thumbnail = contact.thumbnailImageData {
//                            Image(uiImage: UIImage(data: thumbnail) ?? UIImage())
//                                .resizable()
//                                .frame(width: 50, height: 50)
//                        }
//                        Text(contact.familyName + " " + contact.givenName)
//                    }
//                }
//                .searchable(text: self.$searchText)
//
//                // This will automatically show a contact if one is matched, or a Search button otherwise
//                ContactAccessButton(queryString: self.searchText) { results in
//                    self.fetchContacts(with: results)
//                }
//                .contactAccessButtonCaption(.phone)
//                .contactAccessButtonStyle(ContactAccessButton.Style(imageWidth: 30))
//                .padding()
//            }
//        }
        HStack {
            Image("lake-forest")
                .resizable()
                .aspectRatio(contentMode: .fill) // or .fill
                .frame(width: 100, height: 100) // Set desired size
                .clipShape(Circle())
                .overlay(Circle().stroke(.green, lineWidth: 4))
        }
    }

    /// Converts an array of contact identifiers into actual contacts
    func fetchContacts(with identifiers: [String]) {
        Task {
            // Prepare the Contacts system to return the names of matching people
            let keys = [
                CNContactFormatter.descriptorForRequiredKeys(for: .fullName),
                CNContactImageDataKey as any CNKeyDescriptor,
                CNContactImageDataAvailableKey as any CNKeyDescriptor,
                CNContactThumbnailImageDataKey as any CNKeyDescriptor
            ]
            
            let fetchRequest = CNContactFetchRequest(keysToFetch: keys)
            fetchRequest.predicate = CNContact.predicateForContacts(withIdentifiers: identifiers)

            // Store new contacts in this array
            var newContacts = [CNContact]()

            try CNContactStore().enumerateContacts(with: fetchRequest) { contact, _ in
                newContacts.append(contact)
            }

            // Load is completed, so add the new contacts to our existing array
            self.allContacts += newContacts
        }
    }
}

#Preview {
    Contacts()
}
