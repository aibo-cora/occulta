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
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
    @State private var creatingNewContact = false

    var body: some View {
        NavigationStack {
            VStack {
                BusinessCardContactsView(searchText: self.$searchText)
                    .navigationTitle("Contacts")
                    .toolbar {
                        ToolbarItem(placement: .navigationBarTrailing) {
                            Button {
                                self.creatingNewContact = true
                            } label: {
                                Image(systemName: "plus")
                            }
                        }
                    }
                
                // This will automatically show a contact if one is matched, or a Search button otherwise
                if #available(iOS 18.0, *) {
                    ContactAccessButton(queryString: self.searchText) { identifiers in
                        self.fetchContacts(with: identifiers)
                    }
                    .contactAccessButtonCaption(.phone)
                    .contactAccessButtonStyle(ContactAccessButton.Style(imageWidth: 30))
                    .padding()
                } else {
                    // Fallback on earlier versions
                }
            }
        }
        .sheet(isPresented: self.$creatingNewContact, onDismiss: {
            /// On dismiss
        }, content: {
            Contact.Form(mode: .create)
        })
    }

    /// Converts an array of contact identifiers into actual contacts
    func fetchContacts(with identifiers: [String]) {
        Task {
            let fetchRequest = CNContactFetchRequest(keysToFetch: self.contactManager.keys)
            
            fetchRequest.predicate = CNContact.predicateForContacts(withIdentifiers: identifiers)
            
            // Store new contacts in this array
            var newContacts = [CNContact]()

            try CNContactStore().enumerateContacts(with: fetchRequest) { contact, _ in
                newContacts.append(contact)
            }

            // Load is completed, so add the new contacts to our existing list
            try self.contactManager.createContacts(from: newContacts)
        }
    }
}

extension Contact.Profile {
    struct Card: View {
        @Binding var searchText: String
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
        
        var body: some View {
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
        }
    }
}

#Preview {
    Contacts()
        .environment(ContactManager.preview)
}

struct BusinessCardContactsView: View {
    /// Stored contacts.
    @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]

    /// Results from our existing contacts list
    var filteredContacts: [Contact.Profile] {
        if self.searchText.isEmpty {
            self.contacts.sorted {
                if $0.familyName.decrypt().isEmpty == false || $1.familyName.decrypt().isEmpty == false {
                    return $0.familyName.decrypt() < $1.familyName.decrypt()
                } else {
                    return $0.givenName.decrypt() < $1.givenName.decrypt()
                }
            }
        } else {
            self.contacts.filter {
                $0.givenName.decrypt().localizedStandardContains(self.searchText)
                || $0.familyName.decrypt().localizedStandardContains(self.searchText)
            }.sorted {
                if $0.familyName.decrypt().isEmpty == false || $1.familyName.decrypt().isEmpty == false {
                    return $0.familyName.decrypt() < $1.familyName.decrypt()
                } else {
                    return $0.givenName.decrypt() < $1.givenName.decrypt()
                }
            }
        }
    }
    
    @Binding private var searchText: String
    
    init(searchText: Binding<String>) {
        self._searchText = searchText
    }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(spacing: 20) {
                    ForEach(self.filteredContacts) { contact in
                        NavigationLink(value: contact.identifier) {
                            BusinessCard(identifier: contact.identifier)
                                .padding(.horizontal)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.vertical)
            }
            .searchable(text: self.$searchText, placement: .navigationBarDrawer(displayMode: .always), prompt: "Search contacts")
            .navigationTitle("Contacts")
            .navigationBarTitleDisplayMode(.large)
            .background(Color(.systemGroupedBackground))
            .navigationDestination(for: String.self) { identifier in
                Contact.Details(identifier: identifier)
            }
        }
    }
}

// MARK: - The actual beautiful business card

struct BusinessCard: View {
    /// Stored contacts.
    @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
    init(identifier: String) {
        let predicate = #Predicate<Contact.Profile> {
            $0.identifier == identifier
        }
        
        self._contacts = Query(filter: predicate)
    }
    
    var fullName: String {
        if let given = self.contacts.first?.givenName.decrypt(),
           let family = self.contacts.first?.familyName.decrypt() {
            return [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        }
        
        return ""
    }
    
    var thumbnail: Data? {
        self.contacts.first?.imageData?.decrypt() ?? self.contacts.first?.thumbnailImageData?.decrypt()
    }
    
    var body: some View {
        HStack(spacing: 20) {
            if let data = self.thumbnail,
               let uiImage = UIImage(data: data) {
                Image(uiImage: uiImage)
                    .resizable()
                    .scaledToFill()
                    .frame(width: 90, height: 90)
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            } else {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(LinearGradient(
                        colors: [.blue.opacity(0.6), .purple.opacity(0.6)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                    .frame(width: 90, height: 90)
                    .overlay(
                        Text(self.fullName.initials)
                            .font(.system(size: 32, weight: .bold, design: .rounded))
                            .foregroundColor(.white)
                    )
            }
            
            VStack(alignment: .leading, spacing: 8) {
                Text(self.fullName)
                    .font(.headline)
                    .fontWeight(.semibold)
                    .foregroundColor(.primary)
                
                if let job = self.contacts.first?.jobTitle.decrypt(), !job.isEmpty {
                    Text(job)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                if let company = self.contacts.first?.organizationName.decrypt(), !company.isEmpty {
                    Text(company)
                        .font(.subheadline)
                        .fontWeight(.medium)
                        .foregroundColor(.accentColor)
                }
                
                HStack(spacing: 16) {
                    if let phone = self.contacts.first?.phoneNumbers.first?.value.decrypt() {
                        Label(phone, systemImage: "phone.fill")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    if let email = self.contacts.first?.emailAddresses.first?.value.decrypt() as? String {
                        Label(email, systemImage: "envelope.fill")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .lineLimit(1)
            
            Spacer()
            
            Image(systemName: "chevron.right")
                .font(.system(size: 14, weight: .semibold))
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(.regularMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .strokeBorder(.quaternary.opacity(0.3), lineWidth: 1)
                )
                .shadow(color: .black.opacity(0.08), radius: 10, x: 0, y: 5)
        )
    }
}

extension String {
    var initials: String {
        let formatter = PersonNameComponentsFormatter()
        
        if let components = formatter.personNameComponents(from: self) {
            formatter.style = .abbreviated
            
            return formatter.string(from: components)
        }
        
        return String(prefix(2)).uppercased()
    }
}
