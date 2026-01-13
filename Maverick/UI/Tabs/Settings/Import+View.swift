//
//  Import+View.swift
//  Maverick
//
//  Created by Yura on 12/15/25.
//

import SwiftUI
internal import UniformTypeIdentifiers

struct Import: View {
    let imported: OwnedBasket
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    @Environment(\.dismiss) private var dismiss
    
    struct DisplayImportedContactList: View {
        let files: [File]
        let sharedContacts: [Contact.Draft]
        
        @State private var selectedContacts: [Contact.Draft] = []
        
        @Environment(ContactManager.self) private var contactManager: ContactManager
        @Environment(\.dismiss) private var dismiss
        
        init(files: [File]) {
            self.files = files
            
            var shared: [Contact.Draft] = []
            
            for file in self.files {
                let fileContent = file.content ?? Data()
                let contacts = (try? JSONDecoder().decode([Contact.Draft].self, from: fileContent)) ?? []
                
                shared.append(contentsOf: contacts)
            }
            
            self.sharedContacts = shared
        }
        
        private struct Info: View {
            let contact: Contact.Draft
            
            @State private var isDuplicate: Bool = false
            
            var body: some View {
                HStack(spacing: 20) {
                    Photo(contact: self.contact)
                    
                    VStack(alignment: .leading) {
                        Text(self.contact.fullName)
                            .font(.headline)
                        
                        ForEach(self.contact.emailAddresses) { email in
                            Text(email.value)
                                .font(.footnote)
                        }
                        
                        ForEach(self.contact.phoneNumbers) { phone in
                            Text(phone.value)
                                .font(.footnote)
                        }
                    }
                }
            }
            
            private struct Photo: View {
                let contact: Contact.Draft
                
                var body: some View {
                    Group {
                        if let imageData = self.contact.imageData, let uiImage = UIImage(data: imageData) {
                            Image(uiImage: uiImage)
                                .resizable()
                                .aspectRatio(contentMode: .fit)
                        } else {
                            Image(systemName: "person.fill")
                                .resizable()
                                .aspectRatio(contentMode: .fit)
                        }
                    }
                    .frame(width: 50, height: 50)
                    .clipShape(Circle())
                    .overlay(
                        Circle()
                            .strokeBorder(Color.gray.opacity(0.5), lineWidth: 2)
                    )
                }
            }
        }
        
        private struct Checkmark: View {
            let contact: Contact.Draft
            
            @Binding var selectedContacts: [Contact.Draft]
            
            var body: some View {
                ZStack {
                    Circle()
                        .strokeBorder(Color.gray.opacity(0.5), lineWidth: 2)
                        .frame(width: 24, height: 24)
                    
                    if self.selectedContacts.contains(where: { $0.identifier == self.contact.identifier }) {
                        Circle()
                            .fill(Color.blue)
                            .frame(width: 24, height: 24)
                            .overlay {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(.white)
                                    .font(.system(size: 14, weight: .bold))
                            }
                    }
                }
            }
        }
        
        private func toggleSelection(contact: Contact.Draft) {
            if self.selectedContacts.contains(where: { $0.identifier == contact.identifier }) {
                self.selectedContacts.removeAll(where: { $0.identifier == contact.identifier })
            } else {
                self.selectedContacts.append(contact)
            }
        }
        
        var body: some View {
            VStack {
                if self.sharedContacts.isEmpty {
                    EmptyView()
                } else {
                    VStack(spacing: 20) {
                        Text("Select the ones you want to import.")
                            .foregroundStyle(.secondary)
                        
                        HStack {
                            Text("")
                            
                            Spacer()
                            
                            Group {
                                if self.sharedContacts.count == self.selectedContacts.count {
                                    Button {
                                        self.selectedContacts.removeAll()
                                    } label: {
                                        Text("Reset")
                                    }
                                } else {
                                    Button {
                                        self.selectedContacts.append(contentsOf: self.sharedContacts)
                                    } label: {
                                        Text("Select All")
                                    }
                                }
                            }
                            .padding(.horizontal)
                        }
                        
                        VStack(spacing: 20) {
                            ForEach(self.sharedContacts, id: \.identifier) { contact in
                                let _ = self.selectedContacts.contains(where: { $0.identifier == contact.identifier })
                                
                                Button {
                                    self.toggleSelection(contact: contact)
                                } label: {
                                    HStack {
                                        Info(contact: contact)
                                        
                                        Spacer()
                                        
                                        Checkmark(contact: contact, selectedContacts: self.$selectedContacts)
                                    }
                                    .contentShape(Rectangle())
                                    .padding(10)
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                        .padding(.horizontal)
                    }
                    
                    if self.sharedContacts.isEmpty == false {
                        Button {
                            do {
                                try self.contactManager.save(contacts: self.selectedContacts)
                            } catch {
                                debugPrint("Could not import contacts: \(error)")
                            }
                            self.dismiss()
                        } label: {
                            Text("Import")
                        }
                        .prominentButtonStyle()
                        .disabled(self.selectedContacts.isEmpty)
                    }
                }
            }
        }
    }
    
    struct DisplayImportedDocumentList: View {
        let files: [File]
        
        var body: some View {
            ForEach(self.files) { file in
                switch file.format {
                case .file(let metadata):
                    let filename = [metadata.name, metadata.extension].compactMap { $0 }.joined(separator: ".")
                    
                    if let fileContents = file.content {
                        VStack(spacing: 20) {
                            HStack {
                                Text("Received File")
                                    .bold()
                                
                                Text(filename)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            
                            ShareLink(item: FileTransferable(data: fileContents, fileName: filename), preview: SharePreview(Text(filename), image: Image(systemName: "doc.fill"))) {
                                Label("Export File", systemImage: "square.and.arrow.up")
                            }
                        }
                    }
                default:
                    EmptyView()
                }
            }
        }
    }
    
    struct DisplayImportedMessageList: View {
        let files: [File]
        
        var body: some View {
            ForEach(self.files) { file in
                let message = String(data: file.content ?? Data(), encoding: .utf8)
                
                if let message {
                    VStack(spacing: 20) {
                        Text(message)
                    }
                } else {
                    EmptyView()
                }
            }
        }
    }
    
    var dateFormatter: DateFormatter {
        let formatter = DateFormatter()
        
        formatter.dateStyle = .long
        formatter.timeStyle = .long
        
        return formatter
    }
    
    @State private var isContactListExpanded: Bool = true
    @State private var isMessageListExpanded: Bool = true
    @State private var isDocumentListExpanded: Bool = true
    
    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(spacing: 20) {
                    if self.imported.owner.isEmpty {
                        /// We don't know who the owner of the basket is.
                        HStack(alignment: .firstTextBaseline) {
                            Text("The owner of this basket is **unknown**.")
                            
                            Button {
                                
                            } label: {
                                Image(systemName: "info.bubble")
                            }

                        }
                    } else {
                        Contact.Info(identifier: self.imported.owner)
                        
                        Text("Your contact wants to share with you.")
                            .multilineTextAlignment(.center)
                    }
                    
                    Divider()
                    
                    let filesContainingContacts = self.imported.basket.files.filter { $0.format == .contacts }
                    let filesContainingMessages = self.imported.basket.files.filter { $0.format == .text }
                    let filesContainingDocuments = self.imported.basket.files.filter { Set(filesContainingContacts + filesContainingMessages).contains($0) == false }
                    
                    Group {
                        let date = self.dateFormatter.string(from: self.imported.basket.date ?? .now)
                        
                        Text("This basket was created on:")
                        Text(date)
                        
                        Divider()
                    }
                    
                    Group {
                        if filesContainingContacts.isEmpty == false {
                            DisclosureGroup("Contacts", isExpanded: self.$isContactListExpanded) {
                                DisplayImportedContactList(files: filesContainingContacts)
                            }
                        }
                        
                        if filesContainingDocuments.isEmpty == false {
                            DisclosureGroup("Documents", isExpanded: self.$isDocumentListExpanded) {
                                DisplayImportedDocumentList(files: filesContainingDocuments)
                            }
                        }
                        
                        if filesContainingMessages.isEmpty == false {
                            DisclosureGroup("Messages", isExpanded: self.$isMessageListExpanded) {
                                DisplayImportedMessageList(files: filesContainingMessages)
                            }
                        }
                    }
                    .padding()
                }
            }
            .scrollIndicators(.hidden)
        }
    }
}

#Preview {
    let contacts: [Contact.Draft] = [
        .init(identifier: UUID().uuidString,
              givenName: "Alex",
              phoneNumbers: [.init(label: "Work", value: "555-1234"), .init(label: "Home", value: "555-5678")],
              emailAddresses: [.init(label: "Work", value: "alex@example.com"), .init(label: "Home", value: "home@example.com")]),
        .init(identifier: UUID().uuidString, givenName: "Max", phoneNumbers: [.init(label: "Work", value: "555-1234"), .init(label: "Home", value: "555-5678")],
              emailAddresses: [.init(label: "Work", value: "max@example.com"), .init(label: "Home", value: "home@example.com")]),
        .init(identifier: UUID().uuidString, givenName: "Sam", phoneNumbers: [.init(label: "Work", value: "555-1234"), .init(label: "Home", value: "555-5678")],
              emailAddresses: [.init(label: "Work", value: "sam@example.com"), .init(label: "Home", value: "home@example.com")])
    ]
    let encoded = try? JSONEncoder().encode(contacts)
    let file = File(content: encoded, format: .contacts)
    let messageFile = File(content: "I will think about it tomorrow, Rhett. There is nothing more important that this. ".data(using: .utf8), format: .text)
    let basket = Basket(files: [file, messageFile])
    
    Import(imported: OwnedBasket(basket: basket, owner: ""))
        .environment(ContactManager.preview)
}

#Preview {
    let contacts: [Contact.Draft] = [
        .init(identifier: UUID().uuidString,
              givenName: "Alex",
              phoneNumbers: [.init(label: "Work", value: "555-1234"), .init(label: "Home", value: "555-5678")],
              emailAddresses: [.init(label: "Work", value: "alex@example.com"), .init(label: "Home", value: "home@example.com")]),
        .init(identifier: UUID().uuidString, givenName: "Max", phoneNumbers: [.init(label: "Work", value: "555-1234"), .init(label: "Home", value: "555-5678")],
              emailAddresses: [.init(label: "Work", value: "max@example.com"), .init(label: "Home", value: "home@example.com")]),
        .init(identifier: UUID().uuidString, givenName: "Sam", phoneNumbers: [.init(label: "Work", value: "555-1234"), .init(label: "Home", value: "555-5678")],
              emailAddresses: [.init(label: "Work", value: "sam@example.com"), .init(label: "Home", value: "home@example.com"), .init(label: "Work", value: "sam@example.com"), .init(label: "Home", value: "home@example.com")])
    ]
    let encoded = try? JSONEncoder().encode(contacts)
    let file = File(content: encoded, format: .contacts)
    
    Import.DisplayImportedContactList(files: [file])
        .environment(ContactManager.preview)
}
