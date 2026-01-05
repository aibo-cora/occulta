//
//  Import+View.swift
//  Maverick
//
//  Created by Yura on 12/15/25.
//

import SwiftUI
internal import UniformTypeIdentifiers

struct Import: View {
    let imported: ImportedFile
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    @Environment(\.dismiss) private var dismiss
    
    struct SelectContacts: View {
        @Environment(ContactManager.self) private var contactManager: ContactManager
        @Environment(\.dismiss) private var dismiss
        
        let imported: ImportedFile
        
        @State private var sharedContacts: [Contact.Draft]
        @State private var selectedContacts: [Contact.Draft] = []
        
        init(imported: ImportedFile) {
            self.imported = imported
            
            let format = imported.file.format
            let fileContent = imported.file.content ?? Data()
            let file = (try? JSONDecoder().decode(File.self, from: fileContent)) ?? File(content: nil, format: .none)
            let shared = (try? JSONDecoder().decode([Contact.Draft].self, from: file.content ?? Data())) ?? []
                                                   
            switch format {
            case .contacts:
                if fileContent.isEmpty == false {
                    self._sharedContacts = State(initialValue: shared)
                } else {
                    self._sharedContacts = State(initialValue: [])
                }
            default:
                fatalError("Unhandled file format: \(String(describing: format))")
            }
        }
        
        private func toggleSelection(contact: Contact.Draft) {
            if self.selectedContacts.contains(where: { $0.identifier == contact.identifier }) {
                self.selectedContacts.removeAll(where: { $0.identifier == contact.identifier })
            } else {
                self.selectedContacts.append(contact)
            }
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
        
        var body: some View {
            VStack {
                if self.sharedContacts.isEmpty {
                    Text("There is nothing here")
                } else {
                    VStack {
                        ScrollView {
                            VStack(spacing: 20) {
                                Contact.Info(identifier: self.imported.owner)
                                
                                Text("Your contact wants to share other contacts with you.")
                                    .multilineTextAlignment(.center)
                                
                                Divider()
                                
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
                                        }
                                        .buttonStyle(.plain)
                                        .padding(30)
                                        .border(Color.gray)
                                        .shadow(radius: 5)
                                    }
                                }
                                .padding(.horizontal)
                            }
                        }
                        .scrollIndicators(.hidden)
                    }
                    
                    if self.selectedContacts.isEmpty == false {
                        Button {
                            do {
                                try self.contactManager.save(contacts: self.selectedContacts)
                            } catch {
                                debugPrint("Could not import contacts: \(error)")
                            }
                        } label: {
                            Text("Import")
                        }
                        .prominentButtonStyle()
                    }
                }
            }
        }
    }
    
    var body: some View {
        NavigationStack {
            switch self.imported.file.format {
            case .contacts:
                SelectContacts(imported: self.imported)
            case .text:
                let message = String(data: self.imported.file.content ?? Data(), encoding: .utf8)
                
                if let message {
                    VStack(spacing: 20) {
                        Contact.Info(identifier: self.imported.owner)
                        
                        Text(message)
                    }
                } else {
                    Text("This message is not meant for you.")
                        .task {
                            debugPrint("Owner: \(self.imported.owner)")
                        }
                }
            case .file(let metadata):
                let filename = [metadata.name, metadata.extension].compactMap { $0 }.joined(separator: ".")
                
                if let fileContents = self.imported.file.content {
                    VStack(spacing: 20) {
                        Contact.Info(identifier: self.imported.owner)
                     
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
            case .link:
                EmptyView()
            case .none:
                EmptyView()
            }
        }
    }
}

#Preview {
    Import(imported: ImportedFile(file: File(content: Data(), format: .contacts), owner: UUID().uuidString))
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
              emailAddresses: [.init(label: "Work", value: "sam@example.com"), .init(label: "Home", value: "home@example.com")])
    ]
    let encoded = try? JSONEncoder().encode(contacts)
    let file = File(content: encoded, format: .contacts)
    
    Import.SelectContacts(imported: ImportedFile(id: UUID(), file: file, owner: UUID().uuidString))
        .environment(ContactManager.preview)
}
