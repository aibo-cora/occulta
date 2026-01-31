//
//  ContactFormView.swift
//  Occulta
//
//  Created by Yura on 12/2/25.
//


import SwiftUI
import PhotosUI

extension Contact {
    struct Form: View {
        @State var contact: Contact.Draft
        @State private var selectedPhotoItem: PhotosPickerItem?
        
        @Environment(\.dismiss) private var dismiss
        @Environment(ContactManager.self) private var contactManager: ContactManager
        
        enum Mode {
            /// Create a new contact.
            case create
            /// We are editing an existing contact. The identifier is encrypted.
            case edit(identifier: String)
        }
        
        let mode: Mode
        var onDismiss: (() -> Void)?
        
        init(mode: Mode, onDismiss: (() -> Void)? = nil) {
            switch mode {
            case .create:
                self.contact = .init(identifier: UUID().uuidString)
            case .edit(let identifier):
                self.contact = .init(identifier: identifier)
            }
            
            self.mode = mode
            self.onDismiss = onDismiss
        }
        
        @State private var displayingRevokeKeyWarning: Bool = false
        @State private var displayingDeleteWarning: Bool = false
        
        var body: some View {
            NavigationStack {
                SwiftUI.Form {
                    Section {
                        HStack {
                            Spacer()
                            
                            Contact.Photo(contact: self.$contact)
                            
                            Spacer()
                        }
                        .listRowBackground(Color.clear)
                    }
                    
                    Section {
                        Contact.Name(contact: self.$contact)
                    } header: {
                        Text("Name")
                    }
                    
                    Section {
                        Contact.Company(contact: self.$contact)
                    } header: {
                        Text("Company")
                    }
                    
                    Contact.Phone(contact: self.$contact)
                    
                    Contact.Email(contact: self.$contact)
                    
                    Contact.Address(contact: self.$contact)
                    
                    Contact.URLAddress(contact: self.$contact)
                    
                    // MARK: - Birthday, Multiple dates - Anniversary, graduation, christening, etc.
                    
                    if self.contact.birthday == nil {
                        Button {
                            withAnimation {
                                let now = self.contactManager.dateFormatter.string(from: Date())
                                self.contact.birthday = now
                            }
                        } label: {
                            Label("Add birthday", systemImage: "plus.circle.fill")
                                .foregroundColor(.blue)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .buttonStyle(.plain)
                        .padding()
                    } else {
                        Section {
                            HStack {
                                Button {
                                    self.contact.birthday = nil
                                } label: {
                                    Image(systemName: "minus.circle.fill")
                                        .foregroundColor(.red)
                                        .font(.title2)
                                }
                                .buttonStyle(.plain)
                                
                                DatePicker("Birthday", selection: Binding(
                                    get: {
                                        let now = self.contactManager.dateFormatter.string(from: Date())
                                        let date = self.contactManager.dateFormatter.date(from: self.contact.birthday ?? now)
                                        
                                        return date ?? Date()
                                    },
                                    set: {
                                        let date = self.contactManager.dateFormatter.string(from: $0)
                                        self.contact.birthday = date
                                    }
                                ), displayedComponents: .date)
                                .foregroundStyle(self.contact.birthday == nil ? .secondary : .primary)
                            }
                            .padding()
                        }
                    }
                    
                    Section("Note") {
                        TextField("Add note", text: self.$contact.note, axis: .vertical)
                            .lineLimit(4...)
                    }
                    
                    switch self.mode {
                    case .create:
                        EmptyView()
                    case .edit(let identifier):
                        Button("Revoke Key", systemImage: "key.horizontal.fill", role: .destructive) {
                            self.displayingRevokeKeyWarning.toggle()
                        }
                        .confirmationDialog("Warning", isPresented: self.$displayingRevokeKeyWarning) {
                            Button("Revoke", role: .destructive) {
                                try? self.contactManager.reset(identity: identifier)
                            }
                        } message: {
                            Text("A new key exchange needs to happen after revoking this contact's public key. Are you sure?")
                        }
                        
                        Button("Delete Contact", systemImage: "trash.fill", role: .destructive) {
                            self.displayingDeleteWarning.toggle()
                        }
                        .confirmationDialog("Delete Contact", isPresented: self.$displayingDeleteWarning) {
                            Button("Delete", role: .destructive) {
                                try? self.contactManager.deleteContact(identifier: identifier)
                                
                                self.dismiss()
                                self.onDismiss?()
                            }
                        } message: {
                            Text("Deleting all information for this contact is irreversible. Are you sure?")
                        }
                    }
                }
                .navigationTitle(self.contact.fullName.isEmpty ? "New Contact" : self.contact.fullName)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button(role: .cancel) {
                            self.dismiss()
                        } label: {
                            Text("Cancel")
                        }
                    }
                    
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            do {
                                debugPrint("Contact being saved...")
                                
                                try self.contactManager.save(contact: self.contact)
                                
                                self.dismiss()
                            } catch {
                                // TODO: Display a warning that a contact could not be saved
                                debugPrint("Countact is not saved, error: \(error)")
                            }
                        } label: {
                            Text("Save")
                        }
                    }
                }
                .scrollIndicators(.hidden)
            }
            .task {
                switch self.mode {
                    case .create:
                    break
                case .edit(let identifier):
                    do {
                        self.contact = try self.contactManager.convertToMutableCopy(using: identifier)
                    } catch {
                        debugPrint("Error converting to mutable copy, error = \(error)")
                    }
                    
                    debugPrint("Editing contact, id = \(identifier)")
                }
            }
        }
    }
}

// MARK: - Preview

#Preview {
    Contact.Form(mode: .create)
        .environment(ContactManager.preview)
}
