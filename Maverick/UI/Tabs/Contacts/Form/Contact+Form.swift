//
//  ContactFormView.swift
//  Maverick
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
        
        init(mode: Mode) {
            switch mode {
            case .create:
                self.contact = .init(identifier: UUID().uuidString)
            case .edit(let identifier):
                self.contact = .init(identifier: identifier)
            }
            
            self.mode = mode
        }
        
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
                                self.contact.birthday = Date()
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
                                    get: { self.contact.birthday ?? Date() },
                                    set: { self.contact.birthday = $0 }
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
