//
//  ContactFormView.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//


import SwiftUI
import PhotosUI

struct ContactForm: View {
    @State var contact: Contact.Draft = .init(identifier: UUID().uuidString)
    
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var showingAddPhoneSheet = false
    @State private var showingAddEmailSheet = false
    @State private var showingAddAddressSheet = false
    @State private var showingAddURLSheet = false
    
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        Form {
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
                    
                } label: {
                    Text("Save")
                }
            }
        }
    }
}

// MARK: - Preview

#Preview {
    NavigationStack {
        ContactForm()
    }
}
