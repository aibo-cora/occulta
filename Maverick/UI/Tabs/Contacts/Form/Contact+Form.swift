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
            
            // MARK: - URLs
            Section {
                ForEach(contact.urlAddresses.indices, id: \.self) { i in
                    HStack {
                        Text(contact.urlAddresses[i].label)
                            .foregroundStyle(.secondary)
                            .frame(width: 100, alignment: .leading)
                        Text(contact.urlAddresses[i].value)
                    }
                }
                .onDelete { contact.urlAddresses.remove(atOffsets: $0) }
                
                Button("Add URL") {
                    showingAddURLSheet = true
                }
                .foregroundStyle(.blue)
            } header: {
                Text("URL")
            }
            .sheet(isPresented: $showingAddURLSheet) {
                AddURLSheet { label, url in
                    contact.urlAddresses.append(Contact.Draft.URLAddress(label: label, value: url))
                }
            }
            
            // MARK: - Birthday & Notes
            Section {
                DatePicker("Birthday", selection: Binding(
                    get: { contact.birthday ?? Date() },
                    set: { contact.birthday = $0 }
                ), displayedComponents: .date)
                .foregroundStyle(contact.birthday == nil ? .secondary : .primary)
                
                TextField("Add note", text: $contact.note, axis: .vertical)
                    .lineLimit(4...)
            }
        }
        .navigationTitle(contact.fullName.isEmpty ? "New Contact" : contact.fullName)
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Helper Sheets

struct AddURLSheet: View {
    @Environment(\.dismiss) var dismiss
    var onAdd: (String, String) -> Void
    
    @State private var label = "homepage"
    @State private var url = ""
    
    let labels = ["homepage", "work", "twitter", "facebook", "other"]
    
    var body: some View {
        NavigationStack {
            Form {
                Picker("Label", selection: $label) {
                    ForEach(labels, id: \.self) { Text($0).tag($0) }
                }
                TextField("URL", text: $url)
                    .keyboardType(.URL)
                    .autocapitalization(.none)
            }
            .navigationTitle("Add URL")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        onAdd(label, url)
                        dismiss()
                    }
                    .disabled(url.isEmpty)
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
