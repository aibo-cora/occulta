//
//  ContactFormView.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//


import SwiftUI
import PhotosUI // For photo picker

struct ContactFormView: View {
    @Binding var contact: ContactDraft
    
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var showingAddPhoneSheet = false
    @State private var showingAddEmailSheet = false
    @State private var showingAddAddressSheet = false
    @State private var showingAddURLSheet = false
    
    var body: some View {
        Form {
            // MARK: - Profile Photo & Name
            Section {
                HStack {
                    Spacer()
                    PhotosPicker(selection: $selectedPhotoItem, matching: .images) {
                        if let imageData = contact.imageData,
                           let uiImage = UIImage(data: imageData) {
                            Image(uiImage: uiImage)
                                .resizable()
                                .scaledToFill()
                                .frame(width: 100, height: 100)
                                .clipShape(Circle())
                        } else {
                            Image(systemName: "person.crop.circle.fill")
                                .font(.system(size: 80))
                                .foregroundStyle(.gray.opacity(0.6))
                        }
                    }
                    .onChange(of: selectedPhotoItem) { _, newItem in
                        Task {
                            if let data = try? await newItem?.loadTransferable(type: Data.self) {
                                contact.imageData = data
                                // Generate thumbnail
                                if let image = UIImage(data: data),
                                   let thumbnail = image.preparingThumbnail(of: CGSize(width: 120, height: 120)) {
                                    contact.thumbnailImageData = thumbnail.jpegData(compressionQuality: 0.8)
                                }
                            }
                        }
                    }
                    Spacer()
                }
                .listRowBackground(Color.clear)
            }
            
            Section {
                TextField("First name", text: $contact.givenName)
                TextField("Last name", text: $contact.familyName)
                TextField("Middle name", text: $contact.middleName)
                TextField("Prefix", text: $contact.namePrefix)
                    .autocapitalization(.words)
                TextField("Suffix", text: $contact.nameSuffix)
                    .autocapitalization(.words)
                TextField("Nickname", text: $contact.nickname)
            } header: {
                Text("Name")
            }
            
            Section {
                TextField("Company", text: $contact.organizationName)
                TextField("Department", text: $contact.departmentName)
                TextField("Job title", text: $contact.jobTitle)
            } header: {
                Text("Company")
            }
            
            // MARK: - Phone Numbers
            Section {
                ForEach(contact.phoneNumbers.indices, id: \.self) { i in
                    HStack {
                        Text(contact.phoneNumbers[i].label)
                            .foregroundStyle(.secondary)
                            .frame(width: 100, alignment: .leading)
                        Text(contact.phoneNumbers[i].value)
                            .foregroundStyle(contact.phoneNumbers[i].value.isEmpty ? .secondary : .primary)
                    }
                }
                .onDelete { contact.phoneNumbers.remove(atOffsets: $0) }
                
                Button("Add phone") {
                    showingAddPhoneSheet = true
                }
                .foregroundStyle(.blue)
            } header: {
                Text("Phone")
            }
            .sheet(isPresented: $showingAddPhoneSheet) {
                AddPhoneSheet { label, number in
                    contact.phoneNumbers.append(PhoneNumberDraft(label: label, value: number))
                }
            }
            
            // MARK: - Email Addresses
            Section {
                ForEach(contact.emailAddresses.indices, id: \.self) { i in
                    HStack {
                        Text(contact.emailAddresses[i].label)
                            .foregroundStyle(.secondary)
                            .frame(width: 100, alignment: .leading)
                        Text(contact.emailAddresses[i].value)
                            .foregroundStyle(contact.emailAddresses[i].value.isEmpty ? .secondary : .primary)
                    }
                }
                .onDelete { contact.emailAddresses.remove(atOffsets: $0) }
                
                Button("Add email") {
                    showingAddEmailSheet = true
                }
                .foregroundStyle(.blue)
            } header: {
                Text("Email")
            }
            .sheet(isPresented: $showingAddEmailSheet) {
                AddEmailSheet { label, email in
                    contact.emailAddresses.append(EmailAddressDraft(label: label, value: email))
                }
            }
            
            // MARK: - Postal Addresses
            Section {
                ForEach(contact.postalAddresses.indices, id: \.self) { i in
                    let addr = contact.postalAddresses[i]
                    VStack(alignment: .leading, spacing: 4) {
                        Text(addr.label).font(.subheadline).foregroundStyle(.secondary)
                        if !addr.street.isEmpty { Text(addr.street) }
                        if !addr.city.isEmpty || !addr.state.isEmpty {
                            Text([addr.city, addr.state, addr.postalCode]
                                .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", "))
                        }
                        if !addr.country.isEmpty { Text(addr.country) }
                    }
                }
                .onDelete { contact.postalAddresses.remove(atOffsets: $0) }
                
                Button("Add address") {
                    showingAddAddressSheet = true
                }
                .foregroundStyle(.blue)
            } header: {
                Text("Address")
            }
            .sheet(isPresented: $showingAddAddressSheet) {
                AddAddressSheet { newAddress in
                    contact.postalAddresses.append(newAddress)
                }
            }
            
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
                    contact.urlAddresses.append(URLAddressDraft(label: label, value: url))
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

struct AddPhoneSheet: View {
    @Environment(\.dismiss) var dismiss
    var onAdd: (String, String) -> Void
    
    @State private var label = "mobile"
    @State private var number = ""
    
    let labels = ["mobile", "home", "work", "main", "home fax", "work fax", "pager", "other"]
    
    var body: some View {
        NavigationStack {
            Form {
                Picker("Label", selection: $label) {
                    ForEach(labels, id: \.self) { Text($0).tag($0) }
                }
                TextField("Phone number", text: $number)
                    .keyboardType(.phonePad)
            }
            .navigationTitle("Add Phone")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        onAdd(label, number)
                        dismiss()
                    }
                    .disabled(number.isEmpty)
                }
            }
        }
    }
}

struct AddEmailSheet: View {
    @Environment(\.dismiss) var dismiss
    var onAdd: (String, String) -> Void
    
    @State private var label = "home"
    @State private var email = ""
    
    let labels = ["home", "work", "iCloud", "other"]
    
    var body: some View {
        NavigationStack {
            Form {
                Picker("Label", selection: $label) {
                    ForEach(labels, id: \.self) { Text($0).tag($0) }
                }
                TextField("Email", text: $email)
                    .keyboardType(.emailAddress)
                    .autocapitalization(.none)
            }
            .navigationTitle("Add Email")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        onAdd(label, email)
                        dismiss()
                    }
                    .disabled(email.isEmpty)
                }
            }
        }
    }
}

struct AddAddressSheet: View {
    @Environment(\.dismiss) var dismiss
    var onAdd: (PostalAddressEntryDraft) -> Void
    
    @State private var label = "home"
    @State private var street = ""
    @State private var city = ""
    @State private var state = ""
    @State private var postalCode = ""
    @State private var country = ""
    
    let labels = ["home", "work", "other"]
    
    var body: some View {
        NavigationStack {
            Form {
                Picker("Label", selection: $label) {
                    ForEach(labels, id: \.self) { Text($0).tag($0) }
                }
                
                TextField("Street", text: $street)
                TextField("City", text: $city)
                TextField("State / Province", text: $state)
                TextField("ZIP / Postal Code", text: $postalCode)
                TextField("Country", text: $country)
            }
            .navigationTitle("Add Address")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        let address = PostalAddressEntryDraft(
                            label: label,
                            street: street,
                            city: city,
                            state: state,
                            postalCode: postalCode,
                            country: country,
                            isoCountryCode: ""
                        )
                        onAdd(address)
                        dismiss()
                    }
                }
            }
        }
    }
}

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
        ContactFormView(contact: .constant(ContactDraft(
            identifier: UUID().uuidString,
            givenName: "Taylor",
            familyName: "Swift",
            phoneNumbers: [PhoneNumberDraft(label: "mobile", value: "+1 (555) 1989")]
        )))
    }
}
