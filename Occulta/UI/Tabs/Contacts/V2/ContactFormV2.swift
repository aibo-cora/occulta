//
//  ContactFormV2.swift
//  Occulta
//

import SwiftUI
import SwiftData
import PhotosUI

extension Contact {
    struct FormV2: View {
        enum Mode {
            case create
            case edit(identifier: String)
        }

        @State private var contact: Contact.Draft
        @State private var selectedPhotoItem: PhotosPickerItem?
        @State private var displayingRevokeKeyWarning = false
        @State private var displayingDeleteWarning = false
        @State private var isSensitive = false

        @Environment(\.dismiss)              private var dismiss
        @Environment(ContactManager.self)    private var contactManager
        @Environment(Manager.Security.self)  private var security

        @Query private var profiles: [Contact.Profile]

        let mode: Mode
        var onDismiss: (() -> Void)?

        init(mode: Mode = .create, onDismiss: (() -> Void)? = nil) {
            switch mode {
            case .create:
                self._contact  = State(initialValue: .init(identifier: UUID().uuidString))
                self._profiles = Query(filter: #Predicate { _ in false })
            case .edit(let identifier):
                self._contact  = State(initialValue: .init(identifier: identifier))
                self._profiles = Query(filter: #Predicate { $0.identifier == identifier })
            }
            self.mode      = mode
            self.onDismiss = onDismiss
        }

        private var isCreate: Bool {
            if case .create = self.mode { return true }
            
            return false
        }

        private var canSave: Bool {
            !self.contact.givenName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || !self.contact.familyName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }

        private var keyIsRevocable: Bool {
            guard case .edit = self.mode, let key = self.contact.contactPublicKeys.last else { return false }
            return key.expiredOn == nil
        }

        var body: some View {
            NavigationStack {
                ScrollView {
                    VStack(spacing: 24) {
                        PhotoSlotV2(contact: self.$contact, selectedPhotoItem: self.$selectedPhotoItem)

                        FormSectionV2(header: "IDENTITY") {
                            FormFieldRowV2(label: "GIVEN",  placeholder: "First name",   text: self.$contact.givenName)
                            Divider().padding(.leading, 76)
                            FormFieldRowV2(label: "FAMILY", placeholder: "Last name",    text: self.$contact.familyName)
                            Divider().padding(.leading, 76)
                            FormFieldRowV2(label: "ORG",    placeholder: "Organization", text: self.$contact.organizationName)
                        }

                        FormSectionV2(header: "CONTACT") {
                            PhoneSectionRowsV2(contact: self.$contact)
                            EmailSectionRowsV2(contact: self.$contact)
                        }

                        // No depth guard — isSensitive and setVisibility are depth-relative;
                        // hiding the section at depth > 0 is a tell with no security benefit.
                        // (Bug 60, same reasoning as Bug 57 for ContactClassification.)
                        FormSectionV2(header: "VISIBILITY") {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Private contact")
                                        .font(.system(size: 15))
                                    Text("Hidden in alternate view")
                                        .font(.system(size: 12))
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Toggle("", isOn: self.$isSensitive)
                                    .labelsHidden()
                                    .tint(Color.occultaDanger)
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                        }

                        if self.isCreate {
                            EncryptionCTAV2()

                            Text("You can save without a key — you just can't encrypt until you exchange one.")
                                .font(.system(size: 12))
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                        } else {
                            self.editOnlyActions
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 20)
                    .padding(.bottom, 20)
                }
                .background(Color(.systemGroupedBackground))
                .navigationTitle(self.isCreate ? "New Contact" : self.contact.fullName.isEmpty ? "Edit Contact" : self.contact.fullName)
                .navigationBarTitleDisplayMode(.large)
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Cancel", role: .cancel) { self.dismiss() }
                            .tint(Color.occultaAccent)
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Save") {
                            try? self.contactManager.save(contact: self.contact,
                                                          currentDepth: self.security.currentDepth)
                            try? self.security.setVisibility(for: self.contact.identifier,
                                                             isSensitive: self.isSensitive)
                            self.dismiss()
                        }
                        .tint(Color.occultaAccent)
                        .disabled(!self.canSave)
                    }
                }
                .onChange(of: selectedPhotoItem) { _, newItem in
                    Task {
                        guard let data = try? await newItem?.loadTransferable(type: Data.self) else { return }
                        
                        self.contact.imageData = data
                        
                        if let img   = UIImage(data: data),
                           let thumb = img.preparingThumbnail(of: CGSize(width: 120, height: 120)) {
                            self.contact.thumbnailImageData = thumb.jpegData(compressionQuality: 0.8)
                        }
                    }
                }
                .task {
                    guard case .edit(let identifier) = self.mode else { return }
                    if let mutable = try? self.contactManager.convertToMutableCopy(using: identifier) {
                        self.contact = mutable
                    }
                    self.isSensitive = self.security.isSensitive(identifier)
                }
            }
        }

        @ViewBuilder
        private var editOnlyActions: some View {
            if let profile = self.profiles.first {
                IdentityChallenge.VerifyIdentityButton(contact: profile)
            }

            Button(role: .destructive) {
                self.displayingRevokeKeyWarning = true
            } label: {
                Label("Revoke Key", systemImage: "key.horizontal.fill")
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .foregroundStyle(Color.occultaDanger)
            .confirmationDialog("Warning", isPresented: self.$displayingRevokeKeyWarning) {
                Button("Revoke", role: .destructive) {
                    try? self.contactManager.reset(identity: self.contact.identifier)
                }
            } message: {
                Text("A new key exchange needs to happen after revoking this contact's public key. Are you sure?")
            }
            .disabled(self.profiles.first?.contactPublicKeys?.last?.expiredOn != nil)

            if case .edit(let identifier) = self.mode {
                Button(role: .destructive) {
                    self.displayingDeleteWarning = true
                } label: {
                    Label("Delete Contact", systemImage: "trash.fill")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color(.secondarySystemGroupedBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Color.occultaDanger)
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
    }
}

// MARK: - Photo Slot

private struct PhotoSlotV2: View {
    @Binding var contact: Contact.Draft
    @Binding var selectedPhotoItem: PhotosPickerItem?

    var body: some View {
        PhotosPicker(selection: self.$selectedPhotoItem, matching: .images) {
            ZStack {
                Circle()
                    .fill(Color(.tertiarySystemFill))
                    .overlay(
                        Circle()
                            .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [4, 3]))
                            .foregroundStyle(Color.secondary)
                    )

                if let data = self.contact.thumbnailImageData, let img = UIImage(data: data) {
                    Image(uiImage: img).resizable().scaledToFill().clipShape(Circle())
                } else {
                    VStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 22, weight: .medium))
                            .foregroundStyle(.secondary)
                        Text("PHOTO")
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .frame(width: 92, height: 92)
        }
    }
}

// MARK: - Form Section

private struct FormSectionV2<Content: View>: View {
    let header: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(self.header)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .tracking(1.6)
                .padding(.leading, 4)
                .padding(.bottom, 6)

            VStack(spacing: 0) {
                self.content()
            }
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }
}

// MARK: - Field Row

private struct FormFieldRowV2: View {
    let label: String
    let placeholder: String
    @Binding var text: String

    var body: some View {
        HStack(spacing: 12) {
            Text(self.label)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(minWidth: 50, alignment: .leading)
            TextField(self.placeholder, text: self.$text)
                .tint(Color.occultaAccent)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }
}

// MARK: - Phone Rows

private struct PhoneSectionRowsV2: View {
    @Binding var contact: Contact.Draft

    var body: some View {
        if self.contact.phoneNumbers.isEmpty {
            addButtonV2(label: "add phone") { self.contact.phoneNumbers.append(.init()) }
        } else {
            ForEach($contact.phoneNumbers) { $phone in
                Divider().padding(.leading, 76)
                HStack(spacing: 12) {
                    removeButtonV2 { self.contact.phoneNumbers.removeAll { $0.id == phone.id } }
                    
                    Text("PHONE")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(minWidth: 50, alignment: .leading)
                    TextField("Phone number", text: $phone.value)
                        .keyboardType(.phonePad)
                        .textContentType(.telephoneNumber)
                        .tint(Color.occultaAccent)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 11)
            }
            if self.contact.phoneNumbers.count < 4 {
                Divider().padding(.leading, 76)
                
                addButtonV2(label: "add phone") { self.contact.phoneNumbers.append(.init()) }
            }
        }
    }
}

// MARK: - Shared row helpers

private func addButtonV2(label: String, action: @escaping () -> Void) -> some View {
    Button {
        withAnimation { action() }
    } label: {
        HStack(spacing: 10) {
            Image(systemName: "plus.circle.fill").foregroundStyle(Color.occultaAccent)
            Text(label)
                .font(.system(size: 11, weight: .regular, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }
    .buttonStyle(.plain)
}

private func removeButtonV2(action: @escaping () -> Void) -> some View {
    Button {
        withAnimation { action() }
    } label: {
        Image(systemName: "minus.circle.fill").foregroundStyle(.red)
    }
    .buttonStyle(.plain)
}

// MARK: - Email Rows

private struct EmailSectionRowsV2: View {
    @Binding var contact: Contact.Draft

    var body: some View {
        Divider().padding(.leading, 76)
        if self.contact.emailAddresses.isEmpty {
            addButtonV2(label: "add email") { self.contact.emailAddresses.append(.init()) }
        } else {
            ForEach(self.$contact.emailAddresses) { $email in
                HStack(spacing: 12) {
                    removeButtonV2 { self.contact.emailAddresses.removeAll { $0.id == email.id } }
                    
                    Text("EMAIL")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(minWidth: 50, alignment: .leading)
                    TextField("Email address", text: $email.value)
                        .keyboardType(.emailAddress)
                        .textContentType(.emailAddress)
                        .autocorrectionDisabled()
                        .tint(Color.occultaAccent)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 11)
                Divider().padding(.leading, 76)
            }
            
            if self.contact.emailAddresses.count < 4 {
                addButtonV2(label: "add email") { self.contact.emailAddresses.append(.init()) }
            }
        }
    }
}

// MARK: - Encryption CTA

private struct EncryptionCTAV2: View {
    var body: some View {
        HStack(spacing: 14) {
            RoundedRectangle(cornerRadius: 4)
                .strokeBorder(.white.opacity(0.6), lineWidth: 1.5)
                .frame(width: 44, height: 44)
                .overlay(Image(systemName: "key.horizontal.fill").foregroundStyle(.white.opacity(0.9)))

            VStack(alignment: .leading, spacing: 3) {
                Text("Exchange keys")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
                Text("scan · paste · or receive")
                    .font(.system(size: 11, weight: .regular, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.7))
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white.opacity(0.7))
        }
        .padding(16)
        .background(Color.occultaAccent)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .shadow(color: Color.occultaAccent.opacity(0.25), radius: 12, x: 0, y: 8)
    }
}

#Preview {
    let container = try! ModelContainer(
        for: Schema([AppLayerConfig.self, Contact.Profile.self,
                     Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
                     Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self,
                     Contact.Profile.Key.self]),
        configurations: [ModelConfiguration(isStoredInMemoryOnly: true)]
    )
    Contact.FormV2()
        .environment(ContactManager.preview)
        .environment(Manager.Security(modelContainer: container))
}
