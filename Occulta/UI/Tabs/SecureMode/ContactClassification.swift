//
//  ContactClassification.swift
//  Occulta
//

import SwiftUI
import SwiftData

struct ContactClassification: View {

    /// Label for the confirm button. "Activate" in the activation flow, "Save" from Settings.
    var confirmLabel: String = "Save"
    /// Called after saving, before dismissing. Use to trigger the next step in the activation flow.
    var onConfirm: (() -> Void)? = nil

    @Environment(\.dismiss)             private var dismiss
    @Environment(Manager.Security.self) private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]

    /// Contacts the user has moved to the Sensitive section during this session.
    @State private var sensitiveIDs: Set<String> = []

    // MARK: - Derived lists

    /// Contacts in scope for this classification pass: visible at the current depth.
    /// At depth 0 this is all contacts. At depth N this excludes contacts already
    /// hidden below depth N (classified at a shallower layer), so the user only
    /// sees and edits contacts they can actually control at this layer.
    private var classifiableContacts: [Contact.Profile] {
        self.contacts.filter { self.security.isDisplayable($0) }
    }

    private var visibleContacts: [Contact.Profile] {
        self.classifiableContacts.filter { !self.sensitiveIDs.contains($0.identifier) }
    }

    private var verifiedVisible: [Contact.Profile] {
        self.visibleContacts.filter { $0.verificationStatus == .verified }
    }

    private var unverifiedVisible: [Contact.Profile] {
        self.visibleContacts.filter { $0.verificationStatus != .verified }
    }

    private var sensitiveContacts: [Contact.Profile] {
        self.classifiableContacts.filter { self.sensitiveIDs.contains($0.identifier) }
    }

    // MARK: - Body

    var body: some View {
        List {
                Text("Sensitive contacts are hidden in restricted view. Tap to move between groups.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))

                // MARK: Visible
                if !self.verifiedVisible.isEmpty || !self.unverifiedVisible.isEmpty {
                    Section {
                        if !self.verifiedVisible.isEmpty {
                            groupHeader("Verified")
                            ForEach(self.verifiedVisible) { contact in
                                ClassificationRow(
                                    contact:     contact,
                                    inSensitive: false,
                                    onTap:       { self.sensitiveIDs.insert(contact.identifier) }
                                )
                            }
                        }
                        if !self.unverifiedVisible.isEmpty {
                            groupHeader("Unverified")
                            ForEach(self.unverifiedVisible) { contact in
                                ClassificationRow(
                                    contact:     contact,
                                    inSensitive: false,
                                    onTap:       { self.sensitiveIDs.insert(contact.identifier) }
                                )
                                .opacity(0.45)
                            }
                        }
                    } header: {
                        Text("Visible")
                    }
                }

                // MARK: Sensitive
                Section {
                    if self.sensitiveContacts.isEmpty {
                        Text("None marked sensitive")
                            .font(.subheadline)
                            .foregroundStyle(Color(.tertiaryLabel))
                            .frame(maxWidth: .infinity, alignment: .center)
                            .listRowBackground(Color.clear)
                    } else {
                        ForEach(self.sensitiveContacts) { contact in
                            ClassificationRow(
                                contact:     contact,
                                inSensitive: true,
                                onTap:       { self.sensitiveIDs.remove(contact.identifier) }
                            )
                            .opacity(contact.verificationStatus != .verified ? 0.45 : 1)
                        }
                    }
                } header: {
                    Text("Sensitive")
                }
            }
            .navigationTitle("Classify Contacts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(self.confirmLabel) {
                        self.save()
                        if let onConfirm = self.onConfirm {
                            onConfirm()
                        } else {
                            self.dismiss()
                        }
                    }
                    .fontWeight(.semibold)
                }
            }
            .onAppear { self.loadSensitiveIDs() }
    }

    // MARK: - Helpers

    @ViewBuilder
    private func groupHeader(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(Color(.tertiaryLabel))
            .textCase(.uppercase)
            .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 4, trailing: 16))
            .listRowBackground(Color.clear)
    }

    // MARK: - Persistence

    private func loadSensitiveIDs() {
        // In duress mode, do not reveal which contacts are sensitive.
        // save() has the same guard — the view intentionally appears as if no contacts
        // have been classified (consistent with tell-avoidance: attacker sees normal state).
        guard !self.security.isRestricted else { return }
        self.sensitiveIDs = Set(
            self.contacts
                .filter { self.security.isSensitive($0.identifier) }
                .map { $0.identifier }
        )
    }

    private func save() {
        // Never persist classification changes while restricted. The coercer must
        // not be able to reclassify contacts from within the duress view.
        guard !self.security.isRestricted else { return }
        // Use classifiableContacts so already-hidden contacts are not included in safeIDs.
        // updateSafeContacts has the same guard, but being explicit here is cleaner.
        let safeIDs = Set(self.classifiableContacts.map { $0.identifier }).subtracting(self.sensitiveIDs)
        try? self.security.updateSafeContacts(safeIDs)
    }
}

// MARK: - Row

private struct ClassificationRow: View {

    let contact:     Contact.Profile
    let inSensitive: Bool
    let onTap:       () -> Void

    private var givenName:  String { self.contact.givenName.decrypt() }
    private var familyName: String { self.contact.familyName.decrypt() }

    var body: some View {
        Button(action: { withAnimation(.easeInOut(duration: 0.18)) { self.onTap() } }) {
            HStack(spacing: 12) {
                ZStack {
                    avatarGradientV2(for: self.contact.identifier)
                    Text([self.givenName, self.familyName]
                        .filter { !$0.isEmpty }
                        .joined(separator: " ")
                        .initials)
                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .frame(width: 38, height: 38)
                .clipShape(Circle())

                VStack(alignment: .leading, spacing: 2) {
                    (Text(self.givenName.isEmpty ? "" : self.givenName + " ")
                        .fontWeight(.regular)
                    + Text(self.familyName)
                        .fontWeight(.semibold))
                        .font(.body)
                        .lineLimit(1)

                    Text(self.contact.verificationStatus.chipLabel)
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundStyle(self.contact.verificationStatus.color)
                }

                Spacer()

                Image(systemName: self.inSensitive ? "arrow.up.circle.fill" : "arrow.down.circle.fill")
                    .font(.system(size: 20))
                    .foregroundStyle(self.inSensitive ? Color.occultaDanger : Color(.tertiaryLabel))
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Preview

#Preview {
    let container = try! ModelContainer(
        for: Schema([Contact.Profile.self, AppLayerConfig.self,
                     Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
                     Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self,
                     Contact.Profile.Key.self]),
        configurations: [ModelConfiguration(isStoredInMemoryOnly: true)]
    )
    NavigationStack {
        ContactClassification(confirmLabel: "Activate")
    }
    .modelContainer(container)
    .environment(Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
}
