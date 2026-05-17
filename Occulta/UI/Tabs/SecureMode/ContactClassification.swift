//
//  ContactClassification.swift
//  Occulta
//

import SwiftUI
import SwiftData

struct ContactClassification: View {

    var onContinue: () -> Void = {}

    @Environment(\.dismiss)        private var dismiss
    @Environment(Manager.Security.self) private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]

    @State private var safeIDs: Set<String> = []

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("**Safe** contacts remain visible. **Sensitive** contacts are hidden when restricted access is active.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
                }

                Section("\(self.contacts.count) contacts") {
                    ForEach(self.contacts) { contact in
                        ContactClassificationRow(
                            contact: contact,
                            isSafe:  self.safeIDs.contains(contact.identifier),
                            onToggle: { isSafe in
                                if isSafe {
                                    self.safeIDs.insert(contact.identifier)
                                } else {
                                    self.safeIDs.remove(contact.identifier)
                                }
                            }
                        )
                    }
                }

                Section {
                    HStack(spacing: 16) {
                        LegendItem(color: .occultaVerified, label: "visible in restricted view")
                        LegendItem(color: .occultaDanger,   label: "hidden in restricted view")
                    }
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                    .frame(maxWidth: .infinity, alignment: .center)
                }
            }
            .navigationTitle("Classify Contacts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { self.dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { self.save(); self.dismiss() }
                        .fontWeight(.semibold)
                }
            }
            .safeAreaInset(edge: .bottom) {
                Button {
                    self.save()
                    self.onContinue()
                } label: {
                    Text("Continue to PIN Setup")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 16)
                        .background(Color.occultaAccent)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 8)
                .background(.ultraThinMaterial)
            }
            .onAppear { self.loadSafeIDs() }
        }
    }

    // MARK: - Persistence

    private func loadSafeIDs() {
        self.safeIDs = self.security.safeContactIDs()
    }

    private func save() {
        try? self.security.updateSafeContacts(self.safeIDs)
    }
}

// MARK: - Row

private struct ContactClassificationRow: View {

    let contact:  Contact.Profile
    let isSafe:   Bool
    let onToggle: (Bool) -> Void

    private var givenName:  String { self.contact.givenName.decrypt() }
    private var familyName: String { self.contact.familyName.decrypt() }

    var body: some View {
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
            .frame(width: 40, height: 40)
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

            SafeToggle(isSafe: self.isSafe, onToggle: self.onToggle)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Safe Toggle

private struct SafeToggle: View {

    let isSafe:   Bool
    let onToggle: (Bool) -> Void

    var body: some View {
        HStack(spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { self.onToggle(true) }
            } label: {
                Text("Safe")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(self.isSafe ? .white : .secondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(self.isSafe ? Color.occultaVerified : Color.clear)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            .buttonStyle(.plain)

            Button {
                withAnimation(.easeInOut(duration: 0.15)) { self.onToggle(false) }
            } label: {
                Text("Sensitive")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(self.isSafe ? .secondary : Color.occultaDanger)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(self.isSafe ? Color.clear : Color.occultaDanger.opacity(0.15))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            .buttonStyle(.plain)
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color(.separator), lineWidth: 0.5)
        )
    }
}

// MARK: - Legend Item

private struct LegendItem: View {
    let color: Color
    let label: String

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(self.color).frame(width: 8, height: 8)
            Text(self.label)
                .font(.system(size: 12, weight: .regular, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Preview

#Preview {
    let container = try! ModelContainer(
        for: Schema([Contact.Profile.self, AppLayerConfig.self]),
        configurations: [ModelConfiguration(isStoredInMemoryOnly: true)]
    )
    ContactClassification()
        .modelContainer(container)
        .environment(Manager.Security(modelContainer: container))
}
