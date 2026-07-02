//
//  Group+FormV3.swift
//  Occulta
//

import SwiftUI
import SwiftData

extension Group {
    struct FormV3: View {

        enum FormMode {
            case create
            case edit(groupID: UUID)
        }

        let formMode: FormMode
        let onDelete: (() -> Void)?
        private let crypto = Manager.Crypto()

        @State private var name                = ""
        @State private var selectedIdentifiers = Set<String>()
        @State private var eligible:   [Contact.Profile] = []
        @State private var ineligible: [Contact.Profile] = []
        @State private var showSaveError  = false
        @State private var saveErrorText  = ""

        @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]
        @Query private var groups: [Group]

        @Environment(\.dismiss)             private var dismiss
        @Environment(\.modelContext)        private var modelContext
        @Environment(ContactManager.self)   private var contactManager
        @Environment(Manager.Security.self) private var security

        init(mode: FormMode = .create, onDelete: (() -> Void)? = nil) {
            self.formMode = mode
            self.onDelete = onDelete
        }

        // MARK: - Derived

        private var existingGroup: Group? {
            guard case .edit(let id) = self.formMode else { return nil }
            return self.groups.first { $0.readID() == id }
        }

        private var isEditing: Bool {
            if case .edit = self.formMode { return true }
            return false
        }


        private var ineligibleHeader: String {
            let hasUnknown = self.ineligible.contains { $0.maxBundleVersion == nil }
            let hasOld     = self.ineligible.contains { $0.maxBundleVersion != nil }
            if hasUnknown && hasOld {
                return "These contacts need a newer version of Occulta or haven't messaged you yet."
            }
            if hasOld { return "Ask them to update Occulta." }
            return "Version unknown — ask them to send you a message."
        }

        private var atCapacity: Bool {
            self.selectedIdentifiers.count >= Group.slotCount
        }

        private var membersHeader: String {
            self.selectedIdentifiers.isEmpty
                ? "Members"
                : "Members · \(self.selectedIdentifiers.count) / \(Group.slotCount)"
        }

        private var canSave: Bool {
            !self.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }

        // MARK: - Body

        var body: some View {
            NavigationStack {
                Form {
                    Section("Name") {
                        TextField("Group name", text: self.$name)
                            .tint(Color.occultaAccent)
                    }

                    if !self.eligible.isEmpty {
                        Section {
                            ForEach(self.eligible) { contact in
                                self.eligibleRow(contact)
                            }
                        } header: {
                            Text(self.membersHeader)
                                .foregroundStyle(self.atCapacity ? Color.orange : Color.secondary)
                        }
                    }

                    if !self.ineligible.isEmpty {
                        Section(self.ineligibleHeader) {
                            ForEach(self.ineligible) { contact in
                                self.ineligibleRow(contact)
                            }
                        }
                    }

                    if self.isEditing {
                        Section {
                            Button(role: .destructive, action: self.deleteGroup) {
                                Label("Delete group", systemImage: "trash")
                            }
                        }
                    }
                }
                .navigationTitle(self.isEditing ? "Edit Group" : "New Group")
                .navigationBarTitleDisplayMode(.large)
                .onAppear {
                    self.computeEligibility()
                    guard let grp = self.existingGroup else { return }
                    self.name                = grp.readName() ?? ""
                    self.selectedIdentifiers = Set(grp.members(atDepth: self.security.currentDepth))
                }
                .onChange(of: self.contacts) { _, _ in self.computeEligibility() }
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Cancel", role: .cancel) { self.dismiss() }
                            .tint(Color.occultaAccent)
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Button(self.isEditing ? "Save" : "Create", action: self.saveGroup)
                            .tint(Color.occultaAccent)
                            .disabled(!self.canSave)
                    }
                }
                .alert("Couldn't save group", isPresented: self.$showSaveError) {
                    Button("OK") {}
                } message: {
                    Text(self.saveErrorText)
                }
            }
        }

        // MARK: - Rows

        @ViewBuilder
        private func eligibleRow(_ contact: Contact.Profile) -> some View {
            let id         = contact.identifier
            let givenName  = contact.givenName.decrypt()
            let familyName = contact.familyName.decrypt()
            let fullName   = [givenName, familyName].filter { !$0.isEmpty }.joined(separator: " ")
            let isSelected = self.selectedIdentifiers.contains(id)

            let blocked = !isSelected && self.atCapacity
            Button {
                if isSelected { self.selectedIdentifiers.remove(id) }
                else          { self.selectedIdentifiers.insert(id) }
            } label: {
                HStack(spacing: 12) {
                    ZStack {
                        avatarGradientV2(for: id)
                        Text(fullName.initials)
                            .font(.system(size: 14, weight: .semibold, design: .rounded))
                            .foregroundStyle(.white)
                    }
                    .frame(width: 36, height: 36)
                    .clipShape(Circle())

                    (Text(givenName.isEmpty ? "" : givenName + " ").fontWeight(.regular)
                     + Text(familyName).fontWeight(.semibold))
                        .font(.body)
                        .lineLimit(1)
                        .foregroundStyle(.primary)

                    Spacer()

                    Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                        .font(.system(size: 22))
                        .foregroundStyle(isSelected ? Color.occultaAccent : Color.secondary)
                }
            }
            .buttonStyle(.plain)
            .disabled(blocked)
            .opacity(blocked ? 0.35 : 1)
        }

        @ViewBuilder
        private func ineligibleRow(_ contact: Contact.Profile) -> some View {
            let givenName  = contact.givenName.decrypt()
            let familyName = contact.familyName.decrypt()
            let fullName   = [givenName, familyName].filter { !$0.isEmpty }.joined(separator: " ")
            let subLabel   = contact.maxBundleVersion == nil
                ? "No bundle received yet"
                : "Needs to update Occulta"

            HStack(spacing: 12) {
                ZStack {
                    avatarGradientV2(for: contact.identifier)
                    Text(fullName.initials)
                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .frame(width: 36, height: 36)
                .clipShape(Circle())

                VStack(alignment: .leading, spacing: 2) {
                    (Text(givenName.isEmpty ? "" : givenName + " ").fontWeight(.regular)
                     + Text(familyName).fontWeight(.semibold))
                        .font(.body)
                        .lineLimit(1)
                    Text(subLabel)
                        .font(.system(size: 12, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            .opacity(0.5)
        }

        // MARK: - Actions

        private func computeEligibility() {
            let displayable = self.contacts.filter { self.security.isDisplayable($0) }
            self.eligible   = displayable.filter {  ContactManager.resolveTargetVersion(for: $0, using: self.crypto).supportsGroups }
            self.ineligible = displayable.filter { !ContactManager.resolveTargetVersion(for: $0, using: self.crypto).supportsGroups }
        }

        private func saveGroup() {
            let trimmed = self.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }

            do {
                let depth = self.security.currentDepth
                if let group = self.existingGroup {
                    try group.writeName(trimmed)
                    let current = Set(group.members(atDepth: depth))
                    for identifier in current.subtracting(self.selectedIdentifiers) {
                        try group.removeMember(identifier, atDepth: depth)
                    }
                    for identifier in self.selectedIdentifiers.subtracting(current) {
                        try group.addMember(identifier, atDepth: depth)
                    }
                    try self.modelContext.save()
                } else {
                    let group = try Group(name: trimmed)
                    self.modelContext.insert(group)
                    for identifier in self.selectedIdentifiers {
                        try group.addMember(identifier, atDepth: depth)
                    }
                    try self.modelContext.save()
                }
            } catch {
                self.saveErrorText  = error.localizedDescription
                self.showSaveError  = true
                return
            }

            self.dismiss()
        }

        private func deleteGroup() {
            guard let group = self.existingGroup else { return }
            self.modelContext.delete(group)
            try? self.modelContext.save()
            self.dismiss()
            self.onDelete?()
        }
    }
}
