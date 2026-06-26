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
        private let crypto = Manager.Crypto()

        @State private var name                = ""
        @State private var selectedIdentifiers = Set<String>()

        @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]
        @Query private var groups: [Group]

        @Environment(\.dismiss)             private var dismiss
        @Environment(ContactManager.self)   private var contactManager
        @Environment(Manager.Security.self) private var security

        init(mode: FormMode = .create) {
            self.formMode = mode
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

        private var layer: RoutingDepth {
            RoutingDepth(rawValue: self.security.currentDepth) ?? .normal
        }

        private var displayable: [Contact.Profile] {
            self.contacts.filter { self.security.isDisplayable($0) }
        }

        private var eligible: [Contact.Profile] {
            self.displayable.filter {
                ContactManager.resolveTargetVersion(for: $0, using: self.crypto).supportsGroups
            }
        }

        private var ineligible: [Contact.Profile] {
            self.displayable.filter {
                !ContactManager.resolveTargetVersion(for: $0, using: self.crypto).supportsGroups
            }
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

        private var membersHeader: String {
            self.selectedIdentifiers.isEmpty
                ? "Members"
                : "Members · \(self.selectedIdentifiers.count) selected"
        }

        private var canSave: Bool {
            !self.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && !self.selectedIdentifiers.isEmpty
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
                        Section(self.membersHeader) {
                            ForEach(self.eligible) { contact in
                                self.eligibleRow(contact)
                            }
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
                    guard let grp = self.existingGroup else { return }
                    self.name                = grp.readName() ?? ""
                    self.selectedIdentifiers = Set(grp.members(in: self.layer))
                }
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

        private func saveGroup() {
            let trimmed = self.name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }

            if let group = self.existingGroup {
                try? group.writeName(trimmed)
                guard let id = group.readID() else { self.dismiss(); return }
                let current = Set(group.members(in: self.layer))
                self.selectedIdentifiers.subtracting(current).forEach {
                    try? self.contactManager.addGroupMember($0, toGroupID: id, in: self.layer)
                }
                current.subtracting(self.selectedIdentifiers).forEach {
                    try? self.contactManager.removeGroupMember($0, fromGroupID: id, in: self.layer)
                }
            } else {
                if let group = try? self.contactManager.createGroup(name: trimmed),
                   let id    = group.readID() {
                    self.selectedIdentifiers.forEach {
                        try? self.contactManager.addGroupMember($0, toGroupID: id, in: self.layer)
                    }
                }
            }
            self.dismiss()
        }

        private func deleteGroup() {
            guard case .edit(let id) = self.formMode else { return }
            try? self.contactManager.deleteGroup(id: id)
            self.dismiss()
        }
    }
}
