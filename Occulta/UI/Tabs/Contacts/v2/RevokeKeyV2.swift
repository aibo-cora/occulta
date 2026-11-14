//
//  RevokeKeyV2.swift
//  Occulta
//
//  The one Revoke Key screen, pushed from Trust Check and from the contact form. It replaces a confirmation dialog,
//  which had room for a sentence and none for what the revoke touches: the groups the contact is in.
//  `Docs/Bugs/v2.1.0/Revoked-Contact-Stays-In-Group-With-No-Warning-And-Group-Send-Fails-Opaquely.md`.
//

import SwiftUI

struct RevokeKeyV2: View {
    let identifier: String
    let displayName: String
    /// Runs after the key is revoked, before this screen pops itself.
    let onRevoked: () -> Void

    @Environment(\.dismiss)             private var dismiss
    @Environment(ContactManager.self)   private var contactManager
    @Environment(Manager.Security.self) private var security

    /// Nil until looked up. The depth is the current one only, so no group is named that this depth can't already see.
    @State private var groups: [String]?
    @State private var lookupFailed = false
    @State private var revokeFailed = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Revoke \(self.displayName)'s key?")
                    .font(.system(size: 22, weight: .bold))

                self.card(title: "What happens") {
                    self.line("key.horizontal.fill", "\(self.displayName)'s key stops being trusted. You can't encrypt anything for them until you exchange keys again, in person.")
                    self.line("trash", "The one-time keys they gave you are deleted from this phone.")
                }

                if let groups = self.groups, !groups.isEmpty {
                    self.card(title: groups.count == 1 ? "In 1 group" : "In \(groups.count) groups") {
                        ForEach(groups, id: \.self) { name in
                            self.line("person.2.fill", name)
                        }
                        Text("\(self.displayName) stays in \(groups.count == 1 ? "this group" : "these groups"). A message to \(groups.count == 1 ? "it" : "them") leaves \(self.displayName) out until you exchange keys again or remove \(self.displayName).")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                } else if self.lookupFailed {
                    self.card(title: "Groups") {
                        Text("Couldn't check which groups \(self.displayName) is in. They may be in some.")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                }

                if self.revokeFailed {
                    Text("The key could not be revoked. Nothing was changed.")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.occultaDanger)
                }

                Button(role: .destructive) {
                    self.revoke()
                } label: {
                    Text("Revoke Key")
                        .font(.system(size: 16, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .foregroundStyle(.white)
                        .background(Color.occultaDanger, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
                .buttonStyle(.plain)
            }
            .padding(16)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Revoke Key")
        .navigationBarTitleDisplayMode(.inline)
        .task { self.loadGroups() }
    }

    private func loadGroups() {
        do {
            self.groups = try self.contactManager.groupNames(containing: self.identifier, atDepth: self.security.currentDepth)
        } catch {
            self.lookupFailed = true
        }
    }

    private func revoke() {
        do {
            try self.contactManager.reset(identity: self.identifier)
        } catch {
            self.revokeFailed = true
            return
        }
        self.onRevoked()
        self.dismiss()
    }

    private func card<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(15)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func line(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 18)
            Text(text)
                .font(.system(size: 15))
                .multilineTextAlignment(.leading)
        }
    }
}
