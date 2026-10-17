//
//  ShareRecipientPicker.swift
//  Occulta
//
//  Who a staged share gets encrypted for. Presented by `RootView` only from the .unlocked
//  phase, so the PIN is always answered before this list is drawn (Bug 84).
//
//  Rows, headers, filtering, and sort order are the contacts tab's own — `ContactRowV2`,
//  `GroupRowV2`, `SectionHeaderV2`, `ContactListFilter` — so the two screens cannot show a
//  different set of people at the same depth.
//

import SwiftUI
import SwiftData

struct ShareRecipientPicker: View {

    enum Recipient {
        case contact(String)
        case group(UUID)
    }

    let onSelect: (Recipient) -> Void
    let onCancel: () -> Void

    @State private var searchText = ""

    @AppStorage("showFingerprints") private var showFingerprints = false

    @Environment(Manager.Security.self) private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]
    @Query private var groups: [Group]

    private var selectableGroups: [Group] {
        ContactListFilter.sortedGroups(
            ContactListFilter.groupsWithMembers(self.groups, atDepth: self.security.currentDepth),
            matching: self.searchText
        )
    }

    private var selectableContacts: [Contact.Profile] {
        ContactListFilter.sortedContacts(
            ContactListFilter.visibleContacts(self.contacts, atDepth: self.security.currentDepth),
            matching: self.searchText
        )
    }

    var body: some View {
        NavigationStack {
            List {
                let groups     = self.selectableGroups
                let contacts   = self.selectableContacts
                // Once per contact: the status opens the key owner hash and, with no keys, the card field.
                let statuses   = Dictionary(contacts.map { ($0.identifier, $0.verificationStatus) }, uniquingKeysWith: { first, _ in first })
                let verified   = contacts.filter { statuses[$0.identifier] == .verified }
                let unverified = contacts.filter { statuses[$0.identifier] == .unverified }
                let pending    = contacts.filter { statuses[$0.identifier] == .pending }

                if !groups.isEmpty {
                    Section {
                        ForEach(groups) { group in
                            if let groupID = group.readID() {
                                Button {
                                    self.onSelect(.group(groupID))
                                } label: {
                                    GroupRowV2(group: group)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    } header: {
                        SectionHeaderV2(label: "GROUPS")
                    }
                }

                if !verified.isEmpty {
                    Section { self.rows(verified, statuses: statuses) } header: { SectionHeaderV2(status: .verified) }
                }
                if !unverified.isEmpty {
                    Section {
                        self.rows(unverified, statuses: statuses)
                    } header: {
                        SectionHeaderV2(status: .unverified)
                    } footer: {
                        Text(IntroCardCopy.notVerifiedListFooter)
                    }
                }
                if !pending.isEmpty {
                    Section { self.rows(pending, statuses: statuses) } header: { SectionHeaderV2(status: .pending) }
                }

                if groups.isEmpty && contacts.isEmpty {
                    Section {
                        Text(self.searchText.isEmpty
                             ? "Exchange keys with someone before you can encrypt for them."
                             : "No contacts or groups match your search.")
                            .font(.body)
                            .padding(.vertical, 4)
                    }
                    .listRowBackground(Color.clear)
                } else if self.searchText.isEmpty {
                    Section {
                        Text("\(contacts.count) contact\(contacts.count == 1 ? "" : "s") · \(groups.count) group\(groups.count == 1 ? "" : "s") · encrypted at rest")
                            .font(.system(size: 10, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 2)
                    }
                    .listRowBackground(Color.clear)
                }
            }
            .scrollIndicators(.hidden)
            .listStyle(.insetGrouped)
            .searchable(text: self.$searchText, placement: .navigationBarDrawer(displayMode: .always), prompt: "Find a recipient…")
            .autocorrectionDisabled()
            .navigationTitle("Encrypt for")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: self.onCancel)
                }
            }
        }
    }

    @ViewBuilder
    private func rows(_ items: [Contact.Profile], statuses: [String: VerificationStatus]) -> some View {
        ForEach(items) { contact in
            Button {
                self.onSelect(.contact(contact.identifier))
            } label: {
                ContactRowV2(contact: contact, status: statuses[contact.identifier] ?? .pending, showFingerprint: self.showFingerprints)
            }
            .buttonStyle(.plain)
        }
    }
}
