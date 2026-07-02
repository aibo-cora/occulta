//
//  ContactsListV2.swift
//  Occulta
//

import SwiftUI
import SwiftData
import ContactsUI

struct ContactsV2: View {
    @State private var searchText        = ""
    @State private var showGroups         = false
    @State private var creatingNewContact = false
    @State private var creatingNewGroup   = false

    @AppStorage("showFingerprints")  private var showFingerprints  = false
    @AppStorage("showTrustSummary")  private var showTrustSummary  = true

    @Environment(\.modelContext)          private var modelContext
    @Environment(ContactManager.self)     private var contactManager
    @Environment(Manager.Security.self)   private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]
    @Query private var groups: [Group]

    private var sortedGroups: [Group] {
        let source = self.searchText.isEmpty ? self.groups : self.groups.filter {
            ($0.readName() ?? "").localizedStandardContains(self.searchText)
        }
        return source.sorted { ($0.readName() ?? "") < ($1.readName() ?? "") }
    }

    private var visibleContacts: [Contact.Profile] {
        self.contacts.filter { self.security.isDisplayable($0) }
    }

    private var sortedContacts: [Contact.Profile] {
        let source = self.searchText.isEmpty ? self.visibleContacts : self.visibleContacts.filter {
            $0.givenName.decrypt().localizedStandardContains(self.searchText)
            || $0.familyName.decrypt().localizedStandardContains(self.searchText)
            || $0.organizationName.decrypt().localizedStandardContains(self.searchText)
        }
        
        return source.sorted {
            let lf = $0.familyName.decrypt(), rf = $1.familyName.decrypt()
            
            if !lf.isEmpty || !rf.isEmpty { return lf < rf }
            
            return $0.givenName.decrypt() < $1.givenName.decrypt()
        }
    }

    var body: some View {
        NavigationStack {
            VStack {
                List {
                    if self.showGroups {
                        let sorted = self.sortedGroups
                        
                        if sorted.isEmpty {
                            Section {
                                Text(self.searchText.isEmpty
                                     ? "Tap **+** to create your first group."
                                     : "No groups match your search.")
                                    .font(.body)
                                    .padding(.vertical, 4)
                            }
                            .listRowBackground(Color.clear)
                        } else {
                            Section {
                                ForEach(sorted) { group in
                                    if let groupID = group.readID() {
                                        NavigationLink(value: groupID) {
                                            GroupRowV2(group: group)
                                        }
                                    }
                                }
                            }
                            if self.searchText.isEmpty {
                                Section {
                                    Text("\(sorted.count) group\(sorted.count == 1 ? "" : "s") · encrypted at rest")
                                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                        .frame(maxWidth: .infinity, alignment: .center)
                                        .padding(.vertical, 2)
                                }
                                .listRowBackground(Color.clear)
                            }
                        }
                    } else {
                        let sorted = self.sortedContacts
                        let verified = sorted.filter { $0.verificationStatus == .verified }
                        let unverified = sorted.filter { $0.verificationStatus == .unverified }
                        let pending = sorted.filter { $0.verificationStatus == .pending }

                        if self.showTrustSummary && !self.contacts.isEmpty {
                            Section {
                                TrustSummaryCard(verified: verified.count, unverified: unverified.count, pending: pending.count)
                                .listRowInsets(EdgeInsets())
                            }
                            .listRowBackground(Color.clear)
                        }

                        if self.searchText.isEmpty {
                            if !verified.isEmpty {
                                Section { self.rows(verified) } header: { SectionHeaderV2(status: .verified) }
                            }
                            if !unverified.isEmpty {
                                Section { self.rows(unverified) } header: { SectionHeaderV2(status: .unverified) }
                            }
                            if !pending.isEmpty {
                                Section { self.rows(pending) } header: { SectionHeaderV2(status: .pending) }
                            }
                        }

                        if self.contacts.isEmpty {
                            Section {
                                VStack(alignment: .leading, spacing: 10) {
                                    if #available(iOS 18.0, *) {
                                        Text("Use the search field to import a contact from your device.")
                                    }
                                    Text("Tap **+** to create a new contact.")
                                }
                                .font(.body)
                                .padding(.vertical, 4)
                            }
                            .listRowBackground(Color.clear)
                        }

                        if self.searchText.isEmpty {
                            Section {
                                Text("\(self.visibleContacts.count) contacts · encrypted at rest")
                                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .frame(maxWidth: .infinity, alignment: .center)
                                    .padding(.vertical, 2)
                            }
                            .listRowBackground(Color.clear)
                        }
                    }
                }
                .scrollIndicators(.hidden)
                .listStyle(.insetGrouped)
                .safeAreaInset(edge: .top, spacing: 0) {
                    Picker("", selection: self.$showGroups) {
                        Text("Contacts").tag(false)
                        Text("Groups").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .background(Color(.systemGroupedBackground))
                }
                .onChange(of: self.showGroups) { _, _ in self.searchText = "" }
                
                if #available(iOS 18.0, *), !self.showGroups {
                    ContactAccessButton(queryString: self.searchText) { identifiers in
                        self.fetchContacts(with: identifiers)
                    }
                    
                    .contactAccessButtonCaption(.phone)
                    .contactAccessButtonStyle(ContactAccessButton.Style(imageWidth: 30))
                    .padding()
                }
            }
            .searchable(text: self.$searchText, placement: .navigationBarDrawer(displayMode: .always), prompt: self.showGroups ? "Find a group…" : "Find a contact…")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        if self.showGroups { self.creatingNewGroup   = true }
                        else               { self.creatingNewContact = true }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: self.$creatingNewContact) {
                Contact.FormV2()
            }
            .sheet(isPresented: self.$creatingNewGroup) {
                Group.FormV3()
            }
            .navigationDestination(for: String.self) { identifier in
                Contact.DetailsV2(identifier: identifier)
            }
            .navigationDestination(for: UUID.self) { groupID in
                GroupDetailV3(groupID: groupID)
            }
        }
    }

    @ViewBuilder
    private func rows(_ items: [Contact.Profile]) -> some View {
        ForEach(items) { contact in
            NavigationLink(value: contact.identifier) {
                ContactRowV2(contact: contact, showFingerprint: self.showFingerprints)
            }
        }
    }

    private func fetchContacts(with identifiers: [String]) {
        do {
            let request = CNContactFetchRequest(keysToFetch: self.contactManager.keys)
            request.predicate = CNContact.predicateForContacts(withIdentifiers: identifiers)
            var batch = [CNContact]()
            try CNContactStore().enumerateContacts(with: request) { contact, _ in batch.append(contact) }
            try self.contactManager.createContacts(from: batch, currentDepth: self.security.currentDepth)
        } catch {
            #if DEBUG
            debugPrint("fetchContacts error: \(error.localizedDescription)")
            #endif
        }
    }
}

// MARK: - Contact Row

struct ContactRowV2: View {
    let contact: Contact.Profile
    let showFingerprint: Bool

    private var givenName:  String { self.contact.givenName.decrypt() }
    private var familyName: String { self.contact.familyName.decrypt() }

    private var thumbnail: Data? {
        self.contact.imageData?.decrypt() ?? self.contact.thumbnailImageData?.decrypt()
    }

    var body: some View {
        HStack(spacing: 14) {
            SwiftUI.Group {
                if let data = self.thumbnail, let img = UIImage(data: data) {
                    Image(uiImage: img).resizable().scaledToFill()
                } else {
                    ZStack {
                        avatarGradientV2(for: self.contact.identifier)

                        Text([self.givenName, self.familyName].filter { !$0.isEmpty }
                                .joined(separator: " ").initials)
                            .font(.system(size: 15, weight: .semibold, design: .rounded))
                            .foregroundStyle(.white)
                    }
                }
            }
            .frame(width: 44, height: 44)
            .clipShape(Circle())

            VStack(alignment: .leading, spacing: 4) {
                (Text(self.givenName.isEmpty ? "" : self.givenName + " ")
                    .fontWeight(.regular)
                + Text(self.familyName)
                    .fontWeight(.semibold))
                    .font(.body)
                    .lineLimit(1)

                HStack(spacing: 6) {
                    Circle()
                        .fill(self.contact.verificationStatus.color)
                        .frame(width: 6, height: 6)

                    if self.showFingerprint, let fp = self.contact.fingerprintPreview {
                        Text(fp)
                            .font(.system(size: 10, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
            }

            Spacer()
        }
        .padding(.vertical, 3)
    }
}

// MARK: - Trust Summary Card

private struct TrustSummaryCard: View {
    let verified: Int
    let unverified: Int
    let pending: Int

    var body: some View {
        HStack(spacing: 0) {
            Spacer()
            CountColumn(count: self.verified,   label: "VERIFIED",   color: .occultaVerified)
            Spacer()
            Divider().frame(height: 36)
            Spacer()
            CountColumn(count: self.unverified, label: "UNVERIFIED", color: .occultaWarn)
            Spacer()
            Divider().frame(height: 36)
            Spacer()
            CountColumn(count: self.pending,    label: "PENDING",    color: .secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal, 16)
        .padding(.vertical, 4)
    }

    private struct CountColumn: View {
        let count: Int
        let label: String
        let color: Color

        var body: some View {
            VStack(spacing: 4) {
                HStack(spacing: 5) {
                    Circle().fill(self.color).frame(width: 7, height: 7)
                    Text("\(self.count)").font(.system(size: 17, weight: .semibold))
                }
                Text(self.label)
                    .font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .tracking(0.5)
            }
        }
    }
}

// MARK: - Section Header

private struct SectionHeaderV2: View {
    let status: VerificationStatus

    var body: some View {
        HStack(spacing: 6) {
            if self.status == .pending {
                Circle()
                    .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [3, 2]))
                    .frame(width: 8, height: 8)
                    .foregroundStyle(.secondary)
            } else {
                Circle().fill(self.status.color).frame(width: 8, height: 8)
            }
            Text(self.status.sectionLabel)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .tracking(1.6)
        }
    }
}

// MARK: - Group Row

private struct GroupRowV2: View {
    let group: Group

    private var name: String { self.group.readName() ?? "Unnamed Group" }

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                avatarGradientV2(for: self.group.readID()?.uuidString ?? self.name)
                Text(self.name.initials)
                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .frame(width: 44, height: 44)
            .clipShape(Circle())

            Text(self.name)
                .font(.body.weight(.semibold))
                .lineLimit(1)

            Spacer()
        }
        .padding(.vertical, 3)
    }
}

#Preview {
    ContactsV2()
        .environment(ContactManager.preview)
}
