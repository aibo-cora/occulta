//
//  ContactsListV2.swift
//  Occulta
//

import SwiftUI
import SwiftData
import ContactsUI

struct ContactsV2: View {
    @State private var searchText = ""
    @State private var creatingNewContact = false

    @AppStorage("showFingerprints")  private var showFingerprints  = true
    @AppStorage("showTrustSummary")  private var showTrustSummary  = true

    @Environment(\.modelContext)       private var modelContext
    @Environment(ContactManager.self)  private var contactManager

    @Query(sort: \Contact.Profile.familyName) private var contacts: [Contact.Profile]

    private var sorted: [Contact.Profile] {
        let source = self.searchText.isEmpty ? self.contacts : self.contacts.filter {
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

    private var verified:   [Contact.Profile] { self.sorted.filter { $0.verificationStatus == .verified } }
    private var unverified: [Contact.Profile] { self.sorted.filter { $0.verificationStatus == .unverified } }
    private var pending:    [Contact.Profile] { self.sorted.filter { $0.verificationStatus == .pending } }

    var body: some View {
        NavigationStack {
            List {
                if self.showTrustSummary && !self.contacts.isEmpty {
                    Section {
                        TrustSummaryCard(
                            verified: self.verified.count,
                            unverified: self.unverified.count,
                            pending: self.pending.count
                        )
                        .listRowInsets(EdgeInsets())
                    }
                    .listRowBackground(Color.clear)
                }

                if !self.verified.isEmpty {
                    Section { self.rows(self.verified) } header: { SectionHeaderV2(status: .verified) }
                }
                if !self.unverified.isEmpty {
                    Section { self.rows(self.unverified) } header: { SectionHeaderV2(status: .unverified) }
                }
                if !self.pending.isEmpty {
                    Section { self.rows(self.pending) } header: { SectionHeaderV2(status: .pending) }
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

                Section {
                    Text("\(self.contacts.count) contacts · e2e encrypted at rest")
                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 2)
                }
                .listRowBackground(Color.clear)

                if #available(iOS 18.0, *) {
                    Section {
                        ContactAccessButton(queryString: self.searchText) { identifiers in
                            self.fetchContacts(with: identifiers)
                        }
                        .contactAccessButtonCaption(.phone)
                        .contactAccessButtonStyle(ContactAccessButton.Style(imageWidth: 30))
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Contacts")
            .searchable(
                text: self.$searchText,
                placement: .navigationBarDrawer(displayMode: .always),
                prompt: "Find a contact…"
            )
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        self.creatingNewContact = true
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: self.$creatingNewContact) {
                Contact.FormV2()
            }
            .navigationDestination(for: String.self) { identifier in
                Contact.DetailsV2(identifier: identifier)
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
            try self.contactManager.createContacts(from: batch)
        } catch {
            debugPrint("fetchContacts error: \(error.localizedDescription)")
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
            Group {
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

            Text(self.contact.freshnessLabel)
                .font(.system(size: 10, weight: .regular, design: .monospaced))
                .foregroundStyle(.secondary)
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

#Preview {
    ContactsV2()
        .environment(ContactManager.preview)
}
