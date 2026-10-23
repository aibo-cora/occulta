//
//  ContactsListV2.swift
//  Occulta
//

import SwiftUI
import SwiftData
import ContactsUI
import UniformTypeIdentifiers
import OccultaFormats

/// The second line a card puts under a contact's name while it is pending (SPEC §5): "Card · …" on the issuer's
/// phone, "Send by · …" on the recipient's until the first message goes. Ticks every second.
enum CardRowLine: Equatable {
    case issued(expiresAt: Date)
    case sendBy(expiresAt: Date)

    init?(_ state: CardState) {
        switch state {
        case .issued(_, _, _, _, let expiresAt):
            self = .issued(expiresAt: expiresAt)
        case .imported(_, _, _, _, _, _, let expiresAt, let sentFirstMessage) where !sentFirstMessage:
            self = .sendBy(expiresAt: expiresAt)
        default:
            return nil
        }
    }
}

struct ContactsV2: View {
    /// Set from outside to open a contact's details, such as after importing a card. Cleared once handled.
    @Binding var openRequest: ContactOpenRequest?

    @State private var path = NavigationPath()
    /// The contact whose details open with the cursor in compose.
    @State private var focusComposeFor: String?
    @State private var importingCardFile = false
    @State private var cardImportData: CardImportData?
    @State private var cardFileError = false

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
    @Query private var drafts: [Message.Draft]

    init(openRequest: Binding<ContactOpenRequest?> = .constant(nil)) {
        self._openRequest = openRequest
    }

    private var contactIdentifiersWithDrafts: Set<String> {
        Message.Draft.allRecipientIdentifiers(from: self.drafts)
    }

    private var sortedGroups: [Group] {
        ContactListFilter.sortedGroups(self.groups, matching: self.searchText)
    }

    private var visibleContacts: [Contact.Profile] {
        ContactListFilter.visibleContacts(self.contacts, atDepth: self.security.currentDepth)
    }

    private var isListEmpty: Bool {
        ContactListFilter.isEmptyList(self.contacts, atDepth: self.security.currentDepth)
    }

    private var sortedContacts: [Contact.Profile] {
        ContactListFilter.sortedContacts(self.visibleContacts, matching: self.searchText)
    }

    var body: some View {
        NavigationStack(path: self.$path) {
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
                        // Once per contact: the status opens the key owner hash and, with no keys, the card field.
                        // The card field is read along with it, for the contacts that needed it, so it is decrypted once.
                        let reads = Dictionary(sorted.map { ($0.identifier, $0.statusAndCard) }, uniquingKeysWith: { first, _ in first })
                        let statuses = reads.mapValues(\.status)
                        let cardLines = reads.compactMapValues { $0.card.flatMap { CardRowLine($0) } }
                        let verified = sorted.filter { statuses[$0.identifier] == .verified }
                        let unverified = sorted.filter { statuses[$0.identifier] == .unverified }
                        let pending = sorted.filter { statuses[$0.identifier] == .pending }

                        if self.showTrustSummary && !self.isListEmpty {
                            Section {
                                TrustSummaryCard(verified: verified.count, unverified: unverified.count, pending: pending.count)
                                .listRowInsets(EdgeInsets())
                            }
                            .listRowBackground(Color.clear)
                        }

                        if self.searchText.isEmpty {
                            if !verified.isEmpty {
                                Section { self.rows(verified, statuses: statuses, cardLines: cardLines) } header: { SectionHeaderV2(status: .verified) }
                            }
                            if !unverified.isEmpty {
                                Section {
                                    self.rows(unverified, statuses: statuses, cardLines: cardLines)
                                } header: {
                                    SectionHeaderV2(status: .unverified)
                                } footer: {
                                    Text(IntroCardCopy.notVerifiedListFooter)
                                }
                            }
                            if !pending.isEmpty {
                                Section { self.rows(pending, statuses: statuses, cardLines: cardLines) } header: { SectionHeaderV2(status: .pending) }
                            }
                        }

                        if self.isListEmpty {
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
            .autocorrectionDisabled()
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if self.showGroups {
                        Button { self.creatingNewGroup = true } label: {
                            Image(systemName: "plus")
                        }
                    } else {
                        Menu {
                            Button { self.creatingNewContact = true } label: {
                                Label("New contact", systemImage: "person.badge.plus")
                            }
                            Button { self.importingCardFile = true } label: {
                                Label("Import card", systemImage: "square.and.arrow.down")
                            }
                        } label: {
                            Image(systemName: "plus")
                        }
                    }
                }
            }
            .sheet(isPresented: self.$creatingNewContact) {
                Contact.FormV2()
            }
            .sheet(isPresented: self.$creatingNewGroup) {
                Group.FormV3()
            }
            .sheet(item: self.$cardImportData) { card in
                CardImportSheet(data: card.data) { request in
                    self.cardImportData = nil
                    if let request { self.open(request) }
                }
            }
            .fileImporter(isPresented: self.$importingCardFile, allowedContentTypes: [.data]) { result in
                self.loadCardFile(result)
            }
            .alert(IntroCardCopy.notACard.label, isPresented: self.$cardFileError) {
                Button("OK") { }
            } message: {
                Text(IntroCardCopy.notACard.text)
            }
            .onChange(of: self.openRequest, initial: true) { _, request in
                guard let request else { return }
                self.openRequest = nil
                self.open(request)
            }
            // Focus compose only on the screen the request opened, not when the contact is opened again later.
            .onChange(of: self.path) { _, path in
                if path.isEmpty { self.focusComposeFor = nil }
            }
            .navigationDestination(for: String.self) { identifier in
                Contact.DetailsV2(identifier: identifier, focusCompose: identifier == self.focusComposeFor)
            }
            .navigationDestination(for: UUID.self) { groupID in
                GroupDetailV3(groupID: groupID)
            }
        }
    }

    @ViewBuilder
    private func rows(_ items: [Contact.Profile], statuses: [String: VerificationStatus], cardLines: [String: CardRowLine]) -> some View {
        let draftIdentifiers = self.contactIdentifiersWithDrafts
        ForEach(items) { contact in
            NavigationLink(value: contact.identifier) {
                ContactRowV2(
                    contact:         contact,
                    status:          statuses[contact.identifier] ?? .pending,
                    cardLine:        cardLines[contact.identifier],
                    showFingerprint: self.showFingerprints,
                    hasDraft:        draftIdentifiers.contains(contact.identifier)
                )
            }
        }
    }

    /// Opens a contact's details, replacing whatever was pushed. Only a contact this list shows at the current
    /// depth: a request for a hidden one does nothing, so no route reaches a contact the depth filter hides.
    private func open(_ request: ContactOpenRequest) {
        guard self.visibleContacts.contains(where: { $0.identifier == request.identifier }) else { return }
        self.showGroups      = false
        self.focusComposeFor = request.focusCompose ? request.identifier : nil
        self.path            = NavigationPath()
        self.path.append(request.identifier)
    }

    /// Reads the picked file, which has to be a card to open the import sheet. A card is a fixed size, so
    /// anything else is refused without being read.
    private func loadCardFile(_ result: Result<URL, Error>) {
        guard case .success(let url) = result else { return }

        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }

        guard
            (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) == IntroductionCard.byteCount,
            let data = try? Data(contentsOf: url),
            IntroductionCard.recognize(data) != nil
        else {
            self.cardFileError = true
            return
        }
        self.cardImportData = CardImportData(data: data)
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

/// A card's bytes, to present the import sheet with.
struct CardImportData: Identifiable {
    let id = UUID()
    let data: Data
}

// MARK: - Contact Row

struct ContactRowV2: View {
    let contact: Contact.Profile
    /// Computed once per pass by the list that owns the row, not here: it decrypts.
    let status: VerificationStatus
    /// The live line of a pending card, shown in place of the draft and fingerprint lines.
    var cardLine: CardRowLine? = nil
    let showFingerprint: Bool
    var hasDraft: Bool = false

    private var givenName:  String { self.contact.givenName.decrypt() }
    private var familyName: String { self.contact.familyName.decrypt() }

    private var thumbnail: Data? {
        self.contact.imageData?.decrypt() ?? self.contact.thumbnailImageData?.decrypt()
    }

    private func text(for line: CardRowLine, at now: Date) -> String {
        switch line {
        case .issued(let expiresAt): IntroCardCopy.issuedListLine(expiresAt: expiresAt, now: now)
        case .sendBy(let expiresAt): IntroCardCopy.sendByListLine(expiresAt: expiresAt, now: now)
        }
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
                        .fill(self.status.color)
                        .frame(width: 6, height: 6)

                    if let cardLine = self.cardLine {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            Text(self.text(for: cardLine, at: context.date))
                                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                                .foregroundStyle(Color.occultaWarn)
                                .monospacedDigit()
                                .lineLimit(1)
                        }
                    } else if self.hasDraft {
                        Text("Draft")
                            .font(.system(size: 10, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    } else if self.showFingerprint, let fp = self.contact.fingerprintPreview {
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
            CountColumn(count: self.unverified, label: IntroCardCopy.notVerifiedChip.uppercased(), color: .occultaWarn)
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

struct SectionHeaderV2: View {
    private let label: String
    private let color: Color
    private let dashed: Bool

    init(status: VerificationStatus) {
        self.label  = status.sectionLabel
        self.color  = status.color
        self.dashed = status == .pending
    }

    /// For sections that aren't keyed to a verification status — the picker's groups section.
    init(label: String, color: Color = .secondary) {
        self.label  = label
        self.color  = color
        self.dashed = false
    }

    var body: some View {
        HStack(spacing: 6) {
            if self.dashed {
                Circle()
                    .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [3, 2]))
                    .frame(width: 8, height: 8)
                    .foregroundStyle(.secondary)
            } else {
                Circle().fill(self.color).frame(width: 8, height: 8)
            }
            Text(self.label)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .tracking(1.6)
        }
    }
}

// MARK: - Group Row

struct GroupRowV2: View {
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
