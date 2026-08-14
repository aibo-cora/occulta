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

        @State private var name                = ""
        @State private var selectedIdentifiers = Set<String>()
        @State private var eligible:   [Contact.Profile] = []
        @State private var ineligible: [Contact.Profile] = []
        /// Identifiers within `ineligible` shown as "needs to update" rather than "no bundle
        /// received yet". Computed once alongside the partition so the header and rows never
        /// call into crypto during a render.
        ///
        /// Covers both the readable-but-old case and the stranded-marker case. Those are
        /// different states internally and must not be different here — see `computeEligibility`.
        @State private var ineligibleNeedsUpdate = Set<String>()
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
            // Read from the precomputed partition — this is evaluated on every body render.
            let hasOld     = !self.ineligibleNeedsUpdate.isEmpty
            let hasUnknown = self.ineligible.count > self.ineligibleNeedsUpdate.count
            
            if hasUnknown && hasOld {
                return "These contacts need a newer version of Occulta or haven't messaged you yet."
            }
            if hasOld { return "Ask them to update Occulta." }
            return "Version unknown — ask them to send you a message."
        }

        // selectedIdentifiers includes hidden/sensitive members' identifiers (seeded from
        // the group's raw per-depth member list), so this true total is what must gate
        // capacity — a hidden member still occupies a real slot.
        private var atCapacity: Bool {
            self.selectedIdentifiers.count >= Group.slotCount
        }

        // Displayed count intentionally excludes hidden members, matching GroupDetailV3's
        // member count for the same group. Using the raw selectedIdentifiers.count here
        // would print e.g. "30 / 32" while only 25 rows are visible/checkable — a countable
        // mismatch, and one that would disagree with the detail screen's "25 members" for
        // the identical group and depth. Both are concrete, calculable forensic tells.
        private var visibleSelectedCount: Int {
            self.eligible.filter { self.selectedIdentifiers.contains($0.identifier) }.count
        }

        private var membersHeader: String {
            self.visibleSelectedCount == 0
                ? "Members"
                : "Members · \(self.visibleSelectedCount) / \(Group.slotCount)"
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
            let subLabel   = self.ineligibleNeedsUpdate.contains(contact.identifier)
                ? "Needs to update Occulta"
                : "No bundle received yet"

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

        /// Partitions the contact list in one pass, under a single derived key.
        ///
        /// `Manager.Crypto` re-derives the hybrid local DB key on every `decrypt` call — no
        /// caching — so each of these checks is a Secure Enclave plus Keychain round trip. The
        /// previous shape cost roughly four per contact: two inside `isVisible(atDepth:)` for
        /// `originDepth` and `visibleThroughDepth`, then one for each of the two
        /// `resolveTargetVersion` filters, which asked the same question twice to build
        /// complementary lists. This runs at `.onAppear` and again on every `@Query` change,
        /// so on a few hundred contacts that was several hundred round trips per invocation —
        /// the cost profile that produced Bug 74's launch watchdog kill.
        ///
        /// Deriving once and passing the key down makes it one, total. `isVisible` and
        /// `bundleVersionState` both provide key-taking variants for exactly this caller.
        ///
        /// A `Set` difference would also remove the duplicate pass, but `contacts` arrives
        /// sorted by `Contact.Profile.descriptor` and set iteration order is not stable, so
        /// both lists would render in arbitrary order and could reshuffle between renders. A
        /// single pass into two arrays keeps the order and needs no `Hashable` contract.
        ///
        /// `needsUpdate` is captured here rather than recomputed in the view: the header and
        /// row label are evaluated on every body render, and calling into crypto from there
        /// puts Secure Enclave work on the main actor during typing and scrolling.
        private func computeEligibility() {
            guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else {
                // Matches the previous behaviour: without a key `isVisible` treats every
                // contact as hidden, so the lists were empty in this case before too.
                self.eligible = []
                self.ineligible = []
                self.ineligibleNeedsUpdate = []
                return
            }

            let depth = self.security.currentDepth
            var eligible:    [Contact.Profile] = []
            var ineligible:  [Contact.Profile] = []
            var needsUpdate: Set<String>       = []

            for contact in self.contacts where contact.isVisible(atDepth: depth, usingKey: key) {
                switch ContactManager.bundleVersionState(for: contact, using: key) {
                case .readable(let version) where version.supportsGroups:
                    eligible.append(contact)

                // Readable-but-old and stranded are deliberately shown the same way, and the
                // reason is forensic rather than cosmetic.
                //
                // A marker is stranded only by a local DB key rotation that predates
                // `maxBundleVersion` joining `reencryptAllFields` — i.e. only on installs that
                // activated Secure Mode while running 1.10.0 or 1.10.1. That rotation missed the
                // field for *every* contact at once, so on such a device every contact is
                // ineligible. Labelling them "no bundle received yet" states something the user
                // can see is false about anyone they are mid-conversation with, and anyone
                // holding the phone can read that contradiction straight off this screen without
                // sending anything. That is a duress oracle of exactly the shape
                // `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`
                // exists about, and cheaper to use than the one removed there, because it needs
                // no probe.
                //
                // "Needs to update" contradicts nothing observable on the device, and for the
                // stranded case it is also true in effect: the marker heals only when the
                // contact sends a bundle claiming 1.10.0 or newer — that is the floor
                // `updateMaxVersion` applies to an unreadable marker — so a contact who is
                // genuinely behind does need to update, and one who is not needs only to send
                // something. Either way the user's next step is the same, and it is the one
                // this label suggests.
                case .readable, .unreadable:
                    ineligible.append(contact)
                    needsUpdate.insert(contact.identifier)

                // Genuinely never heard from. The only case where "no bundle received yet" is
                // both accurate and consistent with what the user can see.
                case .unrecorded:
                    ineligible.append(contact)
                }
            }

            self.eligible              = eligible
            self.ineligible            = ineligible
            self.ineligibleNeedsUpdate = needsUpdate
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
