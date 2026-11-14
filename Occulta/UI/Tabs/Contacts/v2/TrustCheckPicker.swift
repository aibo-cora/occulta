//
//  TrustCheckPicker.swift
//  Occulta
//
//  "Which contact?" for the Trust Check scenarios that are about one. It lists everyone a playbook can be
//  run for and marks who it can't act on, instead of hiding them: someone looking for the person a caller
//  claims to be has to find them, and a Not verified contact is where the advice matters most.
//
//  Every row comes from `ContactListFilter`, the one filter every list of contacts goes through (Bug 25 /
//  Bug 28). The list and its empty state are built from the contacts visible at the current depth, so a
//  contact hidden at this depth never appears and nothing here is counted or marked over all stored contacts.
//
//  Like the Contacts list, a pass derives the local DB key once and opens every field under it: the body runs
//  on every keystroke in the search field, and each `decrypt()` would derive afresh
//  (`Docs/Bugs/v2.1.0/Contact-List-Hangs-From-Uncached-Key-Derivation-In-Body.md`).
//

import SwiftUI
import SwiftData
import CryptoKit

enum TrustCheckPicker {

    struct Row: Equatable {
        let identifier: String
        let givenName: String
        let familyName: String
        let status: VerificationStatus
        let remedy: TrustRemedy
        let line: String
    }

    struct Rows {
        /// Contacts the scenario's own action applies to: first.
        let acting: [Row]
        /// The rest, below a divider.
        let rest: [Row]
        /// Whether no contact is listed for the scenario at `depth`, before any search text narrows it.
        let isEmpty: Bool

        static let empty = Rows(acting: [], rest: [], isEmpty: true)
    }

    /// `key` is the local DB key the caller derived for this pass. Without one nothing is listed, as in the
    /// Contacts list.
    static func rows(
        for scenario: TrustScenario,
        contacts: [Contact.Profile],
        atDepth depth: Int,
        matching searchText: String,
        usingKey key: SymmetricKey?
    ) -> Rows {
        guard let key else { return .empty }

        // Visibility, names, search and sort are the shared filter's, in its one-pass form.
        let listing = ContactListFilter.listing(contacts, atDepth: depth, matching: searchText, usingKey: key)

        // The status opens the key owner hash and, with no keys, the card field: once per contact.
        let ourHash = (try? Manager.Ambient.keyManager.retrieveIdentity())?.sha256
        let statuses = Dictionary(
            listing.visible.map { ($0.contact.identifier, $0.contact.statusAndCard(using: key, ourHash: ourHash).status) },
            uniquingKeysWith: { first, _ in first }
        )

        let rows = listing.shown.compactMap { entry -> Row? in
            guard let status = statuses[entry.contact.identifier], scenario.lists(status: status) else { return nil }

            let remedy = TrustRemedy.make(for: scenario, status: status, canRevoke: entry.contact.trustCheckCanRevokeKey)

            return Row(
                identifier: entry.contact.identifier, givenName: entry.givenName, familyName: entry.familyName,
                status: status, remedy: remedy, line: remedy.line(for: scenario, status: status)
            )
        }

        return Rows(
            acting: rows.filter { $0.remedy.actsOnContact },
            rest: rows.filter { !$0.remedy.actsOnContact },
            isEmpty: !statuses.values.contains { scenario.lists(status: $0) }
        )
    }
}

// MARK: - View

struct TrustCheckPickerV2: View {
    let scenario: TrustScenario

    @Environment(Manager.Security.self) private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]

    @State private var searchText = ""

    var body: some View {
        let key = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey()
        let rows = TrustCheckPicker.rows(for: self.scenario, contacts: self.contacts, atDepth: self.security.currentDepth, matching: self.searchText, usingKey: key)

        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(self.scenario.pickerTitle)
                    .font(.system(size: 26, weight: .bold))

                if rows.isEmpty {
                    Text(self.scenario.emptyListText)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else {
                    self.group(rows.acting)

                    if !rows.acting.isEmpty && !rows.rest.isEmpty {
                        Divider()
                    }

                    self.group(rows.rest)
                }
            }
            .padding(16)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Trust Check")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: self.$searchText, placement: .navigationBarDrawer(displayMode: .always), prompt: "Find a contact…")
        .autocorrectionDisabled()
    }

    @ViewBuilder
    private func group(_ rows: [TrustCheckPicker.Row]) -> some View {
        if !rows.isEmpty {
            VStack(spacing: 0) {
                ForEach(rows, id: \.identifier) { row in
                    NavigationLink(value: TrustCheckRoute.remedy(self.scenario, identifier: row.identifier)) {
                        TrustCheckPickerRow(row: row)
                    }
                    .buttonStyle(.plain)

                    if row.identifier != rows.last?.identifier {
                        Divider().padding(.leading, 66)
                    }
                }
            }
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }
}

private struct TrustCheckPickerRow: View {
    let row: TrustCheckPicker.Row

    var body: some View {
        HStack(spacing: 12) {
            TrustCheckAvatar(identifier: self.row.identifier, givenName: self.row.givenName, familyName: self.row.familyName, size: 40)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(TrustCheckNames.fullName(given: self.row.givenName, family: self.row.familyName))
                        .font(.system(size: 16, weight: .semibold))
                        .lineLimit(1)

                    Text(self.row.status.trustCheckLabel)
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(self.row.status.color)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(self.row.status.color.opacity(0.14), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                }

                Text(self.row.line)
                    .font(.system(size: 13))
                    .foregroundStyle(self.row.remedy == .revoke ? Color.occultaDanger : .secondary)
                    .multilineTextAlignment(.leading)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .contentShape(Rectangle())
    }
}

// MARK: - Shared bits

extension VerificationStatus {
    /// The word on a picker row's chip.
    var trustCheckLabel: String {
        switch self {
        case .verified:   "Verified"
        case .unverified: IntroCardCopy.notVerifiedChip
        case .pending:    "Pending"
        }
    }
}

enum TrustCheckNames {
    /// "this contact" where there's no name to say, as the sheet has always done.
    static func firstName(given: String) -> String {
        given.isEmpty ? "this contact" : given
    }

    static func fullName(given: String, family: String) -> String {
        let name = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        return name.isEmpty ? "this contact" : name
    }

    /// A contact's names under the pass's key. Nothing opens without one.
    static func names(of profile: Contact.Profile, key: SymmetricKey?) -> (given: String, family: String) {
        guard let key else { return ("", "") }

        return (profile.givenName.decrypt(using: key), profile.familyName.decrypt(using: key))
    }

    /// A contact's status under the pass's key. Pending without one, the status of a contact nothing is known about.
    static func status(of profile: Contact.Profile, key: SymmetricKey?) -> VerificationStatus {
        guard let key else { return .pending }

        return profile.statusAndCard(using: key, ourHash: (try? Manager.Ambient.keyManager.retrieveIdentity())?.sha256).status
    }
}

struct TrustCheckAvatar: View {
    let identifier: String
    let givenName: String
    let familyName: String
    let size: CGFloat

    var body: some View {
        ZStack {
            avatarGradientV2(for: self.identifier)
            Text([self.givenName, self.familyName].filter { !$0.isEmpty }.joined(separator: " ").initials)
                .font(.system(size: self.size * 0.35, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: self.size, height: self.size)
        .clipShape(Circle())
    }
}
