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

import SwiftUI
import SwiftData

enum TrustCheckPicker {

    struct Row: Equatable {
        let identifier: String
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
    }

    static func rows(
        for scenario: TrustScenario,
        contacts: [Contact.Profile],
        atDepth depth: Int,
        matching searchText: String
    ) -> Rows {
        let visible = ContactListFilter.visibleContacts(contacts, atDepth: depth)
        // The status is read once per contact: it decrypts, and the rest follows from it.
        let listed = visible.map { (profile: $0, status: $0.verificationStatus) }.filter { scenario.lists(status: $0.status) }
        let statuses = Dictionary(listed.map { ($0.profile.identifier, $0.status) }, uniquingKeysWith: { first, _ in first })

        let sorted = ContactListFilter.sortedContacts(listed.map(\.profile), matching: searchText)

        let rows = sorted.map { profile -> Row in
            let status = statuses[profile.identifier] ?? .pending
            let remedy = TrustRemedy.make(for: scenario, status: status, canRevoke: profile.trustCheckCanRevokeKey)

            return Row(identifier: profile.identifier, status: status, remedy: remedy, line: remedy.line(for: scenario, status: status))
        }

        return Rows(
            acting: rows.filter { $0.remedy.actsOnContact },
            rest: rows.filter { !$0.remedy.actsOnContact },
            isEmpty: ContactListFilter.isEmptyList(listed.map(\.profile), atDepth: depth)
        )
    }
}

// MARK: - View

struct TrustCheckPickerV2: View {
    let scenario: TrustScenario

    @Environment(Manager.Security.self) private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]

    @State private var searchText = ""

    private var rows: TrustCheckPicker.Rows {
        TrustCheckPicker.rows(for: self.scenario, contacts: self.contacts, atDepth: self.security.currentDepth, matching: self.searchText)
    }

    var body: some View {
        let rows = self.rows

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
                    if let profile = self.contacts.first(where: { $0.identifier == row.identifier }) {
                        NavigationLink(value: TrustCheckRoute.remedy(self.scenario, identifier: row.identifier)) {
                            TrustCheckPickerRow(profile: profile, row: row)
                        }
                        .buttonStyle(.plain)

                        if row.identifier != rows.last?.identifier {
                            Divider().padding(.leading, 66)
                        }
                    }
                }
            }
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }
}

private struct TrustCheckPickerRow: View {
    let profile: Contact.Profile
    let row: TrustCheckPicker.Row

    private var name: String {
        TrustCheckNames.fullName(of: self.profile)
    }

    var body: some View {
        HStack(spacing: 12) {
            TrustCheckAvatar(profile: self.profile, size: 40)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(self.name)
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
    static func firstName(of profile: Contact.Profile) -> String {
        let name = profile.givenName.decrypt()
        return name.isEmpty ? "this contact" : name
    }

    static func fullName(of profile: Contact.Profile) -> String {
        let name = [profile.givenName.decrypt(), profile.familyName.decrypt()].filter { !$0.isEmpty }.joined(separator: " ")
        return name.isEmpty ? "this contact" : name
    }
}

struct TrustCheckAvatar: View {
    let profile: Contact.Profile
    let size: CGFloat

    var body: some View {
        ZStack {
            avatarGradientV2(for: self.profile.identifier)
            Text([self.profile.givenName.decrypt(), self.profile.familyName.decrypt()].filter { !$0.isEmpty }.joined(separator: " ").initials)
                .font(.system(size: self.size * 0.35, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: self.size, height: self.size)
        .clipShape(Circle())
    }
}
