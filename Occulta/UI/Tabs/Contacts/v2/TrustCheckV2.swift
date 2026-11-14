//
//  TrustCheckV2.swift
//  Occulta
//
//  "Trust Check" — a scenario-first entry point, opened from the Contacts tab
//  ("Something happened?") and from the bottom of Contact.DetailsV2, that routes a
//  plain-language event to whichever existing security/identity action already
//  addresses it. What it says lives in TrustCheckPlaybook.swift; the contact
//  picker is TrustCheckPicker.swift. No new cryptography: every
//  destination here (Revoke Key, Identity Challenge, the Visibility toggle)
//  reuses the app's existing security primitives directly — this is now the
//  sole surface for Revoke Key and the Visibility toggle, not a duplicate of
//  one in Contact.FormV2. See Docs/Features/Master Feature & Expansion
//  Analysis.md #29 for the full design history and rationale.
//

import SwiftUI
import SwiftData

// MARK: - Eligibility

/// Pure, SE-independent eligibility checks — kept separate from both views below
/// so they're unit-testable without constructing any SwiftUI hierarchy, and so
/// `Contact.TrustCheckV2` and its sheet don't each maintain their own copy.
extension Contact.Profile {
    /// Revocable whenever the last key hasn't already been revoked.
    /// Deliberately not tied to verified/unverified — revoking doesn't
    /// require the key to have matched an owner hash.
    var trustCheckCanRevokeKey: Bool {
        self.currentKey != nil
    }

    /// Mirrors the exact gate `ContactDetailV2` already uses to decide whether
    /// to render `IdentityChallenge.VerifyIdentityButton` at all.
    var trustCheckCanChallenge: Bool {
        self.verificationStatus == .verified
    }
}

extension Contact {
    /// Entry point card. Marking a contact safe or hidden is always a valid
    /// action, so — unlike Revoke Key and Identity Challenge — this card
    /// never hides itself for lack of an eligible scenario.
    struct TrustCheckV2: View {
        let profile: Contact.Profile

        @State private var showSheet = false

        /// The minor version Trust Check shipped in. Compared against
        /// `major.minor` only, so patch/hotfix releases (e.g. 1.10.1) don't
        /// clear the badge — only the next minor version does.
        static let introducedInVersion = "1.10"

        private var showsNewBadge: Bool {
            Bundle.main.appVersion.split(separator: ".").prefix(2).joined(separator: ".") == Self.introducedInVersion
        }

        var body: some View {
            Button {
                self.showSheet = true
            } label: {
                HStack(spacing: 11) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 18))
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Trust Check")
                            .font(.system(size: 16, weight: .medium))
                        Text("For when something feels off")
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .foregroundStyle(Color.occultaAccent)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .overlay(alignment: .topTrailing) {
                if self.showsNewBadge {
                    Text("NEW")
                        .font(.system(size: 9.5, weight: .heavy))
                        .tracking(0.8)
                        .foregroundStyle(Color.occultaAccent)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 3.5)
                        .background(Color(.systemBackground), in: Capsule())
                        .shadow(color: .black.opacity(0.18), radius: 6, y: 3)
                        .offset(x: -14, y: -8)
                }
            }
            .sheet(isPresented: self.$showSheet) {
                TrustCheckSheetV2(profile: self.profile)
            }
        }
    }
}

// MARK: - Sheet

/// Where the sheet can go from its scenario list. Only identifiers and enum cases: the chosen scenario and contact
/// live in the navigation stack's state, never anywhere that outlives the sheet.
enum TrustCheckRoute: Hashable {
    case picker(TrustScenario)
    case remedy(TrustScenario, identifier: String?)
}

/// The one Trust Check sheet. From the Contacts tab it has no contact (`profile` nil) and asks which, when the
/// scenario is about one; from contact detail it has one and skips the picker.
struct TrustCheckSheetV2: View {
    let profile: Contact.Profile?

    @Environment(\.dismiss) private var dismissSheet
    @Environment(ContactManager.self) private var contactManager
    @Environment(Manager.Security.self) private var security

    @Query(Contact.Profile.descriptor) private var contacts: [Contact.Profile]

    private var scenarios: [TrustScenario] {
        if let profile = self.profile {
            return TrustScenario.allCases.filter { $0.needsContact && $0.lists(profile) }
        }

        return TrustScenario.allCases.filter(\.isOffered)
    }

    private var isSensitive: Bool {
        guard let profile = self.profile else { return false }

        return self.contactManager.isSensitive(profile.identifier)
    }

    /// A contact the picker or the detail screen named, among the ones visible at this depth.
    private func resolve(_ identifier: String?) -> Contact.Profile? {
        guard let identifier else { return nil }

        if let profile = self.profile, profile.identifier == identifier { return profile }

        return ContactListFilter.visibleContacts(self.contacts, atDepth: self.security.currentDepth)
            .first { $0.identifier == identifier }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    self.header

                    VStack(spacing: 10) {
                        ForEach(self.scenarios, id: \.self) { scenario in
                            NavigationLink(value: self.route(for: scenario)) {
                                self.scenarioCard(
                                    icon: scenario.icon,
                                    tint: scenario.tint,
                                    title: scenario.title(name: self.profile.map(TrustCheckNames.firstName(of:))),
                                    subtitle: scenario.subtitle
                                )
                            }
                            .buttonStyle(.plain)
                        }

                        if let profile = self.profile {
                            self.hideCard(for: profile)
                        }
                    }
                }
                .padding(16)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Trust Check")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { self.dismissSheet() }
                }
            }
            .navigationDestination(for: TrustCheckRoute.self) { route in
                switch route {
                case .picker(let scenario):
                    TrustCheckPickerV2(scenario: scenario)
                case .remedy(let scenario, let identifier):
                    TrustCheckRemedyV2(scenario: scenario, profile: self.resolve(identifier)) { self.dismissSheet() }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func route(for scenario: TrustScenario) -> TrustCheckRoute {
        if let profile = self.profile { return .remedy(scenario, identifier: profile.identifier) }

        return scenario.needsContact ? .picker(scenario) : .remedy(scenario, identifier: nil)
    }

    @ViewBuilder
    private var header: some View {
        if let profile = self.profile {
            let name = TrustCheckNames.firstName(of: profile)

            HStack(spacing: 12) {
                TrustCheckAvatar(profile: profile, size: 44)

                VStack(alignment: .leading, spacing: 2) {
                    Text("What happened with \(name)?")
                        .font(.system(size: 16, weight: .bold))
                    Text("Pick what's going on — you'll land on the right action")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }
        } else {
            VStack(alignment: .leading, spacing: 4) {
                Text("What happened?")
                    .font(.system(size: 26, weight: .bold))
                Text("Pick what's going on — you'll land on the right action")
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func hideCard(for profile: Contact.Profile) -> some View {
        let name = TrustCheckNames.firstName(of: profile)

        return NavigationLink {
            HideDestinationV2(profile: profile)
        } label: {
            if self.isSensitive {
                self.scenarioCard(
                    icon: "eye",
                    tint: Color.occultaVerified,
                    title: "Mark \(name) safe again",
                    subtitle: "Remove Secure Mode protection"
                )
            } else {
                self.scenarioCard(
                    icon: "eye.slash",
                    tint: Color.occultaVerified,
                    title: "Hide \(name) if my phone is forced open",
                    subtitle: "Move into Secure Mode protection"
                )
            }
        }
    }

    private func scenarioCard(icon: String, tint: Color, title: String, subtitle: String) -> some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(tint)
                Image(systemName: icon)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: 38, height: 38)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
                    .multilineTextAlignment(.leading)
                Text(subtitle)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(15)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .shadow(color: .black.opacity(0.10), radius: 10, y: 5)
    }
}

private extension TrustScenario {
    var icon: String {
        switch self {
        case .suspiciousMessage: "checkmark.shield"
        case .lostPhone:         "key.horizontal.fill"
        case .newPhone:          "iphone"
        case .notVerified:       "exclamationmark.circle"
        case .strangerCard:      "person.crop.rectangle"
        case .fileWontOpen:      "doc.text.magnifyingglass"
        case .signedText:        "signature"
        case .other:             "questionmark.circle"
        }
    }

    var tint: Color {
        switch self {
        case .suspiciousMessage: Color.occultaAccent
        case .lostPhone:         Color.occultaDanger
        case .newPhone:          Color.blue
        case .notVerified:       Color.occultaWarn
        case .strangerCard, .fileWontOpen, .signedText, .other: Color.gray
        }
    }
}

// MARK: - Remedy

/// What to do, for this scenario and this contact's state: the contact's avatar and name, numbered steps, and the
/// action when there is one. Revoke is here so it is reachable from the top level; the confirmation names the contact.
private struct TrustCheckRemedyV2: View {
    let scenario: TrustScenario
    let profile: Contact.Profile?
    /// Closes the whole sheet. This view is pushed, so its own `dismiss` would only pop it.
    let onFinished: () -> Void

    @Environment(ContactManager.self) private var contactManager

    @State private var showRevokeConfirm = false

    var body: some View {
        ScrollView {
            if self.scenario.needsContact && self.profile == nil {
                Text("This contact is no longer available.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(16)
            } else {
                self.remedyBody
            }
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Trust Check")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var remedyBody: some View {
        let status = self.profile?.verificationStatus ?? .pending
        let name = self.profile.map(TrustCheckNames.firstName(of:))
        let remedy = TrustRemedy.make(for: self.scenario, profile: self.profile)
        let content = remedy.content(for: self.scenario, status: status, name: name)

        return VStack(alignment: .leading, spacing: 14) {
            if let profile = self.profile {
                HStack(spacing: 12) {
                    TrustCheckAvatar(profile: profile, size: 44)

                    VStack(alignment: .leading, spacing: 3) {
                        Text(TrustCheckNames.fullName(of: profile))
                            .font(.system(size: 16, weight: .bold))
                        Text(status.trustCheckLabel)
                            .font(.system(size: 11.5, weight: .semibold))
                            .foregroundStyle(status.color)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 2)
                            .background(status.color.opacity(0.14), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    }
                }
            }

            Text(content.heading)
                .font(.system(size: 22, weight: .bold))

            VStack(spacing: 10) {
                ForEach(Array(content.steps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .top, spacing: 12) {
                        if content.steps.count > 1 {
                            Text("\(index + 1)")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundStyle(Color.occultaAccent)
                                .frame(width: 26, height: 26)
                                .background(Color.occultaAccent.opacity(0.14), in: Circle())
                        }

                        Text(step)
                            .font(.system(size: 14.5))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(14)
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
            }

            if let footnote = content.footnote {
                Text(footnote)
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }

            if let profile = self.profile {
                self.action(for: remedy, profile: profile, name: TrustCheckNames.firstName(of: profile))
            }
        }
        .padding(16)
    }

    @ViewBuilder
    private func action(for remedy: TrustRemedy, profile: Contact.Profile, name: String) -> some View {
        switch remedy {
        case .revoke:
            Button(role: .destructive) {
                self.showRevokeConfirm = true
            } label: {
                Label(RevokeConfirmationCopy.button(name: name), systemImage: "key.horizontal.fill")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, minHeight: 52)
                    .background(Color.occultaDanger, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
            .buttonStyle(.plain)
            .padding(.top, 8)
            .confirmationDialog(RevokeConfirmationCopy.title(name: name), isPresented: self.$showRevokeConfirm, titleVisibility: .visible) {
                Button("Revoke", role: .destructive) {
                    try? self.contactManager.reset(identity: profile.identifier)
                    self.onFinished()
                }
            } message: {
                Text(RevokeConfirmationCopy.message)
            }

        case .challenge:
            NavigationLink {
                ChallengeDestinationV2(profile: profile)
            } label: {
                Label("Send \(name) a Challenge", systemImage: "checkmark.shield")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, minHeight: 52)
                    .background(Color.occultaAccent, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
            .padding(.top, 8)

        case .meetInPerson, .alreadyVerified, .explain:
            EmptyView()
        }
    }
}

// MARK: - Identity Challenge destination

private struct ChallengeDestinationV2: View {
    let profile: Contact.Profile

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                IdentityChallenge.VerifyIdentityButton(contact: self.profile)
                    .padding(.top, 24)
            }
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Identity Challenge")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Hide contact destination

private struct HideDestinationV2: View {
    let profile: Contact.Profile

    @Environment(ContactManager.self) private var contactManager
    @State private var isSensitive = false
    @State private var isApplying = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Hidden entirely at any duress layer below this one — not just visually filtered.")
                .font(.footnote)
                .foregroundStyle(.secondary)

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Private contact")
                        .font(.system(size: 15))
                    Text("Hidden in alternate view")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if self.isApplying {
                    ProgressView()
                } else {
                    Toggle("", isOn: self.$isSensitive)
                        .labelsHidden()
                        .tint(Color.occultaDanger)
                        .onChange(of: self.isSensitive) { _, newValue in
                            // setVisibility re-encrypts every group's membership slots
                            // (Group.refreshCiphertext, deliberate forensic camouflage —
                            // see Docs/Bugs/v1.10.0) and can take several seconds. This
                            // Task exists so SwiftUI paints the spinner before that block
                            // starts, and so the toggle can't be double-tapped mid-save —
                            // it does not move the work off the main thread.
                            Task { @MainActor in
                                self.isApplying = true
                                try? self.contactManager.setVisibility(for: self.profile.identifier, isSensitive: newValue)
                                self.isApplying = false
                            }
                        }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            Spacer()
        }
        .padding(16)
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Mark Private")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            self.isSensitive = self.contactManager.isSensitive(self.profile.identifier)
        }
    }
}
