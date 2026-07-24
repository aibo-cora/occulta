//
//  TrustCheckV2.swift
//  Occulta
//
//  "Trust Check" — a scenario-first entry point at the bottom of Contact.DetailsV2
//  that routes a plain-language event about a contact to whichever existing
//  security/identity action already addresses it. No new cryptography: every
//  destination here (Revoke Key, Identity Challenge, the Visibility toggle)
//  reuses the app's existing security primitives directly — this is now the
//  sole surface for Revoke Key and the Visibility toggle, not a duplicate of
//  one in Contact.FormV2. See Docs/Features/Master Feature & Expansion
//  Analysis.md #29 for the full design history and rationale.
//

import SwiftUI

// MARK: - Eligibility

/// Pure, SE-independent eligibility checks — kept separate from both views below
/// so they're unit-testable without constructing any SwiftUI hierarchy, and so
/// `Contact.TrustCheckV2` and its sheet don't each maintain their own copy.
extension Contact.Profile {
    /// Revocable whenever the last key hasn't already been revoked.
    /// Deliberately not tied to verified/unverified — revoking doesn't
    /// require the key to have matched an owner hash.
    var trustCheckCanRevokeKey: Bool {
        guard let key = self.contactPublicKeys?.last else { return false }
        return key.expiredOn == nil
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

private struct TrustCheckSheetV2: View {
    let profile: Contact.Profile

    @Environment(\.dismiss) private var dismissSheet
    @Environment(ContactManager.self) private var contactManager

    @State private var showRevokeConfirm = false
    @State private var isSensitive = false

    private var canRevokeKey: Bool { self.profile.trustCheckCanRevokeKey }
    private var canChallenge: Bool { self.profile.trustCheckCanChallenge }

    private var displayName: String {
        let name = self.profile.givenName.decrypt()
        return name.isEmpty ? "this contact" : name
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    self.header

                    VStack(spacing: 10) {
                        if self.canRevokeKey { self.revokeCard }
                        if self.canChallenge { self.challengeCard }
                        self.hideCard
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
        }
        .presentationDetents([.medium, .large])
        .task {
            self.isSensitive = self.contactManager.isSensitive(self.profile.identifier)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            ZStack {
                avatarGradientV2(for: self.profile.identifier)
                Text(self.displayName.initials)
                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .frame(width: 44, height: 44)
            .clipShape(Circle())

            VStack(alignment: .leading, spacing: 2) {
                Text("What happened with \(self.displayName)?")
                    .font(.system(size: 16, weight: .bold))
                Text("Pick what's going on — you'll land on the right action")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var revokeCard: some View {
        Button(role: .destructive) {
            self.showRevokeConfirm = true
        } label: {
            self.scenarioCard(
                icon: "key.horizontal.fill",
                tint: Color.occultaDanger,
                title: "\(self.displayName)'s phone was lost or stolen",
                subtitle: "Revoke the key so it's no longer trusted"
            )
        }
        .buttonStyle(.plain)
        .confirmationDialog("Warning", isPresented: self.$showRevokeConfirm) {
            Button("Revoke", role: .destructive) {
                try? self.contactManager.reset(identity: self.profile.identifier)
                self.dismissSheet()
            }
        } message: {
            Text("A new key exchange needs to happen after revoking this contact's public key. Are you sure?")
        }
    }

    private var challengeCard: some View {
        NavigationLink {
            ChallengeDestinationV2(profile: self.profile)
        } label: {
            self.scenarioCard(
                icon: "checkmark.shield",
                tint: Color.occultaAccent,
                title: "I got a suspicious call or message from \(self.displayName)",
                subtitle: "Confirm the key still answers"
            )
        }
    }

    private var hideCard: some View {
        NavigationLink {
            HideDestinationV2(profile: self.profile)
        } label: {
            if self.isSensitive {
                self.scenarioCard(
                    icon: "eye",
                    tint: Color.occultaVerified,
                    title: "Mark \(self.displayName) safe again",
                    subtitle: "Remove Secure Mode protection"
                )
            } else {
                self.scenarioCard(
                    icon: "eye.slash",
                    tint: Color.occultaVerified,
                    title: "Hide \(self.displayName) if my phone is forced open",
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
