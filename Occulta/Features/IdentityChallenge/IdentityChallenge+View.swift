//
//  IdentityChallenge+View.swift
//  Occulta
//
//  SwiftUI surfaces for the three phases of identity challenge:
//
//    Challenger side
//    ── VerifyIdentityButton   — entry point on Contact.Details
//    ── EducationalSheet       — "sensitive requests should come via Occulta"
//    ── ContextNoteSheet       — optional freetext before sharing
//    ── VerifiedBadge          — transient "Verified N ago" under the button
//
//    Responder side
//    ── IncomingChallengeSheet — auto-presented on inbound `.identityChallenge`
//
//    Challenger side (phase 3)
//    ── VerificationResultSheet — auto-presented on inbound response envelope
//
//  The sheets read/write state on `IdentityChallenge.Coordinator`, which lives
//  in the environment. None of them do crypto directly.
//

import SwiftUI
import Combine

// MARK: - Verify-Identity button + flow (challenger side, on Contact.Details)

extension IdentityChallenge {

    /// Entry point rendered below the primary actions on `Contact.Details`.
    ///
    /// Shows a transient "Verified N ago" caption on success. Disables itself
    /// while a challenge to this contact is already outstanding — the 1-per-
    /// contact rate limit would throw anyway.
    struct VerifyIdentityButton: View {
        let contact: Contact.Profile

        @Environment(IdentityChallenge.Coordinator.self) private var coordinator: IdentityChallenge.Coordinator?

        @State private var showEducational = false
        @State private var showNoteInput   = false
        @State private var noteDraft       = ""
        @State private var errorMessage: String?

        /// A running tick so the "N minutes ago" caption updates without a
        /// full view rebuild. 30-second cadence is plenty for minute resolution.
        @State private var now: Date = Date()
        private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

        private var hasOutstanding: Bool {
            self.coordinator?.store.hasOutstanding(for: self.contact.identifier) ?? false
        }
        
        private var hasValidIdentity: Bool {
            self.contact.contactPublicKeys?.last?.expiredOn != nil
        }

        private var verifiedCaption: String? {
            self.coordinator?.verifiedBadge(for: self.contact.identifier, now: self.now)
        }

        var body: some View {
            VStack(spacing: 8) {
                Button {
                    self.showEducational = true
                } label: {
                    Label("Verify Identity", systemImage: "checkmark.shield")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .disabled(self.hasOutstanding || self.hasValidIdentity)

                if self.hasOutstanding {
                    Text("Verification in progress. Send the shared file to \(self.displayName), then open their response.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                if let caption = self.verifiedCaption {
                    Label(caption, systemImage: "checkmark.seal.fill")
                        .font(.footnote)
                        .foregroundStyle(.green)
                }
            }
            .padding(.horizontal)
            .onReceive(self.tick) { self.now = $0 }
            .sheet(isPresented: self.$showEducational) {
                EducationalSheet(
                    contactName: self.displayName,
                    onContinue: {
                        self.showEducational = false
                        self.showNoteInput = true
                    },
                    onCancel: { self.showEducational = false }
                )
            }
            .sheet(isPresented: self.$showNoteInput) {
                ContextNoteSheet(
                    note: self.$noteDraft,
                    onSend: {
                        self.showNoteInput = false
                        self.createChallenge()
                    },
                    onCancel: {
                        self.showNoteInput = false
                        self.noteDraft = ""
                    }
                )
            }
            .alert("Couldn't start verification", isPresented: .constant(self.errorMessage != nil)) {
                Button("OK") { self.errorMessage = nil }
            } message: {
                Text(self.errorMessage ?? "")
            }
        }

        private var displayName: String {
            let name = self.contact.givenName.decrypt()
            return name.isEmpty ? "this contact" : name
        }

        private func createChallenge() {
            guard let coordinator = self.coordinator else { return }
            let trimmed = self.noteDraft.trimmingCharacters(in: .whitespacesAndNewlines)
            do {
                try coordinator.createChallenge(
                    for:         self.contact,
                    contextNote: trimmed.isEmpty ? nil : trimmed
                )
                self.noteDraft = ""
            } catch IdentityChallenge.ManagerError.rateLimited {
                self.errorMessage = "A verification is already in progress for this contact."
            } catch {
                self.errorMessage = "Could not create verification request."
            }
        }
    }

    // MARK: - Educational interstitial

    struct EducationalSheet: View {
        let contactName: String
        let onContinue: () -> Void
        let onCancel:   () -> Void

        var body: some View {
            NavigationStack {
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.shield")
                        .font(.system(size: 44))
                        .foregroundStyle(.yellow)
                    Text("Before you verify")
                        .font(.title2.bold())
                    Text("If \(self.contactName) has Occulta, sensitive requests should come through it — not through Telegram or WhatsApp. That alone may be a warning sign.")
                        .font(.callout)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                    Spacer()
                }
                .padding(.top, 40)
                .safeAreaInset(edge: .bottom) {
                    VStack(spacing: 8) {
                        Button {
                            self.onContinue()
                        } label: {
                            Text("Continue to verify")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        Button("Cancel", role: .cancel, action: self.onCancel)
                    }
                    .padding()
                }
            }
            .presentationDetents([.medium])
        }
    }

    // MARK: - Context-note input

    struct ContextNoteSheet: View {
        @Binding var note: String
        let onSend:   () -> Void
        let onCancel: () -> Void

        /// Live byte count — UTF-8, matching `maxContextNoteBytes`.
        private var byteCount: Int { self.note.utf8.count }

        var body: some View {
            NavigationStack {
                Form {
                    Section {
                        TextField(
                            "What do you want to ask? (optional)",
                            text: self.$note,
                            axis: .vertical
                        )
                        .lineLimit(4...10)
                    } header: {
                        Text("Your question")
                    } footer: {
                        let max = IdentityChallenge.maxContextNoteBytes
                        HStack {
                            Text("Example: \"Someone on Telegram is asking me for 18,000. Was this you?\"")
                            Spacer()
                            Text("\(self.byteCount)/\(max)")
                                .foregroundStyle(self.byteCount > max ? .red : .secondary)
                                .monospacedDigit()
                        }
                    }
                    Section {
                        Text("Send this through a different channel than where the suspicious message came from.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                .navigationTitle("Verify Identity")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel", action: self.onCancel)
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Share", action: self.onSend)
                    }
                }
            }
            .presentationDetents([.medium, .large])
        }
    }

    // MARK: - Incoming challenge (responder)

    struct IncomingChallengeSheet: View {
        let incoming: IdentityChallenge.Coordinator.IncomingChallenge
        let onApprove: () -> Void
        let onDecline: () -> Void

        var body: some View {
            NavigationStack {
                VStack(spacing: 20) {
                    Image(systemName: "person.badge.shield.checkmark")
                        .font(.system(size: 48))
                        .foregroundStyle(.blue)

                    Text("\(self.incoming.pending.challengerName) is verifying your identity")
                        .font(.title3.bold())
                        .multilineTextAlignment(.center)

                    if let note = self.incoming.pending.contextNote, !note.isEmpty {
                        // Plain text only — per spec, never render as markdown/HTML.
                        VStack(alignment: .leading, spacing: 4) {
                            Text("They ask:")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(verbatim: note)
                                .font(.callout)
                                .italic()
                                .textSelection(.enabled)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
                        .padding(.horizontal)
                    }

                    Text("Approving will use Face ID / Touch ID to sign a one-time proof. No message content is shared.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)

                    Spacer()
                }
                .padding(.top, 40)
                .safeAreaInset(edge: .bottom) {
                    VStack(spacing: 8) {
                        Button {
                            self.onApprove()
                        } label: {
                            Text("Approve")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        Button("Deny", role: .destructive, action: self.onDecline)
                    }
                    .padding()
                }
                .navigationTitle("Identity Verification")
                .navigationBarTitleDisplayMode(.inline)
            }
            .interactiveDismissDisabled()
        }
    }

    // MARK: - Verification result (challenger)

    struct VerificationResultSheet: View {
        let outcome: IdentityChallenge.Coordinator.VerificationOutcome
        let onDismiss: () -> Void

        var body: some View {
            NavigationStack {
                VStack(spacing: 20) {
                    Image(systemName: self.outcome.passed
                          ? "checkmark.seal.fill"
                          : "xmark.seal.fill")
                        .font(.system(size: 56))
                        .foregroundStyle(self.outcome.passed ? .green : .red)

                    Text(self.outcome.passed
                         ? "Identity verified"
                         : "Verification failed")
                        .font(.title2.bold())

                    Text(self.outcome.passed
                         ? "\(self.outcome.contactName) controls their device."
                         : "This may not be \(self.outcome.contactName). If they may have lost their device, re-exchange keys in person.")
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)

                    if let note = self.outcome.contextNote, !note.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("You asked:")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(verbatim: note)
                                .font(.callout)
                                .italic()
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
                        .padding(.horizontal)
                    }

                    Spacer()
                }
                .padding(.top, 40)
                .safeAreaInset(edge: .bottom) {
                    Button {
                        self.onDismiss()
                    } label: {
                        Text("Done")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .padding()
                }
                .navigationTitle("Verification")
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }
}
