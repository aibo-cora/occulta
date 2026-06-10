//
//  SecureModeSetupFlow.swift
//  Occulta
//
//  Full 4-step activation flow: Education → PIN setup → Contact classification → Review.
//  Presented as a sheet from Settings → Security.
//

import SwiftUI
import SwiftData

// MARK: - Flow

struct SecureModeSetupFlow: View {

    @Environment(\.dismiss)             private var dismiss
    @Environment(Manager.Security.self) private var security
    @Environment(ContactManager.self)   private var contactManager
    @Environment(VaultManager.self)     private var vaultManager

    @State private var path = NavigationPath()

    private enum Step: Hashable {
        case pinSetup
        case contacts(normalPIN: String, duressPIN: String)
        case summary(normalPIN: String, duressPIN: String)
    }

    var body: some View {
        NavigationStack(path: self.$path) {
            EducationView(onContinue: {
                self.path.append(Step.pinSetup)
            })
            .navigationTitle("Secure Mode")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { self.dismiss() }
                }
                ToolbarItem(placement: .principal) {
                    StepDots(total: 4, current: 0)
                }
            }
            .navigationDestination(for: Step.self) { step in
                switch step {
                case .pinSetup:
                    PINEntry(mode: .confirmThenSet { normal, duress in
                        self.path.append(Step.contacts(normalPIN: normal, duressPIN: duress))
                    })
                    .navigationTitle("Secure Mode")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .principal) {
                            StepDots(total: 4, current: 1)
                        }
                    }

                case .contacts(let normalPIN, let duressPIN):
                    ContactClassification(
                        confirmLabel: "Next",
                        onConfirm:    { self.path.append(Step.summary(normalPIN: normalPIN, duressPIN: duressPIN)) }
                    )
                    .toolbar {
                        ToolbarItem(placement: .principal) {
                            StepDots(total: 4, current: 2)
                        }
                    }

                case .summary(let normalPIN, let duressPIN):
                    SummaryView(
                        normalPIN: normalPIN,
                        duressPIN: duressPIN,
                        onDone:    { self.dismiss() }
                    )
                    .navigationTitle("Review")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .principal) {
                            StepDots(total: 4, current: 3)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Activating overlay

private struct ActivatingOverlay: View {
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            
            VStack(spacing: 16) {
                ProgressView()
                    .progressViewStyle(.circular)
                    .tint(.white)
                    .scaleEffect(1.2)
                Text("Securing your data…")
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(.white.opacity(0.8))
            }
        }
        .allowsHitTesting(true) // absorbs all taps
    }
}

// MARK: - Step dots

private struct StepDots: View {
    let total:   Int
    let current: Int  // 0-indexed

    var body: some View {
        HStack(spacing: 5) {
            ForEach(0..<self.total, id: \.self) { i in
                Capsule()
                    .fill(i == self.current ? Color.occultaAccent : Color.secondary.opacity(0.3))
                    .frame(width: i == self.current ? 16 : 6, height: 6)
                    .animation(.spring(duration: 0.2), value: self.current)
            }
        }
    }
}

// MARK: - Education

private struct EducationView: View {
    let onContinue: () -> Void

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Another layer of protection")
                        .font(.title3).fontWeight(.bold)
                    Text("Set up a secondary PIN that opens a limited, alternate view of your data.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
                .listRowSeparator(.hidden)
            }

            Section {
                FeatureRow(
                    icon: "key.fill",
                    color: .occultaAccent,
                    title: "Secondary PIN",
                    description: "A separate PIN that opens an alternate, limited view of your contacts."
                )
                FeatureRow(
                    icon: "person.fill",
                    color: Color(.systemRed),
                    title: "Hidden contacts",
                    description: "Choose which contacts are visible. Others won't appear in the alternate view."
                )
                FeatureRow(
                    icon: "archivebox.fill",
                    color: Color(.systemOrange),
                    title: "Cleared vault",
                    description: "Vault items will not be visible in alternate views."
                )
            }

            Section {
                Button(action: self.onContinue) {
                    Text("Continue")
                        .frame(maxWidth: .infinity)
                        .fontWeight(.semibold)
                }
                .prominentButtonStyle()
                .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
            }
        }
        .listStyle(.insetGrouped)
    }
}

private struct FeatureRow: View {
    let icon:        String
    let color:       Color
    let title:       String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: self.icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(self.color)
                .frame(width: 32, height: 32)
                .background(self.color.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 2) {
                Text(self.title)
                    .font(.subheadline).fontWeight(.semibold)
                Text(self.description)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Summary

private struct SummaryView: View {
    let normalPIN: String
    let duressPIN: String
    let onDone:    () -> Void

    @Environment(Manager.Security.self) private var security
    @Environment(ContactManager.self)   private var contactManager
    @Environment(VaultManager.self)     private var vaultManager
    @Query(Contact.Profile.descriptor)  private var contacts: [Contact.Profile]

    @State private var isActivating     = false
    @State private var activationFailed = false

    private var sensitiveCount: Int {
        self.contacts.filter { self.contactManager.isSensitive($0.identifier) }.count
    }

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Ready to activate")
                        .font(.title3).fontWeight(.bold)
                    Text("Review what will change. This cannot be undone without your PIN.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
                .listRowSeparator(.hidden)
            }

            Section {
                SummaryRow(
                    icon: "checkmark.circle.fill",
                    color: .green,
                    title: "Secondary PIN set",
                    detail: "Hidden for security"
                )
                SummaryRow(
                    icon: "checkmark.circle.fill",
                    color: .green,
                    title: self.sensitiveCount == 0
                        ? "No contacts hidden"
                        : "\(self.sensitiveCount) contact\(self.sensitiveCount == 1 ? "" : "s") will be hidden",
                    detail: "Not visible in alternate view"
                )
                SummaryRow(
                    icon: "checkmark.circle.fill",
                    color: .green,
                    title: "Vault will be cleared",
                    detail: "Messages inaccessible from alternate view"
                )
            }

            Section {
                Label(
                    "Deleting the app while Secure Mode is active is unrecoverable.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.footnote)
                .foregroundStyle(Color(.systemOrange))
                .listRowBackground(Color(.systemOrange).opacity(0.08))
            }

            Section {
                Button {
                    self.isActivating = true
                    let cm = self.contactManager

                    Task {
                        try? await Task.sleep(for: .milliseconds(50))

                        do {
                            try await self.security.activateSecureMode(
                                confirmingEntryPIN: self.normalPIN,
                                duressPIN:          self.duressPIN,
                                contactManager:     cm,
                                vaultManager:       self.vaultManager
                            )
                            cm.syncShareIndex()
                            self.isActivating = false
                            self.onDone()
                        } catch Manager.Security.SecurityError.invalidStateTransition {
                            // Secure Mode is already active (duress state). The flow was
                            // opened for tell-avoidance — the UI looks identical to pinOnly.
                            // Silently dismiss rather than showing an error that would reveal
                            // the app is in a protected state.
                            self.isActivating = false
                            self.onDone()
                        } catch Manager.Security.SecurityError.pinCollision {
                            // The proposed duress PIN matches an existing verifier. Showing
                            // "Activation Failed" would reveal that protected verifiers exist —
                            // a direct tell that Secure Mode is active. Silently dismiss so
                            // collision and success are indistinguishable from the outside.
                            // NOTE: this does not fully close the oracle attack — see Bug 62.
                            self.isActivating = false
                            self.onDone()
                        } catch {
                            debugPrint("Error activating [\(type(of: error))]: \(error)")
                            self.isActivating     = false
                            self.activationFailed = true
                        }
                    }
                } label: {
                    Text("Activate")
                        .frame(maxWidth: .infinity)
                        .fontWeight(.semibold)
                }
                .disabled(self.isActivating)
                .prominentButtonStyle()
                .tint(Color.occultaAccent)
                .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
            }
        }
        .listStyle(.insetGrouped)
        .overlay {
            if self.isActivating {
                ActivatingOverlay()
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: self.isActivating)
        .interactiveDismissDisabled(self.isActivating)
        .navigationBarBackButtonHidden()
        .alert("Activation Failed", isPresented: self.$activationFailed) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Secure Mode could not be activated. Your data is unchanged. Please try again.")
        }
    }
}

private struct SummaryRow: View {
    let icon:   String
    let color:  Color
    let title:  String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: self.icon)
                .foregroundStyle(self.color)
                .font(.system(size: 20))

            VStack(alignment: .leading, spacing: 2) {
                Text(self.title)
                    .font(.subheadline).fontWeight(.semibold)
                Text(self.detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Preview

#Preview {
    let container = try! ModelContainer(
        for: Schema([AppLayerConfig.self, Contact.Profile.self,
                     Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
                     Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self,
                     Contact.Profile.Key.self]),
        configurations: [ModelConfiguration(isStoredInMemoryOnly: true)]
    )
    SecureModeSetupFlow()
        .modelContainer(container)
        .environment(Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
}
