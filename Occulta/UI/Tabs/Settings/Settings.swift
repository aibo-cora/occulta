//
//  Settings.swift
//  Occulta
//
//  Created by Yura on 12/9/25.
//

import SwiftUI
import SwiftData
import UniformTypeIdentifiers

struct Settings: View {
    var body: some View {
        NavigationStack {
            List {
                NavigationLink("My Identity") {
                    MyIdentity()
                }

                NavigationLink("Contact List") {
                    ContactListSettings()
                }

                NavigationLink("Project Info") {
                    ProjectInfo()
                }

                NavigationLink("Manage Contacts") {
                    ManageContacts()
                }

                if FeatureFlags.isEnabled(.secureMode) {
                    NavigationLink("Security") {
                        SecuritySettings()
                    }
                }
            }
            
            VStack {
                Image(systemName: "info.circle")
                    .font(.largeTitle)
                    .padding()
                    
                Text("App Version: \(Bundle.main.appVersion)")
                    .font(.headline)
                
                Text("Build Number: \(Bundle.main.buildNumber)")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
    }
    
    private struct MyIdentity: View {
        @State private var displayingIdentityInfo: Bool = false
        
        var identityHash: String {
            let identity = try? Manager.Key().retrieveIdentity()
            let hash = identity?.sha256.hexEncodedString() ?? "Undefined"
            
            return hash
        }
        
        var body: some View {
            VStack {
                VStack(spacing: 20) {
                    HStack {
                        Text("My identity")
                            .font(.headline)
                        
                        Button {
                            self.displayingIdentityInfo.toggle()
                        } label: {
                            Image(systemName: "info.bubble")
                        }
                    }
                    
                    if self.displayingIdentityInfo {
                        Text("This is **SHA256** hash of your public key. It is used to uniquely identify you.")
                            .padding(.horizontal)
                    }
                    
                    Text(self.identityHash.uppercased())
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal)
                }
                
                Spacer()
                
                ResetMasterKey()
            }
        }
    }
    
    private struct ContactListSettings: View {
        @AppStorage("showFingerprints") private var showFingerprints = true
        @AppStorage("showTrustSummary") private var showTrustSummary = true

        var body: some View {
            List {
                Toggle("Show fingerprints", isOn: $showFingerprints)
                Toggle("Show trust summary card", isOn: $showTrustSummary)
            }
            .navigationTitle("Contact List")
        }
    }

    private struct ProjectInfo: View {
        var body: some View {
            VStack(spacing: 20) {
                Text("This application is **open-source**. Check out the code on [GitHub](https://github.com/aibo-cora/occulta). Make suggestions, help us improve and even contribute!")
            }
            .padding()
        }
    }
    
    private struct ManageContacts: View {
        @Environment(Manager.App.self) private var appManager: Manager.App

        var body: some View {
            VStack(spacing: 20) {
                Text("Delete **entire** contact database, vault, private keys and stored messages.")
                Text("This cannot be undone.").italic()

                Button("Delete", role: .destructive) {
                    try? self.appManager.eraseAllData()
                }
                .prominentButtonStyle()
            }
            .padding()
        }
    }
    
    private struct SecuritySettings: View {
        @Environment(Manager.Security.self) private var security
        @Environment(ContactManager.self)   private var contactManager
        @Environment(VaultManager.self)     private var vaultManager
        @Environment(\.dismiss) private var dismiss

        @State private var showingPINSheet          = false
        @State private var showingSetupFlow         = false
        @State private var showingDeactivateSheet   = false

        private var pinEnabledBinding: Binding<Bool> {
            Binding(
                // True only when a PIN is configured AND the gate overlay is active.
                // When `appLockEnabled` is false (gate lowered under coercion), the toggle
                // appears off even though verifiers are intact — this is the tell-avoidance
                // invariant: the toggle must look identical to a device with no PIN.
                get: { self.security.requiresPIN && self.security.appLockEnabled },
                set: { _ in self.showingPINSheet = true }
            )
        }

        var body: some View {
            List {
                Section {
                    // The toggle is interactive in every state — including .active and .duress.
                    // Disabling it in those states was a forensic tell (visible UI difference
                    // between normal and duress mode). Instead, toggling off in .active/.duress
                    // lowers the gate without removing verifiers via disablePINFromCurrentDepth.
                    Toggle("Enable PIN", isOn: self.pinEnabledBinding)
                }

                if self.security.state == .noPIN || self.security.state == .pinOnly || self.security.state == .duress {
                    Section {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Learn how you can protect your data.")
                                .font(.subheadline)
                            Button("Learn more") { self.showingSetupFlow = true }
                                .font(.subheadline).fontWeight(.semibold)
                        }
                        .padding(.vertical, 4)
                    }
                    .disabled(self.security.state == .noPIN)
                    .opacity(self.security.state == .noPIN ? 0.4 : 1)
                }

                if self.security.state == .active {
                    Section {
                        Button("Deactivate Protection", role: .destructive) {
                            self.showingDeactivateSheet = true
                        }
                    }
                }
            }
            .navigationTitle("Security")
            .sheet(isPresented: self.$showingPINSheet) {
                if !self.security.requiresPIN {
                    // State: .noPIN — no verifier exists yet. Enter + confirm a new PIN,
                    // then call configurePIN so the caller's closure owns the security op.
                    PINEntry(mode: .setup, onNormal: { pin in
                        try? self.security.configurePIN(pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                } else if !self.security.appLockEnabled {
                    // State: gate lowered under coercion. The user wants to re-enable.
                    // Enter + confirm the existing PIN (normal or duress); reEnablePIN
                    // silently routes to the matched verifier depth. UX is identical to
                    // initial setup — no observable tell from which verifier matched.
                    PINEntry(mode: .setup, onNormal: { pin in
                        _ = self.security.reEnablePIN(pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                } else if self.security.state == .pinOnly {
                    // State: .pinOnly — normal PIN set, no duress verifier. User is
                    // turning PIN off entirely. Verify with no counter mutation so a
                    // wrong guess here does not advance the wipe counter.
                    PINEntry(mode: .verifyNormal, onNormal: { pin in
                        try? self.security.deactivatePIN(confirmingNormalPIN: pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                } else {
                    // State: .active or .duress — Secure Mode is live. User is toggling
                    // "off" to lower the gate without removing verifiers (coercion path).
                    // Enter + confirm the current layer's PIN to authorise the gate drop.
                    PINEntry(mode: .setup, onNormal: { pin in
                        try? self.security.disablePINFromCurrentDepth(confirmingPIN: pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                }
            }
            // Secure Mode setup flow
            .sheet(isPresented: self.$showingSetupFlow) {
                SecureModeSetupFlow()
                    .environment(self.security)
            }
            // Deactivate Secure Mode: confirm normal PIN (no counter mutation)
            .sheet(isPresented: self.$showingDeactivateSheet) {
                PINEntry(mode: .verifyNormal, onNormal: { pin in
                    let cm = self.contactManager
                    let vm = self.vaultManager
                    Task {
                        try? await self.security.deactivateSecureMode(
                            confirmingEntryPIN: pin,
                            contactManager:     cm,
                            vaultManager:       vm
                        )
                    }
                    self.showingDeactivateSheet = false
                })
                .environment(self.security)
            }
        }
    }

    private struct ResetMasterKey: View {
        var body: some View {
            #if DEBUG || targetEnvironment(simulator)
            Button("Reset Identity Key", role: .destructive) {
                
            }
            .padding()
            .prominentButtonStyle()
            #endif
        }
    }
    
}

#Preview {
    Settings()
        .environment(ContactManager.preview)
}

extension View {
    func prominentButtonStyle() -> some View {
        modifier(AdaptiveProminentButtonModifier())
    }
}

struct AdaptiveProminentButtonModifier: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            // Use the new style for iOS 26 and later
            content
                .buttonStyle(.glassProminent)
        } else {
            // Fall back to an older style for iOS 17 (and earlier)
            content
                .buttonStyle(.borderedProminent)
        }
    }
}

extension Bundle {
    var appVersion: String {
        return infoDictionary?["CFBundleShortVersionString"] as? String ?? "N/A"
    }
    
    var buildNumber: String {
        return infoDictionary?["CFBundleVersion"] as? String ?? "N/A"
    }
}
