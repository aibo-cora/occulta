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
        @AppStorage("showFingerprints") private var showFingerprints = false
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

        @Query private var configs: [AppLayerConfig]

        @State private var showingPINSheet          = false
        @State private var showingSetupFlow         = false
        @State private var showingDeactivateSheet   = false

        private var requiresPIN:        Bool { self.configs.first?.sealedNormalVerifier != nil }
        private var isSecureModeActive: Bool { self.configs.first?.sealedDuressVerifier != nil }

        /// True when the current operator is at their home depth with Secure Mode active and
        /// the gate up. Governs both the toggle's disabled state and the Deactivate button.
        private var isAtSecureModeHomeDepth: Bool {
            self.isSecureModeActive && self.security.state == .normal
            && (self.security.currentDepth == 0
                || self.security.currentDepth == self.security.coercerBaseDepth)
            && self.security.pinEnabled
        }

        private var pinEnabledBinding: Binding<Bool> {
            Binding(
                // True only when a PIN is configured AND the gate overlay is active at
                // this depth. When `pinEnabled` is false (gate lowered under coercion),
                // the toggle appears off even though verifiers are intact — this is the
                // tell-avoidance invariant: the toggle must look identical to a device
                // with no PIN.
                get: { self.requiresPIN && self.security.pinEnabled },
                set: { _ in self.showingPINSheet = true }
            )
        }

        var body: some View {
            List {
                Section {
                    Toggle("Enable PIN", isOn: self.pinEnabledBinding)
                        .disabled(self.isAtSecureModeHomeDepth)
                }

                // Activate shown when: no Secure Mode configured, OR state is .duress
                // (decoy layer — user can add another layer), OR gate is lowered under coercion.
                // state == .duress (not currentDepth > 0): after the user adds their own SM
                // layer, coercerBaseDepth = depth flips state to .normal, hiding this section.
                if !self.isSecureModeActive || self.security.state == .duress || !self.security.pinEnabled {
                    Section {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Learn how you can protect your data.")
                                .font(.subheadline)
                            Button("Learn more") { self.showingSetupFlow = true }
                                .font(.subheadline).fontWeight(.semibold)
                        }
                        .padding(.vertical, 4)
                    }
                    .disabled(!self.requiresPIN)
                    .opacity(!self.requiresPIN ? 0.4 : 1)
                }

                if self.isAtSecureModeHomeDepth {
                    Section {
                        Button("Deactivate Protection", role: .destructive) {
                            self.showingDeactivateSheet = true
                        }
                    }
                }
            }
            .navigationTitle("Security")
            .sheet(isPresented: self.$showingPINSheet) {
                if !self.requiresPIN {
                    // No verifier exists yet. Enter + confirm a new PIN.
                    PINEntry(mode: .setup, onAuthenticated: { pin in
                        try? self.security.configurePIN(pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                } else if !self.security.pinEnabled {
                    // Gate lowered under coercion. Re-enable via existing PIN (normal or duress).
                    // UX is identical to initial setup — no observable tell from which matched.
                    PINEntry(mode: .setup, onAuthenticated: { pin in
                        _ = self.security.reEnablePIN(pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                } else if !self.isSecureModeActive {
                    // Normal PIN set, no duress verifier. User is turning PIN off entirely.
                    PINEntry(mode: .verifyCurrentLayer, onAuthenticated: { pin in
                        try? self.security.deactivatePIN(confirmingNormalPIN: pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                } else if self.security.state == .duress || self.security.currentDepth > 0 {
                    // Coercion path — lower the gate at the current depth without removing
                    // verifiers. Covers both the legacy .duress state and the multi-layer
                    // .normal state at depth > 0 (reached via routing alias).
                    PINEntry(mode: .verifyCurrentLayer, onAuthenticated: { pin in
                        try? self.security.disablePIN(at: self.security.currentDepth, confirmingPIN: pin)
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
            // Deactivate Secure Mode
            .sheet(isPresented: self.$showingDeactivateSheet) {
                SecureModeDeactivateFlow()
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
