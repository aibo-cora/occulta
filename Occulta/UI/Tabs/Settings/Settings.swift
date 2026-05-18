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

                NavigationLink("Security") {
                    SecuritySettings()
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
        @Environment(\.dismiss) private var dismiss

        @State private var showingPINSheet          = false
        @State private var showingActivateSheet     = false
        @State private var showingDeactivateSheet   = false

        private var pinEnabledBinding: Binding<Bool> {
            Binding(
                get: { self.security.requiresPIN },
                set: { _ in self.showingPINSheet = true }
            )
        }

        var body: some View {
            List {
                Toggle("Enable PIN", isOn: self.pinEnabledBinding)
                    .disabled(self.security.state == .active || self.security.state == .duress)

                if self.security.state == .pinOnly {
                    Button("Activate Secure Mode") {
                        self.showingActivateSheet = true
                    }
                }

                if self.security.state == .active {
                    Button("Deactivate Secure Mode", role: .destructive) {
                        self.showingDeactivateSheet = true
                    }
                }
            }
            .navigationTitle("Security")
            // Enable / disable PIN
            .sheet(isPresented: self.$showingPINSheet) {
                if self.security.requiresPIN {
                    PINEntry(onNormal: { pin in
                        try? self.security.deactivatePIN(confirmingNormalPIN: pin)
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                } else {
                    PINEntry(mode: .setup, onNormal: { _ in
                        self.showingPINSheet = false
                    })
                    .environment(self.security)
                }
            }
            // Activate Secure Mode: confirm normal PIN, then set duress PIN
            .sheet(isPresented: self.$showingActivateSheet) {
                PINEntry(
                    mode: .confirmThenSet { normalPIN, duressPIN in
                        try? self.security.activateSecureMode(
                            confirmingNormalPIN: normalPIN,
                            duressPIN:           duressPIN
                        )
                        self.showingActivateSheet = false
                    }
                )
                .environment(self.security)
            }
            // Deactivate Secure Mode: confirm normal PIN (no counter mutation)
            .sheet(isPresented: self.$showingDeactivateSheet) {
                PINEntry(mode: .verifyNormal, onNormal: { pin in
                    try? self.security.deactivateSecureMode(confirmingNormalPIN: pin)
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
