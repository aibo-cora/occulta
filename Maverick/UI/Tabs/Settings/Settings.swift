//
//  Settings.swift
//  Maverick
//
//  Created by Yura on 12/9/25.
//

import SwiftUI
import SwiftData
internal import UniformTypeIdentifiers

struct Settings: View {
    private struct Export: View {
        @State private var showingExportOptions = false
        /// Stored contacts.
        @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
        
        var body: some View {
            if FeatureFlags.isEnabled(.usePassphraseToExportContacts) {
                if self.contacts.isEmpty {
                    Text("You will be able to export contacts here once you have added some.")
                        .font(.caption)
                        .padding()
                } else {
                    VStack(spacing: 20) {
                        Text("Create a file with your contacts encrypted using a passphrase.")
                            .multilineTextAlignment(.center)
                            .font(.caption)
                        
                        Button {
                            self.showingExportOptions = true
                        } label: {
                            Text("Export Contacts")
                        }
                        .navigationTitle("Settings")
                        .sheet(isPresented: self.$showingExportOptions) {
                            
                        } content: {
                            Export()
                        }
                        .prominentButtonStyle()
                    }
                    .padding()
                }
            }
        }
    }
    
    var body: some View {
        NavigationStack {
            List {
                NavigationLink("My Identity") {
                    MyIdentity()
                }
                
                NavigationLink("Project Info") {
                    ProjectInfo()
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
                }
                
                Spacer()
                
                ResetMasterKey()
            }
        }
    }
    
    private struct ProjectInfo: View {
        var body: some View {
            VStack(spacing: 20) {
                Text("This application is **open-source**. Check out the code on [GitHub](https://github.com/aibo-cora/maverick). Make suggestions, help us improve and even contribute!")
            }
            .padding()
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
