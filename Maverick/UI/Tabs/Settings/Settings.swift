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
    @State private var showingExportOptions = false
    /// Stored contacts.
    @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
    
    var identityHash: String {
        let identity = try? Manager.Key().retrieveIdentity()
        let hash = identity?.sha256.hexEncodedString() ?? "Undefined"
        
        return hash
    }
    
    @State private var displayingIdentityInfo: Bool = false
    
    var body: some View {
        NavigationStack {
            VStack {
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
                
                VStack(spacing: 20) {
                    HStack {
                        Text("My identity")
                        
                        Button {
                            self.displayingIdentityInfo.toggle()
                        } label: {
                            Image(systemName: "info.bubble")
                        }
                    }
                    
                    if self.displayingIdentityInfo {
                        Text("This is **SHA256** hash of your public key. It is used to uniquely identify you.")
                    }
                    
                    Text(self.identityHash.uppercased())
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding()
                
                #if DEBUG || targetEnvironment(simulator)
                Spacer()

                Button("Reset Master Key", role: .destructive) {
                    
                }
                .padding()
                .prominentButtonStyle()
                #endif
            }
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
