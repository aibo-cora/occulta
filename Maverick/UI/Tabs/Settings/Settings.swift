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
    
    var body: some View {
        NavigationStack {
            List {
                if self.contacts.isEmpty {
                    
                } else {
                    Section {
                        Button {
                            self.showingExportOptions = true
                        } label: {
                            Text("Export Contacts")
                                .frame(maxWidth: .infinity)
                        }
                    } header: {
                        Text("Backup")
                    } footer: {
                        Text("Create a file with your contacts encrypted using a passphrase.")
                    }
                }
            }
            .navigationTitle("Settings")
            .sheet(isPresented: self.$showingExportOptions) {
                
            } content: {
                Export()
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
