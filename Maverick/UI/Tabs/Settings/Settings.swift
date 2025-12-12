//
//  Settings.swift
//  Maverick
//
//  Created by Yura on 12/9/25.
//

import SwiftUI
import SwiftData

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

struct Export: View {
    @State private var porter = Manager.Porter()
    @State private var generator: Manager.PassphraseGenerator = .init()
    
    @State private var passphrase: String = ""
    
    @State private var buttonStyle: any PrimitiveButtonStyle = .borderedProminent
    
    var body: some View {
        VStack {
            List {
                Section {
                    VStack(spacing: 20) {
                        Text("To store a backup, we first need to decrypt all your contacts that are encrypted with your private key. Another key, derived from the passphrase below, will be used to encrypt the backup.")
                            .font(.footnote)
                        
                        Divider()
                        
                        HStack {
                            Text(self.passphrase)
                                .font(.custom("Courier", size: 20))
                                .lineLimit(1)
                                .minimumScaleFactor(0.5)
                                .bold()
                        }
                        .padding(.top)
                        
                        
                        HStack(spacing: 20) {
                            Button {
                                self.passphrase = self.generator.generate()
                            } label: {
                                HStack {
                                    Image(systemName: "arrow.clockwise")
                                    Text("Refresh")
                                }
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Color.accentColor)
                            
                            Spacer()
                            
                            Button {
                                
                            } label: {
                                HStack {
                                    Image(systemName: "doc.on.doc")
                                    Text("Copy")
                                }
                            }
                        }
                        .padding(.bottom)
                        
                        Divider()
                        
                        VStack(spacing: 20) {
                            Toggle("iCloud", systemImage: "icloud.fill", isOn: .constant(true))
                            Toggle("File", systemImage: "doc.fill", isOn: .constant(true))
                        }
                        .padding()
                        
                        Button {
                            /// Encrypt
                        } label: {
                            Text("Encrypt & Export")
                        }
                        .prominentButtonStyle()
                    }
                } header: {
                    Text("Encryption Passphrase")
                } footer: {
                    Text("Remember this passphrase or store it in a Password Manager.")
                }
            }
            .task {
                self.passphrase = self.generator.generate()
            }
        }
    }
}

#Preview {
    Settings()
        .environment(ContactManager.preview)
}

#Preview {
    Export()
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
