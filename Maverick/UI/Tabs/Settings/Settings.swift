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

struct Export: View {
    @State private var generator: Manager.PassphraseGenerator = .init()
    
    @State private var passphrase: String = ""
    @State private var exportedFile: URL?
    @State private var exporting = false
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
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
                        
                        
                    }
                } header: {
                    Text("Encryption Passphrase")
                } footer: {
                    Text("Remember this passphrase or store it in a Password Manager.")
                }
                
                Options(exportedFile: self.$exportedFile, passphrase: self.passphrase)
                
                if let exportedFile {
                    Section("Save to Files") {
                        HStack {
                            Spacer()
                            
                            VStack() {
                                Button {
                                    self.exporting = true
                                } label: {
                                    HStack {
                                        Text("Export")
                                        
                                        Image(systemName: "square.and.arrow.up.fill")
                                    }
                                }
                                .fileExporter(isPresented: self.$exporting, item: exportedFile, contentTypes: [.data], defaultFilename: "contacts.maverick", onCompletion: { result in
                                    switch result {
                                    case .success(let url):
                                        let accessing = url.startAccessingSecurityScopedResource()
                                        defer {
                                            if accessing {
                                                url.stopAccessingSecurityScopedResource()
                                            }
                                        }
                                        
                                        if let contents = try? Data(contentsOf: url) {
                                            print("Exported successfully, contents = \(contents), url = \(url.absoluteString)")
                                        } else {
                                            debugPrint("No contents..., url = \(url)")
                                        }
                                    case .failure(let error):
                                        print("Failed to export: \(error)")
                                    }
                                    
                                }, onCancellation: {
                                    
                                })
                                .prominentButtonStyle()
                                
                                Text("Created on \(self.contactManager.dateFormatter.string(from: Date()))")
                                    .font(.footnote)
                            }
                            .padding()
                            
                            Spacer()
                        }
                    }
                }
            }
            .task {
                self.passphrase = self.generator.generate()
            }
        }
    }
    
    private struct Options: View {
        @State private var useCloud = false
        @State private var useFile = false
        
        @Environment(ContactManager.self) private var contactManager: ContactManager
        
        @State private var porter = Manager.Porter()
        @Binding private var exportedFile: URL?
        
        let passphrase: String
        
        init(exportedFile: Binding<URL?>, passphrase: String) {
            self._exportedFile = exportedFile
            self.passphrase = passphrase
        }
        
        var body: some View {
            Section("Options") {
                Toggle("iCloud", systemImage: "icloud.fill", isOn: self.$useCloud)
                    .disabled(true)
                Toggle("File", systemImage: "doc.fill", isOn: self.$useFile)
                    .padding(.bottom)
            }
            
            HStack(spacing: 20) {
                Spacer()
                
                Button {
                    do {
                        let encryptedContactExport = try self.contactManager.prepareForExporting(using: self.passphrase)
                        let url = try self.porter.export(data: encryptedContactExport)
                        
                        self.exportedFile = url
                    } catch {
                        debugPrint("Could not export contacts: \(error)")
                    }
                } label: {
                    Text("Encrypt")
                }
                .prominentButtonStyle()
                .disabled(self.useFile == false)
                
                Spacer()
            }
            .padding()
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
