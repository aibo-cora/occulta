//
//  MaverickApp.swift
//  Maverick
//
//  Created by Yura on 10/13/25.
//

import SwiftUI
import SwiftData

@main
struct MaverickApp: App {
    @State private var contactManager: ContactManager
    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false
    
    var sharedModelContainer: ModelContainer
    
    init() {
        let sharedModelContainer: ModelContainer = {
            let schema = Schema([
                Contact.Profile.self,
                Contact.Profile.PhoneNumber.self,
                Contact.Profile.EmailAddress.self,
                Contact.Profile.PostalAddress.self,
                Contact.Profile.URLAddress.self,
                Contact.Profile.Key.self,
                Contact.Message.self,
            ])
            
            let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false)

            do {
                return try ModelContainer(for: schema, configurations: [modelConfiguration])
            } catch {
                fatalError("Could not create ModelContainer: \(error)")
            }
        }()
        
        self.sharedModelContainer = sharedModelContainer
        self.contactManager = ContactManager(modelContainer: sharedModelContainer)
    }
    
    enum Tabs: String, Hashable {
        case contacts, sign, verify, settings
        
        var image: Image {
            switch self {
            case .contacts:
                .init(systemName: "person.2.fill")
            case .sign:
                .init(systemName: "signature")
            case .settings:
                .init(systemName: "gearshape.fill")
            case .verify:
                .init(systemName: "checkmark.bubble")
            }
        }
        
        var name: some View {
            switch self {
            case .contacts:
                Text("Contacts")
            case .sign:
                Text("Sign")
            case .settings:
                Text("Settings")
            case .verify:
                Text("Verify")
            }
        }
    }
    /// Container with plaintext message or file.
    @State private var openedFileContents: OwnedBasket?
    /// Encrypted contacts database.
    @State private var openedEncryptedFileContents: EncryptedFile?

    var body: some Scene {
        WindowGroup {
            if self.hasCompleted == false {
                ForeverOnboardingView()
            } else {
                TabView {
                    Contacts()
                        .tag(Tabs.contacts)
                        .tabItem {
                            Tabs.contacts.image
                            Tabs.contacts.name
                        }
                    
                    if FeatureFlags.isEnabled(.signature) {
                        Sign()
                            .tag(Tabs.sign)
                            .tabItem {
                                Tabs.sign.image
                                Tabs.sign.name
                            }
                        
                        Verify()
                            .tag(Tabs.verify)
                            .tabItem {
                                Tabs.verify.image
                                Tabs.verify.name
                            }
                    }
                    
                    Settings()
                        .tag(Tabs.settings)
                        .tabItem {
                            Tabs.settings.image
                            Tabs.settings.name
                        }
                }
                .onOpenURL { url in
                    let accessing = url.startAccessingSecurityScopedResource()
                    
                    defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                    
                    if accessing {
                        do {
                            let data = try Data(contentsOf: url)
                            let decrypted = try self.contactManager.decrypt(data: data)
                            let basket = try JSONDecoder().decode(Basket.self, from: decrypted.plaintext)
                            
                            self.openedFileContents = OwnedBasket(basket: basket, owner: decrypted.ownerID)
                        } catch ContactManager.Errors.messageHasNoData {
                            debugPrint("Error reading data, no data.")
                        } catch ContactManager.Errors.noPublicKeyToEncryptWith {
                            if FeatureFlags.isEnabled(.usePassphraseToExportContacts) {
                                /// This file contains contacts or we don't have the owner's public key to decrypt the file of the file is corrupted.
                                let data = (try? Data(contentsOf: url)) ?? Data()
                                
                                self.openedEncryptedFileContents = EncryptedFile(content: data)
                            } else {
                                debugPrint("Importing a file encrypted with a passphrase is not enabled.")
                            }
                            
                            debugPrint("Could not find this file's owner's public key, it must contain contacts or is corrupted.")
                        } catch {
                            debugPrint("Error reading data, error = \(error)")
                        }
                    } else {
                        debugPrint("Could not access file data. Try saving the file in Files first and thentry opening it.")
                    }
                }
                .sheet(item: self.$openedFileContents) {
                    /// Dismiss
                } content: { data in
                    Import(imported: data)
                }
                .sheet(item: self.$openedEncryptedFileContents) { encryptedContactsFile in
                    Import.Contacts(encryptedFile: encryptedContactsFile)
                }
            }
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
    }
}
