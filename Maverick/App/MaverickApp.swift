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
    
    var sharedModelContainer: ModelContainer
    
    init() {
        let sharedModelContainer: ModelContainer = {
            let schema = Schema([
                Contact.Profile.self,
                Contact.Profile.PhoneNumber.self,
                Contact.Profile.EmailAddress.self,
                Contact.Profile.PostalAddress.self,
                Contact.Profile.URLAddress.self,
                Contact.Profile.Key.self
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
    
    @State private var openedEncryptedFileContents: File?

    var body: some Scene {
        WindowGroup {
            TabView {
                Contacts()
                    .tag(Tabs.contacts)
                    .tabItem {
                        Tabs.contacts.image
                        Tabs.contacts.name
                    }
                
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
                
                Settings()
                    .tag(Tabs.settings)
                    .tabItem {
                        Tabs.settings.image
                        Tabs.settings.name
                    }
            }
            .onOpenURL { url in
                do {
                    let accessing = url.startAccessingSecurityScopedResource()
                    defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                    
                    let contents = try Data(contentsOf: url)
                    let fileContents = try JSONDecoder().decode(File.self, from: contents)
                    
                    self.openedEncryptedFileContents = fileContents
                } catch {
                    debugPrint("Error reading data, error = \(error)")
                }
            }
            .sheet(item: self.$openedEncryptedFileContents) {
                /// Dismiss
            } content: { data in
                Import(fileContents: data)
            }
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
    }
}
