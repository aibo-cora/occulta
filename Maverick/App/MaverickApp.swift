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
    
    enum Tabs: Hashable {
        case contacts, settings
    }
    
    @State private var openedEncryptedFileContents: File?

    var body: some Scene {
        WindowGroup {
            TabView {
                Contacts()
                    .tag(Tabs.contacts)
                    .tabItem {
                        Image(systemName: "person.2.fill")
                        Text("Contacts")
                    }
                
                Settings()
                    .tag(Tabs.settings)
                    .tabItem {
                        Image(systemName: "gearshape.fill")
                        Text("Settings")
                    }
            }
            .onOpenURL { url in
                do {
                    let accessing = url.startAccessingSecurityScopedResource()
                    defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                    
                    self.openedEncryptedFileContents = File(content: try Data(contentsOf: url))
                } catch {
                    debugPrint("Error reading data, error = \(error)")
                }
            }
            .sheet(item: self.$openedEncryptedFileContents) {
                /// Dismiss
            } content: { message in
                Import(document: message.content)
            }
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
    }
}

struct File: Identifiable {
    let id = UUID()
    let content: Data
}
