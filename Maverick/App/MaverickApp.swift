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

    var body: some Scene {
        WindowGroup {
            TabView {
                Tab("Contacts", systemImage: "person.2.fill") {
                    Contacts()
                        .tag(Tabs.contacts)
                }
                
                Tab("Settings", systemImage: "gearshape.fill") {
                    Settings()
                        .tag(Tabs.settings)
                }
            }
            .onOpenURL { url in
                let accessing = url.startAccessingSecurityScopedResource()
                defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                
                if let data = try? Data(contentsOf: url) {
                    print("Opened file with \(data.count) bytes")
                } else {
                    debugPrint("No data after opening file, url = \(url.absoluteString)")
                }
            }
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
    }
}
