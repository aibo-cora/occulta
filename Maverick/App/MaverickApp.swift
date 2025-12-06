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
                Contact.Profile.URLAddress.self
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

    var body: some Scene {
        WindowGroup {
            Contacts()
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
    }
}
