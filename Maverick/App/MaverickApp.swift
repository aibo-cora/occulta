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
    var sharedModelContainer: ModelContainer = {
        let schema = Schema([
            Contact.self,
            PhoneNumber.self,
            EmailAddress.self,
            PostalAddressEntry.self,
            URLAddress.self
        ])
        
        let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false)

        do {
            return try ModelContainer(for: schema, configurations: [modelConfiguration])
        } catch {
            fatalError("Could not create ModelContainer: \(error)")
        }
    }()

    var body: some Scene {
        WindowGroup {
            Contacts()
        }
        .modelContainer(self.sharedModelContainer)
    }
}
