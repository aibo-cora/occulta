//
//  OccultaApp.swift
//  Occulta
//
//  Created by Yura on 10/13/25.
//

import SwiftUI
import SwiftData

@main
struct OccultaApp: App {
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
            
            let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false, cloudKitDatabase: .automatic)

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
    // Error feedback
    @State private var showError = false
    @State private var errorMessage = ""

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
                    
                    Task {
                        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                        /// Contents of the enrypted file we opened.
                        let (data, _) = try await URLSession.shared.data(from: url)
                        
                        do {
                            let ownedBasket = try await self.buildOwnedBasket(from: data)
                            
                            self.openedFileContents = ownedBasket
                        } catch ContactManager.Errors.messageHasNoData {
                            self.errorMessage = "This message contains no data."
                            self.showError = true
                        } catch ContactManager.Errors.noPublicKeyToEncryptWith {
                            self.errorMessage = "Could not find this file's owner's public key. It is either corrupted and you need to update the app and try again or the message was not addressed to you."
                            self.showError = true
                        } catch {
                            self.errorMessage = "There was an error. \(error.localizedDescription)"
                            self.showError = true
                        }
                    }
                }
                .alert("Error", isPresented: self.$showError) {
                    Button("OK") { }
                } message: {
                    Text(self.errorMessage)
                }
                .sheet(item: self.$openedFileContents) {
                    /// Dismiss
                } content: { data in
                    if FeatureFlags.isEnabled(.useComposableMessage) {
                        ComposableMessage.Conversation(mode: .read(messageOwner: data.owner), messages: .constant(data.basket.files))
                    } else {
                        Import(imported: data)
                    }
                }
                .sheet(item: self.$openedEncryptedFileContents) { encryptedContactsFile in
                    Import.Contacts(encryptedFile: encryptedContactsFile)
                }
            }
        }
        .modelContainer(self.sharedModelContainer)
        .environment(self.contactManager)
    }
    
    private func buildOwnedBasket(from fileContents: Data) async throws -> OwnedBasket {
        try await withThrowingTaskGroup(of: Occulta.File.self) { group in
            let multipleBundle = try? MultiRecipientBundle.decode(from: fileContents)
            
            debugPrint("Building basket for version: \(multipleBundle?.version.rawValue ?? "none")")
            
            var decrypted: (plaintext: Data, ownerID: String)
            
            switch multipleBundle?.version {
            case .v1, .none:
                decrypted = try self.contactManager.decrypt(data: fileContents)
            case .v2:
                // The message was composed for multiple recipients, version `v2`
                
                /// Capsuled containging session keys. Each element is a session key encrypted with the shared key of a contact.
                let capsules = multipleBundle?.capsules ?? []
                var found: (sessionKey: Data, messageOwner: String)?
                
                for capsule in capsules {
                    if let decryptable = try? self.contactManager.decrypt(data: capsule) {
                        found = (decryptable.plaintext, decryptable.ownerID)
                        
                        break
                    }
                }
                
                if let found = found {
                    let sessionKey = found.sessionKey
                    let messageOwner = found.messageOwner
                    
                    // We found the owner of the message and successfully decrypted the session key. Now we need to decrypt the playload using this session key.
                    
                    /// Decrypted payload of the message.
                    let plainText = try Manager.Crypto().decrypt(message: multipleBundle?.ciphertext, sessionKey: sessionKey)
                    
                    decrypted = (plainText, messageOwner)
                } else {
                    throw ContactManager.Errors.noPublicKeyToEncryptWith
                }
            }
            
            let basket = try JSONDecoder().decode(Basket.self, from: decrypted.plaintext)
            
            var processed: [Occulta.File] = []
            
            let tempDir = FileManager.default.temporaryDirectory
            
            for file in basket.files {
                /// Store photos, videos and documents in temp folder if the file's content is a file
                switch file.format {
                case .file(let metadata):
                    let fileURL = tempDir.appendingPathComponent(metadata.name ?? UUID().uuidString).appendingPathExtension(metadata.extension ?? "bin")
                    let content = file.content ?? Data()
                    
                    group.addTask {
                        try content.write(to: fileURL)
                        
                        let newFile = Occulta.File(url: fileURL, format: file.format, date: file.date)
                        
                        return newFile
                    }
                default:
                    processed.append(file)
                }
            }
            
            for try await file in group {
                processed.append(file)
            }
            
            let sorted = processed.sorted(by: { $0.date ?? .now < $1.date ?? .now })
            let modifiedBasket = Basket(id: basket.id, files: sorted, date: basket.date, owner: basket.owner)
            let ownedBasket = OwnedBasket(basket: modifiedBasket, owner: decrypted.ownerID)
            
            return ownedBasket
        }
    }
}
