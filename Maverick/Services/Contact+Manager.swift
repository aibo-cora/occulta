//
//  ContactManager.swift
//  Maverick
//
//  Created by Yura on 11/5/25.
//


import SwiftData
import Contacts
import SwiftUI
import Combine

@Observable
class ContactManager {
    private let modelExecutor: any ModelExecutor
    private let modelContainer: ModelContainer
    private var modelContext: ModelContext { self.modelExecutor.modelContext }
    
    private let cryptoManager: CryptoProtocol = Manager.Crypto()
    
    init(modelContainer: ModelContainer) {
        self.modelExecutor = DefaultSerialModelExecutor(modelContext: ModelContext(modelContainer))
        self.modelContainer = modelContainer
    }
    
    // MARK: - Create
    
    /// Creates a contact from a CNContact object.
    ///
    /// All properties are encrypted before being stored in the local database.
    /// - Parameter cnContact: Apple's contact object.
    func createContacts(from cnContacts: [CNContact]) throws {
        for contact in cnContacts {
            let encryptedIdentifier = try self.cryptoManager.encrypt(data: contact.identifier.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedGivenName = try self.cryptoManager.encrypt(data: contact.givenName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedFamilyName = try self.cryptoManager.encrypt(data: contact.familyName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedMiddleName = try self.cryptoManager.encrypt(data: contact.middleName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedImageData = try self.cryptoManager.encrypt(data: contact.imageData)
            
            let imageDataAvailableFlag: UInt8 = contact.imageDataAvailable ? 1 : 0
            let encryptedImageDataAvailable = try self.cryptoManager.encrypt(data: Data([imageDataAvailableFlag]))
            
            let encryptedThumbnailImageData = try self.cryptoManager.encrypt(data: contact.thumbnailImageData)
            
            var encryptedEmailAddresses: [CNLabeledValue<NSString>] = []
            
            contact.emailAddresses.forEach { email in
                do {
                    let label = try self.cryptoManager.encrypt(data: email.label?.data(using: .utf8))?.base64EncodedString() ?? ""
                    let value = try self.cryptoManager.encrypt(data: String(email.value).data(using: .utf8))?.base64EncodedString() ?? ""
                    
                    encryptedEmailAddresses.append(CNLabeledValue(label: label, value: value as NSString))
                } catch {
                    
                }
            }
            
            var encryptedPhoneNumbers: [CNLabeledValue<CNPhoneNumber>] = []
            
            contact.phoneNumbers.forEach { phoneNumber in
                do {
                    let label = try self.cryptoManager.encrypt(data: phoneNumber.label?.data(using: .utf8))?.base64EncodedString() ?? ""
                    let value = try self.cryptoManager.encrypt(data: phoneNumber.value.stringValue.data(using: .utf8))?.base64EncodedString() ?? ""
                    
                    encryptedPhoneNumbers.append(CNLabeledValue(label: label, value: CNPhoneNumber(stringValue: value)))
                } catch {
                    
                }
            }
            
            let newContact = Contact(
                identifier: encryptedIdentifier,
                givenName: encryptedGivenName,
                familyName: encryptedFamilyName,
                middleName: encryptedMiddleName,
                imageData: encryptedImageData,
                imageDataAvailable: encryptedImageDataAvailable,
                thumbnailImageData: encryptedThumbnailImageData,
                emailAddresses: encryptedEmailAddresses,
                phoneNumbers: encryptedPhoneNumbers
            )
            
            self.modelContext.insert(newContact)
        }
        
        try self.modelContext.save()
    }
    
    // MARK: - Read
    /// Fetches all contacts from the SwiftData context.
    func fetchAllContacts() throws -> [Contact] {
        let descriptor = FetchDescriptor<Contact>(sortBy: [SortDescriptor(\.familyName)])
        
        return try self.modelContext.fetch(descriptor)
    }
    
    /// Fetches a contact by its identifier.
    func fetchContact(by identifier: String) throws -> Contact? {
        let predicate = #Predicate<Contact> { $0.identifier == identifier }
        let descriptor = FetchDescriptor<Contact>(predicate: predicate)
        let contacts = try self.modelContext.fetch(descriptor)
        
        return contacts.first
    }
    
    // MARK: - Update
    
    /// Updates an existing contact with new values.
    @available(*, unavailable, message: "This function is no longer supported. Need to handle encryption")
    func updateContact(
        identifier: String,
        givenName: String? = nil,
        familyName: String? = nil,
        middleName: String? = nil,
        emailAddresses: [LabeledValue]? = nil,
        phoneNumbers: [LabeledValue]? = nil,
        imageData: Data?? = nil,
        thumbnailImageData: Data?? = nil
    ) throws {
        guard
            let _ = try fetchContact(by: identifier)
        else {
            throw ContactManagerError.contactNotFound
        }
        
        try self.modelContext.save()
    }
    
    /// Updates a contact from a CNContact object.
    @available(*, unavailable, message: "This function is no longer supported. Need to handle encryption")
    func updateContact(from cnContact: CNContact) throws {
        guard
            let _ = try fetchContact(by: cnContact.identifier)
        else {
            throw ContactManagerError.contactNotFound
        }
        
        try self.modelContext.save()
    }
    
    // MARK: - Delete
    /// Deletes a contact by its identifier.
    func deleteContact(identifier: String) throws {
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManagerError.contactNotFound
        }
        
        self.modelContext.delete(contact)
        try modelContext.save()
    }
    
    /// Deletes all contacts.
    func deleteAllContacts() throws {
        let contacts = try self.fetchAllContacts()
        
        for contact in contacts {
            self.modelContext.delete(contact)
        }
        try self.modelContext.save()
    }
}

extension ContactManager {
    /// <#Description#>
    /// - Parameters:
    ///   - key: <#key description#>
    ///   - identifier: <#identifier description#>
    func update(identity key: Data, for identifier: String) throws {
        guard
            let contact = try self.fetchContact(by: identifier),
            let encrypted = try self.cryptoManager.encrypt(data: key)
        else {
            throw ContactManagerError.identityNotSaved
        }
        
        contact.contactPublicKeys.append(Key(material: encrypted))
        
        try self.modelContext.save()
    }
    
    func encrypt(message: String, for identifier: String) throws -> String? {
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManagerError.contactNotFound
        }
        
        guard
            let publicKeyingMaterial = contact.contactPublicKeys.last?.material
        else {
            throw ContactManagerError.contactHasNoKeys
        }
        
        if let encrypted = try self.cryptoManager.encrypt(message: message, using: publicKeyingMaterial) {
            let encoded = encrypted.base64EncodedString()
            
            return encoded
        } else {
            return nil
        }
    }
    
    func decrypt(message: String, for identifier: String) throws -> String? {
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManagerError.contactNotFound
        }
        
        guard
            let publicKeyingMaterial = contact.contactPublicKeys.last?.material
        else {
            throw ContactManagerError.contactHasNoKeys
        }
        
        guard
            let decrypted = try self.cryptoManager.decrypt(message: message, using: publicKeyingMaterial)
        else {
            return nil
        }
        
        return String(data: decrypted, encoding: .utf8)
    }
}

// MARK: - Error Handling

enum ContactManagerError: Error {
    case contactNotFound
    case identityNotSaved
    case contactHasNoKeys
}
