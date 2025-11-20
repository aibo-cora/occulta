//
//  ContactManager.swift
//  Maverick
//
//  Created by Yura on 11/5/25.
//


import SwiftData
import Contacts
import SwiftUI

@Observable
class ContactManager {
    private let modelExecutor: any ModelExecutor
    private let modelContainer: ModelContainer
    private var modelContext: ModelContext { self.modelExecutor.modelContext }
    
    init(modelContainer: ModelContainer) {
        self.modelExecutor = DefaultSerialModelExecutor(modelContext: ModelContext(modelContainer))
        self.modelContainer = modelContainer
    }
    
    // MARK: - Create
    
    /// Creates a contact from a CNContact object.
    /// - Parameter cnContact: Apple's contact object.
    func createContacts(from cnContacts: [CNContact]) throws {
        for contact in cnContacts {
            if let newContact = try Contact(from: contact) {
                _ = try KeyManager(using: newContact.privateKeyIdentifier).create()
                
                self.modelContext.insert(newContact)
            }
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
            let contact = try fetchContact(by: identifier)
        else {
            throw ContactManagerError.contactNotFound
        }
        
        // Update only provided fields
        if let givenName = givenName {
            contact.givenName = givenName
        }
        if let familyName = familyName {
            contact.familyName = familyName
        }
        if let middleName = middleName {
            contact.middleName = middleName
        }
        if let emailAddresses = emailAddresses {
            contact.emailAddresses = emailAddresses
        }
        if let phoneNumbers = phoneNumbers {
            contact.phoneNumbers = phoneNumbers
        }
        if let imageData = imageData {
            contact.imageData = imageData
            contact.imageDataAvailable = imageData != nil
        }
        if let thumbnailImageData = thumbnailImageData {
            contact.thumbnailImageData = thumbnailImageData
        }
        
        try self.modelContext.save()
    }
    
    /// Updates a contact from a CNContact object.
    func updateContact(from cnContact: CNContact) throws {
        guard
            let contact = try fetchContact(by: cnContact.identifier)
        else {
            throw ContactManagerError.contactNotFound
        }
        
        contact.givenName = cnContact.givenName
        contact.familyName = cnContact.familyName
        contact.middleName = cnContact.middleName
        contact.imageData = cnContact.imageData
        contact.imageDataAvailable = cnContact.imageDataAvailable
        contact.thumbnailImageData = cnContact.thumbnailImageData
        contact.emailAddresses = cnContact.emailAddresses.map { LabeledValue(from: $0) }
        contact.phoneNumbers = cnContact.phoneNumbers.map { LabeledValue(from: $0) }
        
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

// MARK: - Error Handling
enum ContactManagerError: Error {
    case contactNotFound
}
