//
//  ContactManager.swift
//  Occulta
//
//  Created by Yura on 11/5/25.
//


import SwiftData
import Contacts
import SwiftUI
import Combine
import Foundation
import CryptoKit

@Observable
class ContactManager {
    private let modelExecutor: any ModelExecutor
    private let modelContainer: ModelContainer
    private var modelContext: ModelContext { self.modelExecutor.modelContext }
    
    private let cryptoManager: CryptoProtocol = Manager.Crypto()
    
    /// Prepare the Contacts system to return the names of matching people
    let keys = [
        CNContactFormatter.descriptorForRequiredKeys(for: .fullName),
        CNContactIdentifierKey as any CNKeyDescriptor,
        CNContactGivenNameKey as any CNKeyDescriptor,
        CNContactFamilyNameKey as any CNKeyDescriptor,
        CNContactMiddleNameKey as any CNKeyDescriptor,
        CNContactImageDataKey as any CNKeyDescriptor,
        CNContactImageDataAvailableKey as any CNKeyDescriptor,
        CNContactThumbnailImageDataKey as any CNKeyDescriptor,
        CNContactEmailAddressesKey as CNKeyDescriptor,
        CNContactPhoneNumbersKey as CNKeyDescriptor,
        CNContactPostalAddressesKey as CNKeyDescriptor,
        CNContactUrlAddressesKey as CNKeyDescriptor,
        CNContactNamePrefixKey as CNKeyDescriptor,
        CNContactNameSuffixKey as CNKeyDescriptor,
        CNContactOrganizationNameKey as CNKeyDescriptor,
        CNContactDepartmentNameKey as CNKeyDescriptor,
        CNContactJobTitleKey as CNKeyDescriptor,
        CNContactNicknameKey as CNKeyDescriptor,
        CNContactBirthdayKey as CNKeyDescriptor,
    ]
    
    init(modelContainer: ModelContainer) {
        self.modelExecutor = DefaultSerialModelExecutor(modelContext: ModelContext(modelContainer))
        self.modelContainer = modelContainer
    }
    
    var dateFormatter: DateFormatter {
        let formatter = DateFormatter()
        
        formatter.dateStyle = .short
        
        return formatter
    }
    
    // MARK: - Create
    
    /// Creates a contact from a `CNContact` object when a user imports a contact.
    ///
    /// All properties are encrypted before being stored in the local database.
    /// - Parameter cnContact: Apple's contact object.
    func createContacts(from cnContacts: [CNContact]) throws {
        for contact in cnContacts {
            let encryptedIdentifier = try self.cryptoManager.encrypt(data: contact.identifier.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedGivenName = try self.cryptoManager.encrypt(data: contact.givenName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedFamilyName = try self.cryptoManager.encrypt(data: contact.familyName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedMiddleName = try self.cryptoManager.encrypt(data: contact.middleName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedNamePrefix = try self.cryptoManager.encrypt(data: contact.namePrefix.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedNameSuffix = try self.cryptoManager.encrypt(data: contact.nameSuffix.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedNickname = try self.cryptoManager.encrypt(data: contact.nickname.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedOrganizationName = try self.cryptoManager.encrypt(data: contact.organizationName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedDepartmentName = try self.cryptoManager.encrypt(data: contact.departmentName.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedJobTitle = try self.cryptoManager.encrypt(data: contact.jobTitle.data(using: .utf8))?.base64EncodedString() ?? ""
            
            let encryptedImageData = try self.cryptoManager.encrypt(data: contact.imageData)
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
            
            var encryptedPostalAddresses: [Contact.Profile.PostalAddress] = []
            
            contact.postalAddresses.forEach { postalAddress in
                do {
                    let encryptedStreet = try self.cryptoManager.encrypt(data: postalAddress.value.street.data(using: .utf8))?.base64EncodedString() ?? ""
                    let encryptedCity = try self.cryptoManager.encrypt(data: postalAddress.value.city.data(using: .utf8))?.base64EncodedString() ?? ""
                    let encryptedState = try self.cryptoManager.encrypt(data: postalAddress.value.state.data(using: .utf8))?.base64EncodedString() ?? ""
                    let encryptedPostalCode = try self.cryptoManager.encrypt(data: postalAddress.value.postalCode.data(using: .utf8))?.base64EncodedString() ?? ""
                    let encryptedCountry = try self.cryptoManager.encrypt(data: postalAddress.value.country.data(using: .utf8))?.base64EncodedString() ?? ""
                    let encryptedIsoCountryCode = try self.cryptoManager.encrypt(data: postalAddress.value.isoCountryCode.data(using: .utf8))?.base64EncodedString() ?? ""
                    
                    let mutable = CNMutablePostalAddress()
                    
                    mutable.street = encryptedStreet
                    mutable.city = encryptedCity
                    mutable.state = encryptedState
                    mutable.postalCode = encryptedPostalCode
                    mutable.country = encryptedCountry
                    mutable.isoCountryCode = encryptedIsoCountryCode
                    
                    let encryptedLabel = try self.cryptoManager.encrypt(data: postalAddress.label?.data(using: .utf8))?.base64EncodedString() ?? ""
                    
                    encryptedPostalAddresses.append(Contact.Profile.PostalAddress(from: CNLabeledValue<CNMutablePostalAddress>(label: encryptedLabel, value: mutable)))
                } catch {
                    
                }
            }
            
            var encryptedURLs: [Contact.Profile.URLAddress] = []
            
            contact.urlAddresses.forEach { urlAddress in
                do {
                    let encryptedLabel = try self.cryptoManager.encrypt(data: urlAddress.label?.data(using: .utf8))?.base64EncodedString() ?? ""
                    let url = urlAddress.value as String
                    let encryptedURL = try self.cryptoManager.encrypt(data: url.data(using: .utf8))?.base64EncodedString() ?? ""
                    
                    encryptedURLs.append(Contact.Profile.URLAddress(label: encryptedLabel, value: encryptedURL))
                } catch {
                    
                }
            }
            
            var encryptedBirthday: String = ""
            
            if let birthday = contact.birthday?.date {
                encryptedBirthday = try self.cryptoManager.encrypt(data: self.dateFormatter.string(from: birthday).data(using: .utf8))?.base64EncodedString() ?? ""
            }
            
            /// Need to request an entitlement from Apple to retrieve the `note` field.
            
            let newContact = Contact.Profile(
                identifier: encryptedIdentifier,
                givenName: encryptedGivenName,
                familyName: encryptedFamilyName,
                middleName: encryptedMiddleName,
                namePrefix: encryptedNamePrefix, nameSuffix: encryptedNameSuffix, nickname: encryptedNickname,
                organizationName: encryptedOrganizationName,
                departmentName: encryptedDepartmentName,
                jobTitle: encryptedJobTitle,
                birthday: encryptedBirthday,
                note: "",
                imageData: encryptedImageData,
                thumbnailImageData: encryptedThumbnailImageData,
                phoneNumbers: encryptedPhoneNumbers.map { Contact.Profile.PhoneNumber(from: $0) },
                emailAddresses: encryptedEmailAddresses.map { Contact.Profile.EmailAddress(from: $0) },
                postalAddresses: encryptedPostalAddresses
            )
            
            self.modelContext.insert(newContact)
        }
        
        try self.modelContext.save()
        self.syncShareIndex()
    }

    func save(contacts: [Contact.Draft]) throws {
        for contact in contacts {
            try self.save(contact: contact)
        }
    }
    
    /// Save a new custom contact or update an existing contact.
    /// - Parameter contact: Custom contact. Thread safe.
    ///
    func save(contact: Contact.Draft) throws {
        let encryptedIdentifier = contact.identifier
        let encryptedGivenName = try self.cryptoManager.encrypt(data: contact.givenName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedFamilyName = try self.cryptoManager.encrypt(data: contact.familyName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedMiddleName = try self.cryptoManager.encrypt(data: contact.middleName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedNamePrefix = try self.cryptoManager.encrypt(data: contact.namePrefix.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedNameSuffix = try self.cryptoManager.encrypt(data: contact.nameSuffix.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedNickname = try self.cryptoManager.encrypt(data: contact.nickname.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedOrganizationName = try self.cryptoManager.encrypt(data: contact.organizationName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedDepartmentName = try self.cryptoManager.encrypt(data: contact.departmentName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedJobTitle = try self.cryptoManager.encrypt(data: contact.jobTitle.data(using: .utf8))?.base64EncodedString() ?? ""
        
        let encryptedImageData = try self.cryptoManager.encrypt(data: contact.imageData)
        let encryptedThumbnailImageData = try self.cryptoManager.encrypt(data: contact.thumbnailImageData)
        
        var encryptedEmailAddresses: [CNLabeledValue<NSString>] = []
        
        contact.emailAddresses.forEach { email in
            do {
                let label = try self.cryptoManager.encrypt(data: email.label.data(using: .utf8))?.base64EncodedString() ?? ""
                let value = try self.cryptoManager.encrypt(data: String(email.value).data(using: .utf8))?.base64EncodedString() ?? ""
                
                encryptedEmailAddresses.append(CNLabeledValue(label: label, value: value as NSString))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }
        
        var encryptedPhoneNumbers: [CNLabeledValue<CNPhoneNumber>] = []
        
        contact.phoneNumbers.forEach { phoneNumber in
            do {
                let label = try self.cryptoManager.encrypt(data: phoneNumber.label.data(using: .utf8))?.base64EncodedString() ?? ""
                let value = try self.cryptoManager.encrypt(data: phoneNumber.value.data(using: .utf8))?.base64EncodedString() ?? ""
                
                encryptedPhoneNumbers.append(CNLabeledValue(label: label, value: CNPhoneNumber(stringValue: value)))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }
        
        var encryptedPostalAddresses: [Contact.Profile.PostalAddress] = []
        
        contact.postalAddresses.forEach { postalAddress in
            do {
                let encryptedStreet = try self.cryptoManager.encrypt(data: postalAddress.street.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedCity = try self.cryptoManager.encrypt(data: postalAddress.city.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedState = try self.cryptoManager.encrypt(data: postalAddress.state.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedPostalCode = try self.cryptoManager.encrypt(data: postalAddress.postalCode.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedCountry = try self.cryptoManager.encrypt(data: postalAddress.country.name.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedIsoCountryCode = try self.cryptoManager.encrypt(data: postalAddress.country.code.data(using: .utf8))?.base64EncodedString() ?? ""
                
                let mutable = CNMutablePostalAddress()
                
                mutable.street = encryptedStreet
                mutable.city = encryptedCity
                mutable.state = encryptedState
                mutable.postalCode = encryptedPostalCode
                mutable.country = encryptedCountry
                mutable.isoCountryCode = encryptedIsoCountryCode
                
                let encryptedLabel = try self.cryptoManager.encrypt(data: postalAddress.label.data(using: .utf8))?.base64EncodedString() ?? ""
                
                encryptedPostalAddresses.append(Contact.Profile.PostalAddress(from: CNLabeledValue<CNMutablePostalAddress>(label: encryptedLabel, value: mutable)))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }
        
        var encryptedURLs: [Contact.Profile.URLAddress] = []
        
        contact.urlAddresses.forEach { urlAddress in
            do {
                let encryptedLabel = try self.cryptoManager.encrypt(data: urlAddress.label.data(using: .utf8))?.base64EncodedString() ?? ""
                let url = urlAddress.value as String
                let encryptedURL = try self.cryptoManager.encrypt(data: url.data(using: .utf8))?.base64EncodedString() ?? ""
                
                encryptedURLs.append(Contact.Profile.URLAddress(label: encryptedLabel, value: encryptedURL))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }
        
        let encryptedBirthday: String = try self.cryptoManager.encrypt(data: contact.birthday?.data(using: .utf8))?.base64EncodedString() ?? ""
        
        let encryptedNote = try self.cryptoManager.encrypt(data: contact.note.data(using: .utf8))?.base64EncodedString() ?? ""
        
        /// Storing
        
        if let existing = try self.fetchContact(by: encryptedIdentifier) {
            /// Replace fields with new values
            existing.givenName = encryptedGivenName
            existing.familyName = encryptedFamilyName
            existing.middleName = encryptedMiddleName
            existing.nickname = encryptedNickname
            existing.organizationName = encryptedOrganizationName
            existing.departmentName = encryptedDepartmentName
            existing.jobTitle = encryptedJobTitle
            existing.birthday = encryptedBirthday
            existing.imageData = encryptedImageData
            existing.thumbnailImageData = encryptedThumbnailImageData
            existing.phoneNumbers = encryptedPhoneNumbers.map { Contact.Profile.PhoneNumber(from: $0) }
            existing.emailAddresses = encryptedEmailAddresses.map { Contact.Profile.EmailAddress(from: $0) }
            existing.postalAddresses = encryptedPostalAddresses
            existing.urlAddresses = encryptedURLs
            existing.namePrefix = encryptedNamePrefix
            existing.nameSuffix = encryptedNameSuffix
            existing.note = encryptedNote
            existing.encryptionScheme = EncryptionScheme.v2_hybridPQ.rawValue
            
            debugPrint("Updated existing contact")
        } else {
            let newContact = Contact.Profile(
                identifier: encryptedIdentifier,
                givenName: encryptedGivenName,
                familyName: encryptedFamilyName,
                middleName: encryptedMiddleName,
                namePrefix: encryptedNamePrefix,
                nameSuffix: encryptedNameSuffix,
                nickname: encryptedNickname,
                organizationName: encryptedOrganizationName,
                departmentName: encryptedDepartmentName,
                jobTitle: encryptedJobTitle,
                birthday: encryptedBirthday,
                note: encryptedNote,
                imageData: encryptedImageData,
                thumbnailImageData: encryptedThumbnailImageData,
                phoneNumbers: encryptedPhoneNumbers.map { Contact.Profile.PhoneNumber(from: $0) },
                emailAddresses: encryptedEmailAddresses.map { Contact.Profile.EmailAddress(from: $0) },
                postalAddresses: encryptedPostalAddresses,
                urlAddresses: encryptedURLs,
                encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
            )
            
            self.modelContext.insert(newContact)
            
            for key in contact.contactPublicKeys {
                try? self.update(key: key, for: newContact.identifier)
            }
            
            debugPrint("Inserted new contact, id = \(encryptedIdentifier), name - \(String(describing: encryptedGivenName)) \(String(describing: encryptedFamilyName))")
        }

        try self.modelContext.save()
        self.syncShareIndex()
    }

    // MARK: - Read
    
    /// Fetches all contacts from the SwiftData context.
    func fetchAllContacts() throws -> [Contact.Profile] {
        let descriptor = FetchDescriptor<Contact.Profile>(sortBy: [SortDescriptor(\.familyName)])
        
        return try self.modelContext.fetch(descriptor)
    }
    
    /// Fetches a contact by its identifier.
    func fetchContact(by identifier: String) throws -> Contact.Profile? {
        let predicate = #Predicate<Contact.Profile> { $0.identifier == identifier }
        let descriptor = FetchDescriptor<Contact.Profile>(predicate: predicate)
        let contacts = try self.modelContext.fetch(descriptor)
        
        return contacts.first
    }
    
    // MARK: - Delete
    
    /// Deletes a contact by its identifier.
    func deleteContact(identifier: String) throws {
        debugPrint("Deleting contact with identifier: \(identifier)")
        
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManager.Errors.contactNotFound
        }
        
        self.modelContext.delete(contact)
        try modelContext.save()
        self.syncShareIndex()
    }

    /// Deletes all contacts.
    func deleteAllContacts() throws {
        let contacts = try self.fetchAllContacts()

        for contact in contacts {
            debugPrint("Deleting contact with identifier: \(contact.identifier)")

            self.modelContext.delete(contact)
        }

        try self.modelContext.save()
        self.syncShareIndex()
    }
}

extension ContactManager {
    /// Rotate private key.
    func rotate() throws {
        
    }
    
    /// Store public keying material of the contact.
    /// - Parameters:
    ///   - key: Keying material.
    ///   - identifier: Identifier of the owner.
    ///   - method: Acquisition method. Nearby Interaction - secure, or something else.
    func update(key: Contact.Draft.Key, for identifier: String) throws {
        guard
            let contact = try self.fetchContact(by: identifier),
            let encryptedMaterial = try self.cryptoManager.encrypt(data: key.material),
            let encryptedOwner = try self.cryptoManager.encrypt(data: key.owner),
            let encryptedCreationDate = try self.cryptoManager.encrypt(data: key.acquiredAt.data(using: .utf8))
        else {
            throw ContactManager.Errors.identityNotSaved
        }
        
        var encryptedQuantumKeyMaterial: Data? = nil
        
        if let quantum = key.quantumKeyMaterial {
            let encodedQuantum = try JSONEncoder().encode(quantum)
            
            encryptedQuantumKeyMaterial = try self.cryptoManager.encrypt(data: encodedQuantum)
        }
        
        contact.contactPublicKeys?.append(Contact.Profile.Key(material: encryptedMaterial, owner: encryptedOwner, date: encryptedCreationDate, quantumKeyMaterialEncrypted: encryptedQuantumKeyMaterial))
        
        try self.modelContext.save()
    }
    
    /// Remove all keys of a contact.
    /// - Parameter identifier: Contact's ID.
    func reset(identity identifier: String) throws {
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManager.Errors.contactNotFound
        }
        
        let expiration = String(Date.now.timeIntervalSince1970).data(using: .utf8)
        let encrypted = try self.cryptoManager.encrypt(data: expiration)
        
        contact.contactPublicKeys?.last?.expiredOn = encrypted
        
        try self.modelContext.save()
    }
    
    /// Encrypt data for a contact using their public key, which is encrypted.
    /// - Parameters:
    ///   - data: Data to encrypt.
    ///   - encrypted: Encrypt public keying material.
    /// - Returns: Encrypted result.
    func encrypt(data: Data, using encrypted: Data?) throws -> Data? {
        guard
            data.isEmpty == false
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        guard
            let publicKeyingMaterial = try self.cryptoManager.decrypt(data: encrypted)
        else {
            throw ContactManager.Errors.contactHasNoKeys
        }
        
        let encryptedData = try self.encrypt(data: data, using: publicKeyingMaterial)
        
        return encryptedData
    }
    
    func encrypt(data: Data, for identifier: String) throws -> Data? {
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManager.Errors.contactNotFound
        }
        
        guard
            let encrypted = contact.contactPublicKeys?.last?.material,
            let publicKeyingMaterial = try self.cryptoManager.decrypt(data: encrypted)
        else {
            throw ContactManager.Errors.contactHasNoKeys
        }
        
        guard
            data.isEmpty == false
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        let encryptedData = try self.encrypt(data: data, using: publicKeyingMaterial)
        
        return encryptedData
    }
    
    private func encrypt(data: Data, using material: Data) throws -> Data? {
        try self.cryptoManager.encrypt(message: data, using: material)
    }
    
    private func decrypt(message: Data?, for identifier: String) throws -> Data? {
        guard
            let payload = message, payload.isEmpty == false
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManager.Errors.contactNotFound
        }
        
        guard
            let encrypted = contact.contactPublicKeys?.last?.material,
            let publicKeyingMaterial = try self.cryptoManager.decrypt(data: encrypted)
        else {
            throw ContactManager.Errors.contactHasNoKeys
        }
        
        let decrypted = try self.cryptoManager.decrypt(message: payload, using: publicKeyingMaterial)
        
        return decrypted
    }
}

// MARK: - Error Handling

extension ContactManager {
    enum Errors: Error {
        case contactNotFound
        case identityNotSaved
        case contactHasNoKeys
        case invalidBase64
        case decryptionFailed
        case messageHasNoData
        case noDataToExport
        case encryptionFailed
        case noPublicKeyToEncryptWith
        case invalidPrekeySyncBatch
        case unsupportedBundleVersion
        case invalidBundleFormat
        case quantumKeyMaterialCorrupted
    }
}

extension ContactManager {
    static var preview: ContactManager {
        let sharedModelContainer: ModelContainer = {
            let schema = Schema([
                Contact.Profile.self,
                Contact.Profile.PhoneNumber.self,
                Contact.Profile.EmailAddress.self,
                Contact.Profile.PostalAddress.self,
                Contact.Profile.URLAddress.self
            ])
            
            let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)

            do {
                return try ModelContainer(for: schema, configurations: [modelConfiguration])
            } catch {
                fatalError("Could not create ModelContainer: \(error)")
            }
        }()
        
        let manager = ContactManager(modelContainer: sharedModelContainer)
        
        do {
            let cryptoManager = manager.cryptoManager
            
            let encryptedIdentifier = try cryptoManager.encrypt(data: UUID().uuidString.data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedGivenName = try cryptoManager.encrypt(data: "Alice".data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedFamilyName = try cryptoManager.encrypt(data: "Wonderland".data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedMiddleName: String = try cryptoManager.encrypt(data: "Elizabeth".data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedNickname: String = try cryptoManager.encrypt(data: "AW".data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedOrganizationName: String = try cryptoManager.encrypt(data: "Wonderland Enterprises".data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedDepartmentName: String = try cryptoManager.encrypt(data: "Engineering".data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedJobTitle: String = try cryptoManager.encrypt(data: "Software Engineer".data(using: .utf8))?.base64EncodedString() ?? ""
            let encryptedKey = try cryptoManager.encrypt(data: Data.randomBytes(32))
            
            let testing = Contact.Profile(identifier: encryptedIdentifier, givenName: encryptedGivenName, familyName: encryptedFamilyName, middleName: encryptedMiddleName, nickname: encryptedNickname, organizationName: encryptedOrganizationName, departmentName: encryptedDepartmentName, jobTitle: encryptedJobTitle)
            testing.contactPublicKeys?.append(Contact.Profile.Key(material: encryptedKey, owner: try Manager.Key().retrieveIdentity(), date: Data()))
            
            sharedModelContainer.mainContext.insert(testing)
            
            try sharedModelContainer.mainContext.save()
        } catch {
            debugPrint("Could not create a test contact, error: \(error)")
        }
        
        return manager
    }
}

extension ContactManager {
    /// Returns a fully decrypted, mutable copy of a contact for editing.
    /// - Parameter identifier: The encrypted unique identifier of the contact.
    /// - Returns: Contact with all fields decrypted and ready for UI or encryption with a new key.
    func convertToMutableCopy(using identifier: String) throws -> Contact.Draft {
        guard
            let storedContact = try self.fetchContact(by: identifier)
        else {
            throw Errors.contactNotFound
        }
        
        func decryptString(_ base64: String) throws -> String {
            guard
                let data = Data(base64Encoded: base64)
            else {
                throw Errors.invalidBase64
            }
            
            guard
                !data.isEmpty
            else {
                return ""
            }
            
            guard
                let decryptedData = try self.cryptoManager.decrypt(data: data),
                let string = String(data: decryptedData, encoding: .utf8)
            else {
                throw Errors.decryptionFailed
            }
            
            return string
        }
        
        func decryptImageData(from base64Data: Data?) throws -> Data? {
            guard
                let encrypted = base64Data, !encrypted.isEmpty
            else {
                return nil
            }
            
            return try self.cryptoManager.decrypt(data: encrypted)
        }
        
        // MARK: - Decrypt scalar fields
        
        let givenName           = try decryptString(storedContact.givenName)
        let familyName          = try decryptString(storedContact.familyName)
        let middleName          = try decryptString(storedContact.middleName)
        let namePrefix          = try decryptString(storedContact.namePrefix)
        let nameSuffix          = try decryptString(storedContact.nameSuffix)
        let nickname            = try decryptString(storedContact.nickname)
        
        let organizationName    = try decryptString(storedContact.organizationName)
        let departmentName      = try decryptString(storedContact.departmentName)
        let jobTitle            = try decryptString(storedContact.jobTitle)
        
        let phoneticGivenName   = try decryptString(storedContact.phoneticGivenName)
        let phoneticMiddleName  = try decryptString(storedContact.phoneticMiddleName)
        let phoneticFamilyName  = try decryptString(storedContact.phoneticFamilyName)
        
        let note                = try decryptString(storedContact.note)
        
        let birthday            = try decryptString(storedContact.birthday ?? "")
        
        let thumbnailImageData  = try decryptImageData(from: storedContact.thumbnailImageData)
        let imageData           = try decryptImageData(from: storedContact.imageData)
        
        // MARK: - Decrypt relationships
        
        let phoneNumbers: [Contact.Draft.PhoneNumber]? = try storedContact.phoneNumbers?.map { stored in
            let label = try decryptString(stored.label)
            let value = try decryptString(stored.value)
            
            var phone = Contact.Draft.PhoneNumber(label: label, value: value)
            
            phone.type = Contact.Draft.PhoneNumber.PhoneType.allCases
                .first { $0.rawValue.localizedCaseInsensitiveCompare(label) == .orderedSame } ?? .other
            return phone
        }
        
        let emailAddresses: [Contact.Draft.EmailAddress]? = try storedContact.emailAddresses?.map { stored in
            let label = try decryptString(stored.label)
            let value = try decryptString(stored.value)
            
            var email = Contact.Draft.EmailAddress(label: label, value: value)
            
            email.type = Contact.Draft.EmailAddress.EmailType.allCases
                .first { $0.rawValue.localizedCaseInsensitiveCompare(label) == .orderedSame } ?? .other
            
            return email
        }
        
        let postalAddresses: [Contact.Draft.PostalAddress]? = try storedContact.postalAddresses?.map { stored in
            let label       = try decryptString(stored.label)
            let street      = try decryptString(stored.street)
            let city        = try decryptString(stored.city)
            let state       = try decryptString(stored.state)
            let postalCode  = try decryptString(stored.postalCode)
            let countryCode = try decryptString(stored.isoCountryCode)
            let country     = Contact.Draft.PostalAddress.Country(code: countryCode.uppercased())
            
            var address = Contact.Draft.PostalAddress(
                label: label,
                street: street,
                city: city,
                state: state,
                postalCode: postalCode,
                country: country
            )
            address.type = Contact.Draft.PostalAddress.AddressType.allCases
                .first { $0.rawValue.localizedCaseInsensitiveCompare(label) == .orderedSame } ?? .other
            
            return address
        }
        
        let urlAddresses: [Contact.Draft.URLAddress]? = try storedContact.urlAddresses?.map { stored in
            let label = try decryptString(stored.label)
            let value = try decryptString(stored.value)
            
            var url = Contact.Draft.URLAddress(label: label, value: value)
            
            url.type = Contact.Draft.URLAddress.WebsiteType.allCases
                .first { $0.rawValue.localizedCaseInsensitiveCompare(label) == .orderedSame } ?? .other
            
            return url
        }
        
        let encryptedPublicKeys = storedContact.contactPublicKeys
        let plaintextPublicKeys = encryptedPublicKeys?.compactMap {
            let material = try? self.cryptoManager.decrypt(data: $0.material)
            let owner = (try? self.cryptoManager.decrypt(data: $0.owner)) ?? Data()
            let date = String(data: (try? self.cryptoManager.decrypt(data: $0.acquiredAt)) ?? Data(), encoding: .utf8) ?? ""
            
            return Contact.Draft.Key(material: material, owner: owner, date: date)
        }
        
        // MARK: - Build final Draft
        
        return Contact.Draft(
            identifier: identifier,
            givenName: givenName,
            familyName: familyName,
            middleName: middleName,
            namePrefix: namePrefix,
            nameSuffix: nameSuffix,
            nickname: nickname,
            organizationName: organizationName,
            departmentName: departmentName,
            jobTitle: jobTitle,
            phoneticGivenName: phoneticGivenName,
            phoneticMiddleName: phoneticMiddleName,
            phoneticFamilyName: phoneticFamilyName,
            birthday: birthday,
            note: note,
            imageData: imageData,
            thumbnailImageData: thumbnailImageData,
            phoneNumbers: phoneNumbers ?? [],
            emailAddresses: emailAddresses ?? [],
            postalAddresses: postalAddresses ?? [],
            urlAddresses: urlAddresses ?? [],
            contactPublicKeys: plaintextPublicKeys ?? []
        )
    }
}

// MARK: Porting

extension ContactManager {
    /// Retrieves all of our contacts from the local database. Then, creates mutable copies of `Contact.Draft` decrypting all values. Encrypts these copies with a `SymmetricKey` which is derived from the passphrase.
    /// - Parameter passphrase: Passphrase generated to derive a `SymmetricKey`.
    /// - Returns: Encrypted `Contact.Export` object.
    func prepareForExporting(using passphrase: String) throws -> Data {
        let cryptoOps: CryptoProtocol = Manager.Crypto()
        /// All of our contacts.
        let storedContacts = try self.fetchAllContacts()
        /// We need to decrypt them so we can encrypt it again with a new key that a new device would understand.
        let decryptedMutableContacts = storedContacts.compactMap { try? self.convertToMutableCopy(using: $0.identifier) }
        
        let encodedContacts = try JSONEncoder().encode(decryptedMutableContacts)
        
        let fileContents = File(content: encodedContacts, format: .contacts)
        let basket = Basket(files: [fileContents])
        
        let encodedBasketContents = try JSONEncoder().encode(basket)
        
        guard
            let encryptedContacts = try cryptoOps.encrypt(contacts: encodedBasketContents, using: passphrase)
        else {
            throw Errors.encryptionFailed
        }
        
        return encryptedContacts
    }

    func decrypt(data: Data?, using passphrase: String) throws -> Data {
        let cryptoOps: CryptoProtocol = Manager.Crypto()
        
        guard
            let data
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        guard
            let encodedContacts = try cryptoOps.decrypt(contacts: data, using: passphrase)
        else {
            throw ContactManager.Errors.decryptionFailed
        }
        
        return encodedContacts
    }
    
    /// Find the rightful owner of the message, the originator, and decrypt it using the right key.
    /// - Parameter text: Encrypted text.
    /// - Returns: Plaintext.
    func decrypt(data: Data?) throws -> (plaintext: Data, ownerID: String) {
        guard
            let data
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        let contacts = try self.fetchAllContacts()
        
        for contact in contacts {
            do {
                if let decrypted = try self.decrypt(message: data, for: contact.identifier) {
                    return (decrypted, contact.identifier)
                }
            } catch {
                /// Keep iterating.
            }
        }
        
        throw ContactManager.Errors.noPublicKeyToEncryptWith
    }
}
 
// MARK: - v3fs bundle encryption
 
extension ContactManager {
    /// Encrypt a payload for a contact using the v3fs path.
    ///
    /// ## Pending batch delivery guarantee
    /// A `pendingOutboundBatch` (if present) is attached to EVERY message until
    /// the contact sends back a .forwardSecret bundle using one of our prekeys.
    /// That is cryptographic proof they received and stored our batch.
    /// Only then is the pending batch cleared and a new one allowed to be generated.
    func encryptBundle(data: Data, for identifier: String) throws -> Data {
        guard data.isEmpty == false else { throw Errors.messageHasNoData }
        guard let contact = try self.fetchContact(by: identifier) else { throw Errors.contactNotFound }
        
        try contact.configureForwardSecrecy()
        
        debugPrint("Encrypting for contact. Inbound prekeys now: \(contact.availableInboundPrekeyCount), contact: \(contact.givenName.decrypt()), has pending batch: \(contact.hasPendingBatch)")
 
        let cryptoOps     = Manager.Crypto()
 
        // ── 1. Recipient's long-term public key ──────────────────────────
        guard
            let keyRecord         = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
            let recipientMaterial = try? cryptoOps.decrypt(data: keyRecord.material),
            recipientMaterial.count == 65
        else {
            throw Errors.contactHasNoKeys
        }
 
        // ── 2. Pop oldest inbound prekey ─────────────────────────────────
        
        var prekey: Prekey? = nil
 
        if let blob = try contact.popOldestPrekeyData() {
            prekey = try JSONDecoder().decode(Prekey.self, from: blob)
        }
        
        // Create payload
        
        let outboundBatch = try contact.loadPendingBatch()
        let sealedPayload = OccultaBundle.SealedPayload(message: data, prekeyBatch: outboundBatch)
        let encodedSealedPayload: Data = try JSONEncoder().encode(sealedPayload)
 
        // 4. ECDH + AES-GCM
        let decryptedQuantum = try? cryptoOps.decrypt(data: keyRecord.quantumKeyMaterialEncrypted)
        var quantumMaterial: QuantumKeyMaterial? = nil
        
        if let decryptedQuantum {
            quantumMaterial = try? JSONDecoder().decode(QuantumKeyMaterial.self, from: decryptedQuantum)
            
            #if DEBUG
            if quantumMaterial == nil {
                debugPrint("Quantum key material present but failed to decode — falling back to classical")
            }
            else {
                debugPrint("Sealing bundle with a session key derived using quantum material...")
            }
            #endif
        }
        
        let bundle = try cryptoOps.seal(message: encodedSealedPayload, contactPrekey: prekey, recipientMaterial: recipientMaterial, quantumMaterial: quantumMaterial)
        // 5. Persist
        try self.modelContext.save()
        
        debugPrint("Encrypt finished for \(identifier), prekey batch pending: \(contact.hasPendingBatch)")
 
        return try bundle.encoded()
    }
}
 
// MARK: - v3fs bundle decryption
 
extension ContactManager {
    /// Decrypt a v3fs bundle.
    func decrypt(bundle: OccultaBundle) throws -> (plaintext: Data, ownerID: String) {
        guard bundle.version == .v3fs else { throw Errors.unsupportedBundleVersion }
 
        let cryptoOps     = Manager.Crypto()
        let prekeyManager = Manager.PrekeyManager()
 
        // ── 1. Identify sender by fingerprint ───────────────────────────
        let contacts = try self.fetchAllContacts()
        var sender: Contact.Profile?
 
        for contact in contacts {
            guard
                let keyRecord = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
                let pubKey    = try? cryptoOps.decrypt(data: keyRecord.material)
            else { continue }
 
            if contact.isLikelySender(of: bundle, contactPublicKey: pubKey) {
                sender = contact
                
                break
            }
        }
        
        try sender?.configureForwardSecrecy()
 
        guard let sender else { throw Errors.noPublicKeyToEncryptWith }
 
        // ── 4. Key derivation + open ─────────────────────────────────────
        //
        // ⚠️  CRASH PROTECTION — SecKey released inside closure before consume().
        let decryptedSealedPayload: Data?
        
        debugPrint("Opening message, using mode: \(bundle.secrecy.mode)")
        
        let validKey = sender.contactPublicKeys?.last(where: { $0.expiredOn == nil })
        let decryptedQuantum = try? cryptoOps.decrypt(data: validKey?.quantumKeyMaterialEncrypted)
        var quantumMaterial: QuantumKeyMaterial? = nil
        
        if let decryptedQuantum {
            do {
                quantumMaterial = try JSONDecoder().decode(QuantumKeyMaterial.self, from: decryptedQuantum)
            } catch {
                throw Errors.quantumKeyMaterialCorrupted
            }
            
            #if DEBUG
            debugPrint("Opening bundle using quantum material to derive session key...")
            #endif
        }
 
        switch bundle.secrecy.mode {
        case .forwardSecret:
            let decrypted: Data? = try {
                guard
                    let prekeyID = bundle.secrecy.prekeyID
                else {
                    return nil
                }
                #if DEBUG
                debugPrint("Using prekey, ID = \(prekeyID)")
                #endif
                /// Temp prekey just for the tag,
                let temp = Prekey(id: prekeyID, contactID: sender.identifier, publicKey: Data())
                
                guard
                    let privKey  = prekeyManager.retrievePrivateKey(for: temp),
                    let sessKey  = cryptoOps.deriveSessionKey(ephemeralPrivateKey: privKey, recipientMaterial: bundle.secrecy.ephemeralPublicKey, quantumMaterial: quantumMaterial)
                else { return nil }
                
                return try cryptoOps.open(bundle, using: sessKey)
            }()
 
            if decrypted != nil, let prekeyID = bundle.secrecy.prekeyID {
                /// Temp prekey just for the tag,
                let temp = Prekey(id: prekeyID, contactID: sender.identifier, publicKey: Data())
                
                #if DEBUG
                debugPrint("Opened bundle using prekey = \(temp), consuming key...")
                #endif
                
                prekeyManager.consume(prekey: temp)
                /// The message was opened successfully. FS was used, we don't need to send more batches - clearing.
                try sender.clearPendingBatch()
                
                debugPrint("Message successfully opened in .forwardSecret mode. Pending batch cleared.")
            } else {
                debugPrint("Attempted open, but something went wrong. Plaintext = \(String(describing: decrypted)), prekeyID = \(String(describing: bundle.secrecy.prekeyID))")
            }
            
            decryptedSealedPayload = decrypted
        case .longTermFallback:
            debugPrint("🔥 longTermFallback detected — forcing fresh pending batch for sender \(sender.identifier)")
            
            let validKey = sender.contactPublicKeys?.first(where: { $0.expiredOn == nil })
            
            guard
                let sendersEncryptedIdentityKey = validKey,
                let decryptedIdentityKey = try cryptoOps.decrypt(data: sendersEncryptedIdentityKey.material)
            else {
                debugPrint("Opening message, could not derive session key. Aborting open...")
                
                throw Errors.decryptionFailed
            }
            
            guard
                let sessionKey = cryptoOps.deriveSessionKey(using: decryptedIdentityKey, quantumMaterial: quantumMaterial)
            else {
                throw Manager.Crypto.EncryptionError.keyDerivationFailed
            }
            
            decryptedSealedPayload = try cryptoOps.open(bundle, using: sessionKey)
        }
 
        guard let decryptedSealedPayload else { throw Errors.decryptionFailed }
 
        // ── 6. Detect inbound fallback → schedule fresh batch ─────────────
        //
        // A .longTermFallback bundle means the sender is out of our prekeys.
        // Generate a new batch immediately so Alice's next outbound message
        // to Bob carries it.
        if bundle.secrecy.mode == .longTermFallback && sender.hasPendingBatch == false {
            debugPrint("🔥 longTermFallback detected — storing fresh pending batch for sender \(sender.identifier)")
            
            let prekeys = try prekeyManager.generateBatch(contactID: sender.identifier)
            /// These prekeys do not contain any useful information for an attacker. They have been stripped of anything meaningful.
            let prekeysSuitableForTransport = prekeys.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
            let timestamp = Date()
            let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: timestamp, prekeys: prekeysSuitableForTransport)
            /// Store the newly generated batch with wired prekeys so it can be sent with the next message.
            try sender.store(batch: batch)
            
            debugPrint("Storage complete. Ready to send new prekey batch in the next message.")
        }
        
        let decodedPayload = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: decryptedSealedPayload)
 
        // ── 7. Store inbound prekey batch ────────────────────────────────
        if let inboundBatch = decodedPayload.prekeyBatch {
            debugPrint("Decrypting bundle containing inbound prekey sync batch...")
            
            guard inboundBatch.prekeys.count <= Manager.PrekeyManager.defaultBatchSize * 2 else {
                throw Errors.invalidPrekeySyncBatch
            }
            guard inboundBatch.prekeys.allSatisfy({ $0.publicKey.count == 65 }) else {
                throw Errors.invalidBundleFormat
            }
 
            let blobs: [Data] = inboundBatch.prekeys.compactMap { wired in
                /// Converted back to `PreKey` so we can look up a key by contact ID during decryption.
                let prekey = Prekey(id: wired.id, contactID: sender.identifier, publicKey: wired.publicKey)
                
                guard
                    let encoded = try? JSONEncoder().encode(prekey)
                else { return nil }
                
                return encoded
            }
            
            debugPrint("Sender's prekeys in our storage before syncInboundPrekeys: \(sender.availableInboundPrekeyCount)")
            
            try sender.syncInboundPrekeys(blobs, date: inboundBatch.generatedAt)
        }
 
        // ── 8. Persist ───────────────────────────────────────────────────
        try self.modelContext.save()
        
        debugPrint("Saved after decrypt. Inbound prekeys now: \(sender.availableInboundPrekeyCount), sender: \(sender.givenName.decrypt()), pending batch: \(sender.hasPendingBatch)")
 
        return (decodedPayload.message, sender.identifier)
    }
}
