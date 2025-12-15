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
            existing.namePrefix = encryptedNamePrefix
            existing.nameSuffix = encryptedNameSuffix
            existing.note = encryptedNote
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
                emailAddresses: encryptedEmailAddresses.map { Contact.Profile.EmailAddress(from: $0) }
            )
            
            self.modelContext.insert(newContact)
            
            debugPrint("Inserted new contact, id = \(encryptedIdentifier), name - \(String(describing: encryptedGivenName)) \(String(describing: encryptedFamilyName))")
        }
    
        try self.modelContext.save()
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
            throw ContactManager.Errors.identityNotSaved
        }
        
        contact.contactPublicKeys.append(Contact.Profile.Key(material: encrypted))
        
        try self.modelContext.save()
    }
    
    func encrypt(message: String, for identifier: String) throws -> String? {
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManager.Errors.contactNotFound
        }
        
        guard
            let publicKeyingMaterial = contact.contactPublicKeys.last?.material
        else {
            throw ContactManager.Errors.contactHasNoKeys
        }
        
        guard
            let payload = message.data(using: .utf8)
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        if let encrypted = try self.cryptoManager.encrypt(message: payload, using: publicKeyingMaterial) {
            let originPublicKeyHash = try KeyManager().retrieveIdentity().sha256
            let recipients = publicKeyingMaterial.sha256
            
            let message = Message(id: UUID().uuidString, origin: originPublicKeyHash, recipients: [recipients], content: encrypted)
            let encoded = try JSONEncoder().encode(message)
            
            let encodedBase64 = encoded.base64EncodedString()
            
            return encodedBase64
        } else {
            return nil
        }
    }
    
    func decrypt(message: String, for identifier: String) throws -> String? {
        guard
            let contact = try self.fetchContact(by: identifier)
        else {
            throw ContactManager.Errors.contactNotFound
        }
        
        guard
            let publicKeyingMaterial = contact.contactPublicKeys.last?.material
        else {
            throw ContactManager.Errors.contactHasNoKeys
        }
        
        guard
            let decoded = Data(base64Encoded: message)
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        let decoder = JSONDecoder()
        let message = try decoder.decode(Message.self, from: decoded)
        
        guard
            let payload = message.content
        else {
            throw ContactManager.Errors.messageHasNoData
        }
        
        guard
            let decrypted = try self.cryptoManager.decrypt(message: payload, using: publicKeyingMaterial)
        else {
            return nil
        }
        
        return String(data: decrypted, encoding: .utf8)
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
            
            let testing = Contact.Profile(identifier: encryptedIdentifier, givenName: encryptedGivenName, familyName: encryptedFamilyName, middleName: encryptedMiddleName, nickname: encryptedNickname, organizationName: encryptedOrganizationName, departmentName: encryptedDepartmentName, jobTitle: encryptedJobTitle)
            
            sharedModelContainer.mainContext.insert(testing)
            try sharedModelContainer.mainContext.save()
        } catch {
            
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
        
        let phoneNumbers: [Contact.Draft.PhoneNumber] = try storedContact.phoneNumbers.map { stored in
            let label = try decryptString(stored.label)
            let value = try decryptString(stored.value)
            
            var phone = Contact.Draft.PhoneNumber(label: label, value: value)
            
            phone.type = Contact.Draft.PhoneNumber.PhoneType.allCases
                .first { $0.rawValue.localizedCaseInsensitiveCompare(label) == .orderedSame } ?? .other
            return phone
        }
        
        let emailAddresses: [Contact.Draft.EmailAddress] = try storedContact.emailAddresses.map { stored in
            let label = try decryptString(stored.label)
            let value = try decryptString(stored.value)
            
            var email = Contact.Draft.EmailAddress(label: label, value: value)
            
            email.type = Contact.Draft.EmailAddress.EmailType.allCases
                .first { $0.rawValue.localizedCaseInsensitiveCompare(label) == .orderedSame } ?? .other
            
            return email
        }
        
        let postalAddresses: [Contact.Draft.PostalAddress] = try storedContact.postalAddresses.map { stored in
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
        
        let urlAddresses: [Contact.Draft.URLAddress] = try storedContact.urlAddresses.map { stored in
            let label = try decryptString(stored.label)
            let value = try decryptString(stored.value)
            
            var url = Contact.Draft.URLAddress(label: label, value: value)
            
            url.type = Contact.Draft.URLAddress.WebsiteType.allCases
                .first { $0.rawValue.localizedCaseInsensitiveCompare(label) == .orderedSame } ?? .other
            
            return url
        }
        
        let encryptedPublicKeys = storedContact.contactPublicKeys
        let plaintextPublicKeys = encryptedPublicKeys.map { Contact.Draft.Key(material: try? self.cryptoManager.decrypt(data: $0.material)) }
        
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
            phoneNumbers: phoneNumbers,
            emailAddresses: emailAddresses,
            postalAddresses: postalAddresses,
            urlAddresses: urlAddresses,
            importedAt: storedContact.importedAt,
            contactPublicKeys: plaintextPublicKeys
        )
    }
    /// Returns a Draft with all properties still encrypted (no decryption performed)
    /// Use this for locked/preview state or when key is unavailable
    ///
    /// This will be using to export our contacts.
    @available(*, unavailable, message: "This function is no longer supported. We cannot export contacts encrypted with out private key, because the destination device does not have a way to decrypt them.")
    func convertToEncryptedCopy(using identifier: String) throws -> Contact.Draft {
        guard
            let storedContact = try self.fetchContact(by: identifier)
        else {
            throw Errors.contactNotFound
        }
        
        var encrypted = Contact.Draft(identifier: identifier, status: .encrypted)
        
        encrypted.givenName = storedContact.givenName
        encrypted.familyName = storedContact.familyName
        encrypted.middleName = storedContact.middleName
        encrypted.namePrefix = storedContact.namePrefix
        encrypted.nameSuffix = storedContact.nameSuffix
        encrypted.nickname = storedContact.nickname
        
        encrypted.organizationName = storedContact.organizationName
        encrypted.departmentName = storedContact.departmentName
        encrypted.jobTitle = storedContact.jobTitle
        
        encrypted.phoneticGivenName = storedContact.phoneticGivenName
        encrypted.phoneticMiddleName = storedContact.phoneticMiddleName
        encrypted.phoneticFamilyName = storedContact.phoneticFamilyName
        
        encrypted.note = storedContact.note
        encrypted.birthday = storedContact.birthday
        
        encrypted.thumbnailImageData = storedContact.thumbnailImageData
        encrypted.imageData = storedContact.imageData
        
        encrypted.phoneNumbers = storedContact.phoneNumbers.map { stored in
            Contact.Draft.PhoneNumber(label: stored.label, value: stored.value)
        }
        
        encrypted.emailAddresses = storedContact.emailAddresses.map { stored in
            Contact.Draft.EmailAddress(label: stored.label, value: stored.value)
        }
        
        encrypted.postalAddresses = storedContact.postalAddresses.map { stored in
            Contact.Draft.PostalAddress(
                label: stored.label,
                street: stored.street,
                city: stored.city,
                state: stored.state,
                postalCode: stored.postalCode,
                country: .init(code: stored.isoCountryCode)
            )
        }
        
        encrypted.urlAddresses = storedContact.urlAddresses.map { stored in
            Contact.Draft.URLAddress(label: stored.label, value: stored.value)
        }
        
        encrypted.importedAt = storedContact.importedAt
        
        return encrypted
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
        
        guard
            let export = Contact.Export(payload: encodedContacts, type: .contacts)
        else {
            throw Errors.noDataToExport
        }
        
        let encodedExport = try JSONEncoder().encode(export)
        
        guard
            let encryptedContacts = try cryptoOps.encrypt(contacts: encodedExport, using: passphrase)
        else {
            throw Errors.encryptionFailed
        }
        
        return encryptedContacts
    }
}
