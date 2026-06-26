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
import CoreData
import Foundation
import CryptoKit

@Observable
class ContactManager {
    private let modelExecutor: any ModelExecutor
    private let modelContainer: ModelContainer
    // Internal (not private) so Manager.Security can flush the context during key rotation.
    // Swift `private` is file-scoped; extensions in other files cannot see it.
    var modelContext: ModelContext { self.modelExecutor.modelContext }
    
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
    
    var contactKeyUpdated: PassthroughSubject<String, Never> = .init()
    /// Emitted (with the contact's identifier) when `update(key:for:)` stores a
    /// key whose P-256 fingerprint differs from the previously active key.
    /// Subscribers (e.g. ShardCustodyManager) use this to schedule auto-returns.
    var contactKeyRotated: PassthroughSubject<String, Never> = .init()

    @ObservationIgnored
    let security: Manager.Security
    @ObservationIgnored
    private var cancellables = Set<AnyCancellable>()

    init(modelContainer: ModelContainer, security: Manager.Security) {
        self.modelExecutor = DefaultSerialModelExecutor(modelContext: ModelContext(modelContainer))
        self.modelContainer = modelContainer
        self.security = security

        NotificationCenter.default
            .publisher(
                for: NSManagedObjectContext.didSaveObjectsNotification,
                object: self.modelExecutor.modelContext
            )
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.syncShareIndex()
            }
            .store(in: &self.cancellables)
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
    /// - Parameter currentDepth: Secure Mode depth at creation time. 0 = true layer (default).
    func createContacts(from cnContacts: [CNContact], currentDepth: Int = 0) throws {
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
            
            // visibleThroughDepth is always encrypted, never nil.
            // Depth 0 imports are safe contacts → Int.max (visible everywhere).
            // Depth N > 0 contacts are stamped with N (hidden from deeper layers).
            let depthValue = currentDepth == 0 ? Int.max : currentDepth
            newContact.visibleThroughDepth = try JSONEncoder().encode(depthValue).encrypt()
            self.modelContext.insert(newContact)
        }

        try self.modelContext.save()
    }

    func save(contacts: [Contact.Draft]) throws {
        for contact in contacts {
            try self.save(contact: contact)
        }
    }
    
    /// Save a new custom contact or update an existing contact.
    /// - Parameter contact: Custom contact. Thread safe.
    /// - Parameter currentDepth: Secure Mode depth at creation time. 0 = true layer (default).
    func save(contact: Contact.Draft, currentDepth: Int = 0) throws {
        try self.save(contact: contact, currentDepth: currentDepth, using: self.cryptoManager)
    }

    /// Overload used by Secure Mode activation to re-encrypt safe contacts under the staged key.
    /// Identical to `save(contact:currentDepth:)` but uses `crypto` instead of `self.cryptoManager`.
    func save(contact: Contact.Draft, currentDepth: Int = 0, using crypto: any CryptoProtocol) throws {
        let encryptedIdentifier = contact.identifier
        let encryptedGivenName = try crypto.encrypt(data: contact.givenName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedFamilyName = try crypto.encrypt(data: contact.familyName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedMiddleName = try crypto.encrypt(data: contact.middleName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedNamePrefix = try crypto.encrypt(data: contact.namePrefix.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedNameSuffix = try crypto.encrypt(data: contact.nameSuffix.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedNickname = try crypto.encrypt(data: contact.nickname.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedOrganizationName = try crypto.encrypt(data: contact.organizationName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedDepartmentName = try crypto.encrypt(data: contact.departmentName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedJobTitle = try crypto.encrypt(data: contact.jobTitle.data(using: .utf8))?.base64EncodedString() ?? ""

        let encryptedImageData = try crypto.encrypt(data: contact.imageData)
        let encryptedThumbnailImageData = try crypto.encrypt(data: contact.thumbnailImageData)

        var encryptedEmailAddresses: [CNLabeledValue<NSString>] = []

        contact.emailAddresses.forEach { email in
            do {
                let label = try crypto.encrypt(data: email.label.data(using: .utf8))?.base64EncodedString() ?? ""
                let value = try crypto.encrypt(data: String(email.value).data(using: .utf8))?.base64EncodedString() ?? ""

                encryptedEmailAddresses.append(CNLabeledValue(label: label, value: value as NSString))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }

        var encryptedPhoneNumbers: [CNLabeledValue<CNPhoneNumber>] = []

        contact.phoneNumbers.forEach { phoneNumber in
            do {
                let label = try crypto.encrypt(data: phoneNumber.label.data(using: .utf8))?.base64EncodedString() ?? ""
                let value = try crypto.encrypt(data: phoneNumber.value.data(using: .utf8))?.base64EncodedString() ?? ""

                encryptedPhoneNumbers.append(CNLabeledValue(label: label, value: CNPhoneNumber(stringValue: value)))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }

        var encryptedPostalAddresses: [Contact.Profile.PostalAddress] = []

        contact.postalAddresses.forEach { postalAddress in
            do {
                let encryptedStreet = try crypto.encrypt(data: postalAddress.street.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedCity = try crypto.encrypt(data: postalAddress.city.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedState = try crypto.encrypt(data: postalAddress.state.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedPostalCode = try crypto.encrypt(data: postalAddress.postalCode.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedCountry = try crypto.encrypt(data: postalAddress.country.name.data(using: .utf8))?.base64EncodedString() ?? ""
                let encryptedIsoCountryCode = try crypto.encrypt(data: postalAddress.country.code.data(using: .utf8))?.base64EncodedString() ?? ""

                let mutable = CNMutablePostalAddress()

                mutable.street = encryptedStreet
                mutable.city = encryptedCity
                mutable.state = encryptedState
                mutable.postalCode = encryptedPostalCode
                mutable.country = encryptedCountry
                mutable.isoCountryCode = encryptedIsoCountryCode

                let encryptedLabel = try crypto.encrypt(data: postalAddress.label.data(using: .utf8))?.base64EncodedString() ?? ""

                encryptedPostalAddresses.append(Contact.Profile.PostalAddress(from: CNLabeledValue<CNMutablePostalAddress>(label: encryptedLabel, value: mutable)))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }

        var encryptedURLs: [Contact.Profile.URLAddress] = []

        contact.urlAddresses.forEach { urlAddress in
            do {
                let encryptedLabel = try crypto.encrypt(data: urlAddress.label.data(using: .utf8))?.base64EncodedString() ?? ""
                let url = urlAddress.value as String
                let encryptedURL = try crypto.encrypt(data: url.data(using: .utf8))?.base64EncodedString() ?? ""

                encryptedURLs.append(Contact.Profile.URLAddress(label: encryptedLabel, value: encryptedURL))
            } catch {
                debugPrint("Contact not saved: \(error)")
            }
        }

        let encryptedBirthday: String = try crypto.encrypt(data: contact.birthday?.data(using: .utf8))?.base64EncodedString() ?? ""

        let encryptedNote = try crypto.encrypt(data: contact.note.data(using: .utf8))?.base64EncodedString() ?? ""
        
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
            if let encryptedImageData          { existing.imageData          = encryptedImageData }
            if let encryptedThumbnailImageData { existing.thumbnailImageData = encryptedThumbnailImageData }
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
            
            // visibleThroughDepth is always encrypted, never nil.
            // Depth 0 contacts are safe by default → Int.max (visible everywhere).
            // Depth N > 0 contacts are stamped with N (hidden from deeper layers).
            let depthValue = currentDepth == 0 ? Int.max : currentDepth
            newContact.visibleThroughDepth = try JSONEncoder().encode(depthValue).encrypt()
            self.modelContext.insert(newContact)

            for key in contact.contactPublicKeys {
                try? self.update(key: key, for: newContact.identifier)
            }

            debugPrint("Inserted new contact, id = \(encryptedIdentifier), name - \(String(describing: encryptedGivenName)) \(String(describing: encryptedFamilyName))")
        }

        try self.modelContext.save()
    }

    // MARK: - Read
    
    /// Fetches all contacts from the SwiftData context.
    func fetchAllContacts() throws -> [Contact.Profile] {
        let predicate = #Predicate<Contact.Profile> { $0.deletionToken == nil }
        let descriptor = FetchDescriptor<Contact.Profile>(predicate: predicate, sortBy: [SortDescriptor(\.familyName)])
        return try self.modelContext.fetch(descriptor)
    }
    
    /// Fetches a contact by its identifier.
    func fetchContact(by identifier: String) throws -> Contact.Profile? {
        let predicate = #Predicate<Contact.Profile> { $0.identifier == identifier }
        let descriptor = FetchDescriptor<Contact.Profile>(predicate: predicate)
        let contacts = try self.modelContext.fetch(descriptor)

        return contacts.first
    }

    /// Decrypted x963-uncompressed P-256 public key (65 bytes) for the contact's
    /// most recent unexpired key record, or nil if none.
    ///
    /// Used by inbound routers (e.g. ShardCustodyManager) that need a stable
    /// per-contact identifier (`SHA-256(publicKey)`) after `decryptSealed` has
    /// already resolved the sender by `identifier`.
    func currentPublicKey(forIdentifier identifier: String) throws -> Data? {
        guard
            let contact   = try self.fetchContact(by: identifier),
            let keyRecord = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
            let pubKey    = try? self.cryptoManager.decrypt(data: keyRecord.material)
        else { return nil }
        return pubKey
    }
    
    // MARK: - Delete
    
    /// Soft-deletes a contact by marking it with an encrypted sentinel.
    /// The row remains in SwiftData but is excluded from all public queries.
    /// Enforces a cap of 50 soft-deleted rows: if the cap is reached, one
    /// existing soft-deleted row is hard-deleted before the new marker is written.
    func deleteContact(identifier: String) throws {
        guard let contact = try self.fetchContact(by: identifier) else {
            throw ContactManager.Errors.contactNotFound
        }

        let softDeleted = try self.fetchSoftDeletedContacts()
        if softDeleted.count >= 50, let victim = softDeleted.first {
            self.modelContext.delete(victim)
        }

        contact.deletionToken = try Data([1]).encrypt()
        try self.modelContext.save()
    }

    /// Hard-deletes a single Contact.Profile row from the store.
    /// Only for use in Secure Mode activation — normal deletions use `deleteContact(:)`.
    func hardDeleteContact(_ profile: Contact.Profile) throws {
        self.modelContext.delete(profile)
        try self.modelContext.save()
    }

    /// Hard-deletes all contacts, including soft-deleted rows. Used for panic wipe only.
    func deleteAllContacts() throws {
        try self.modelContext.delete(model: Contact.Profile.self)
        try self.modelContext.save()
    }

    private func fetchSoftDeletedContacts() throws -> [Contact.Profile] {
        let predicate = #Predicate<Contact.Profile> { $0.deletionToken != nil }
        let descriptor = FetchDescriptor<Contact.Profile>(predicate: predicate)
        
        return try self.modelContext.fetch(descriptor)
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
        
        // Detect fingerprint change before appending the new key.
        var keyRotated = false
        
        if let newMaterial = key.material,
           let currentRecord = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
           let storedMaterial = try? self.cryptoManager.decrypt(data: currentRecord.material) {
            keyRotated = SHA256.hash(data: storedMaterial) != SHA256.hash(data: newMaterial)
        }

        contact.contactPublicKeys?.append(Contact.Profile.Key(material: encryptedMaterial, owner: encryptedOwner, date: encryptedCreationDate, quantumKeyMaterialEncrypted: encryptedQuantumKeyMaterial))
        
        #if DEBUG
        debugPrint("Updated key, owner hash = \(key.owner)")
        #endif

        try self.modelContext.save()

        self.contactKeyUpdated.send(identifier)
        if keyRotated { self.contactKeyRotated.send(identifier) }
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
    
    /// Derives the stable per-contact base key used to encrypt file attachments at rest.
    /// Callers pass this into `AttachmentManager(contactKey:)`.
    func fileEncryptionKey(for identifier: String) throws -> SymmetricKey {
        guard let contact = try self.fetchContact(by: identifier) else {
            throw ContactManager.Errors.contactNotFound
        }
        guard let encrypted = contact.contactPublicKeys?.last?.material,
              let material   = try? self.cryptoManager.decrypt(data: encrypted)
        else { throw ContactManager.Errors.contactHasNoKeys }
        guard let key = Manager.Key().createSharedSecret(using: material) else {
            throw ContactManager.Errors.contactHasNoKeys
        }
        return key
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
        case trusteeLacksQuantumMaterial
        case groupIDMissing
        case groupHasNoMembers
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
        
        let security = Manager.Security(modelContainer: sharedModelContainer, enabled: false)
        let manager = ContactManager(modelContainer: sharedModelContainer, security: security)
        
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
        let plaintextPublicKeys = encryptedPublicKeys?.compactMap { record -> Contact.Draft.Key? in
            let material = try? self.cryptoManager.decrypt(data: record.material)
            let ownerHash = (try? self.cryptoManager.decrypt(data: record.owner)) ?? Data()
            let date = String(data: (try? self.cryptoManager.decrypt(data: record.acquiredAt)) ?? Data(), encoding: .utf8) ?? ""

            let quantumMaterial: QuantumKeyMaterial? = {
                guard let enc = record.quantumKeyMaterialEncrypted,
                      let dec = try? self.cryptoManager.decrypt(data: enc)
                else { return nil }
                return try? JSONDecoder().decode(QuantumKeyMaterial.self, from: dec)
            }()

            // ownerHash is already SHA-256(identity_key) from the DB.
            // Draft.Key.init would sha256 it again (double-hash) — override after construction.
            var key = Contact.Draft.Key(material: material, owner: ownerHash, date: date, quantumKeyMaterial: quantumMaterial)
            key?.owner = ownerHash
            return key
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

extension ContactManager {
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
    /// Encrypt a bundle for a contact using the v3fs path.
    ///
    /// **Mode selection is automatic**, driven by whether any shard operation
    /// carries shard data (`.distribute`, `.handback` — i.e. `op.attribute != nil`):
    ///
    /// - **Shard mode** (any `attribute`-carrying op present, or `data == nil`):
    ///   Forces `longTermFallback + ML-KEM`. Prekeys are not consumed; no prekey
    ///   sync batch is attached. `data` defaults to a human-readable fallback for
    ///   old builds. Throws `trusteeLacksQuantumMaterial` if ML-KEM is absent.
    ///
    /// - **Message mode** (no `attribute`-carrying ops, `data` non-nil):
    ///   Standard v3fs path — pops a prekey (→ `.forwardSecret` when available,
    ///   `.longTermFallback` when exhausted), attaches a pending prekey sync
    ///   batch, and saves prekey state. `data` must be non-empty.
    ///
    /// This means `.distribute` and `.handback` always travel on `longTermFallback +
    /// ML-KEM` regardless of call site — the HNDL constraint is enforced once,
    /// here, and cannot be bypassed by a careless caller.
    ///
    /// ## Pending batch delivery guarantee (message mode only)
    /// A `pendingOutboundBatch` is attached to every message until the contact
    /// sends back a `.forwardSecret` bundle using one of our prekeys — cryptographic
    /// proof they stored the batch. Only then is the batch cleared.
    func encryptBundle(
        basket: Basket? = nil,
        for identifier: String,
        shardOperations: [OccultaBundle.ShardOperation]? = nil,
        custodyManifest: [UUID]? = nil,
        expectedShards: [UUID]? = nil
    ) throws -> Data {
        guard basket != nil || shardOperations != nil || custodyManifest != nil || expectedShards != nil else { throw Errors.messageHasNoData }
        
        guard let contact = try self.fetchContact(by: identifier) else { throw Errors.contactNotFound }

        /// We are forcing long term key to be used in the event when a bundle carries shard data.
        /// This is a precaution because when we have prekey public material, which travels on the wire, there is a higher threat from QC calculating the private part.
        let isCarryingShard = shardOperations?.contains(where: { $0.attribute != nil }) == true

        // ── 1. Resolve recipient key material ─────────────────────────────
        let (recipientMaterial, quantumMaterial) = try self.resolveKeyMaterial(for: contact, requireQuantum: isCarryingShard)

        #if DEBUG
        let modeTag = isCarryingShard ? "shard (longTermFallback + ML-KEM)" : "message"
        debugPrint("Sealing \(modeTag) bundle, quantum: \(quantumMaterial != nil)")
        #endif

        // ── 2. Prekey handling ────────────────────────────────────────────
        // Shard mode: never consume prekeys; never carry a prekey sync batch.
        // Message mode: pop prekey (→ .forwardSecret or .longTermFallback);
        //               attach pending batch if one exists.
        var contactPrekey: Prekey? = nil
        var outboundBatch: OccultaBundle.SealedPayload.PrekeySyncBatch? = nil

        if !isCarryingShard {
            try contact.configureForwardSecrecy()
            
            #if DEBUG
            debugPrint("Encrypting message for contact. Inbound prekeys: \(contact.availableInboundPrekeyCount), pending batch: \(contact.hasPendingBatch)")
            #endif
            
            if let blob = try contact.popOldestPrekeyData() {
                contactPrekey = try JSONDecoder().decode(Prekey.self, from: blob)
            }
            
            outboundBatch = try contact.loadPendingBatch()
        }

        // ── 3. Resolve target wire format for this contact ────────────────
        let cryptoOps     = Manager.Crypto()
        let targetVersion = Self.resolveTargetVersion(for: contact, using: cryptoOps)
        // .groupCapable is a capability signal, not a real wire format — the wire byte
        // for both .v4 and .groupCapable is 0x04, and the receiver always decodes it
        // back as .v4. Passing .groupCapable to seal() would embed "groupCapable" in
        // the AAD while the receiver reconstructs "v4" → authentication failure.
        let wireVersion   = targetVersion == .groupCapable ? OccultaBundle.Version.v4 : targetVersion

        // ── 4. Build and seal payload ─────────────────────────────────────
        let messageData: Data
        if let basket {
            messageData = wireVersion == .v4
                ? try WireHandle.encode(basket: basket)
                : try JSONEncoder().encode(basket)
        } else {
            messageData = Data("Occulta vault operation. Please update your app.".utf8)
        }

        let sealedPayload = OccultaBundle.SealedPayload(
            message:         messageData,
            prekeyBatch:     outboundBatch,
            shardOperations: shardOperations,
            custodyManifest: custodyManifest,
            expectedShards:  expectedShards,
            appVersion:      Bundle.main.appVersion
        )
        let encoded = wireVersion == .v4
            ? try WireHandle.encode(payload: sealedPayload)
            : try JSONEncoder().encode(sealedPayload)

        // contactPrekey == nil in shard mode → Manager.Crypto.seal uses longTermFallback.
        let bundle = try Manager.Crypto().seal(
            message:           encoded,
            contactPrekey:     contactPrekey,
            recipientMaterial: recipientMaterial,
            quantumMaterial:   quantumMaterial,
            version:           wireVersion
        )
        let encodedBundle = try bundle.encoded(version: wireVersion)
        
        if contactPrekey != nil {
            // Persist prekey state only when it was mutated (message mode).
            try self.modelContext.save()
        }

        return encodedBundle
    }
}

// MARK: - Group bundle encryption

extension ContactManager {

    /// Encrypt a basket for all members of a group in the given layer.
    ///
    /// Each member gets an independent wrapping key (FS or fallback) and a
    /// per-recipient prekey sync batch if their stock for this sender is below
    /// the replenishment threshold. The shared ciphertext is sealed once with a
    /// random session key bound to the group UUID.
    func encryptGroupBundle(basket: Basket, groupID: UUID, recipients identifierList: [String]) throws -> Data {
        guard !identifierList.isEmpty else { throw Errors.groupHasNoMembers }
        let predicate = #Predicate<Contact.Profile> {
            identifierList.contains($0.identifier) && $0.deletionToken == nil
        }
        let members = try self.modelContext.fetch(FetchDescriptor<Contact.Profile>(predicate: predicate))
        guard !members.isEmpty else { throw Errors.groupHasNoMembers }

        var prekeyConsumed = false
        let recipients: [GroupRecipient] = try members.map { contact in
            let (recipientMaterial, quantumMaterial) = try self.resolveKeyMaterial(for: contact)
            try contact.configureForwardSecrecy()
            var contactPrekey: Prekey? = nil
            if let blob = try contact.popOldestPrekeyData() {
                contactPrekey = try JSONDecoder().decode(Prekey.self, from: blob)
                prekeyConsumed = true
            }
            let pendingBatch = try contact.loadPendingBatch()
            return GroupRecipient(
                publicKey:       recipientMaterial,
                quantumMaterial: quantumMaterial,
                contactPrekey:   contactPrekey,
                pendingBatch:    pendingBatch
            )
        }

        let sealedPayload = OccultaBundle.SealedPayload(
            message:    try WireHandle.encode(basket: basket),
            appVersion: Bundle.main.appVersion
        )
        let payloadData = try WireHandle.encode(payload: sealedPayload)

        let bundle = try Manager.Crypto().sealGroup(
            message:    payloadData,
            groupID:    groupID,
            recipients: recipients
        )
        let encodedBundle = try bundle.encoded(version: .v4)

        if prekeyConsumed {
            try self.modelContext.save()
        }

        return encodedBundle
    }
}

// MARK: - Shard bundle helpers

extension ContactManager {

    /// Contacts eligible to be SSS trustees — those with ML-KEM key material.
    ///
    /// Only UWB-exchanged contacts carry ML-KEM material. Bluetooth-only contacts
    /// are excluded; shard bundles require the hybrid session key for HNDL protection.
    func fetchTrusteeEligibleContacts() throws -> [Contact.Profile] {
        try self.fetchAllContacts().filter { contact in
            guard let key = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }) else {
                return false
            }
            return key.quantumKeyMaterialEncrypted != nil
        }
    }

    /// Decrypt a contact's stored key record and return the P-256 recipient material
    /// and ML-KEM quantum key material (if present).
    ///
    /// - `requireQuantum`: when `true`, throws `trusteeLacksQuantumMaterial` if the
    ///   contact has no quantum key material. Shard mode always passes `true`.
    private func resolveKeyMaterial(for contact: Contact.Profile, requireQuantum: Bool = false) throws -> (recipientMaterial: Data, quantumMaterial: QuantumKeyMaterial?) {
        let cryptoOps = Manager.Crypto()
        
        guard
            let keyRecord         = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
            let recipientMaterial = try? cryptoOps.decrypt(data: keyRecord.material),
            recipientMaterial.count == 65
        else { throw Errors.contactHasNoKeys }

        let quantumMaterial: QuantumKeyMaterial?
        
        if let encrypted = keyRecord.quantumKeyMaterialEncrypted,
           let decrypted = try? cryptoOps.decrypt(data: encrypted) {
            quantumMaterial = try? JSONDecoder().decode(QuantumKeyMaterial.self, from: decrypted)
        } else {
            quantumMaterial = nil
        }

        if requireQuantum, quantumMaterial == nil {
            throw Errors.trusteeLacksQuantumMaterial
        }
        return (recipientMaterial, quantumMaterial)
    }
}

// MARK: - v3fs bundle decryption

extension ContactManager {
    /// Resolves the sender's ML-KEM quantum key material for hybrid session key derivation.
    ///
    /// Only called for `.forwardSecret` and `.longTermFallback` modes — the two paths
    /// that fold quantum material into the session key. NoPQ modes never call this.
    ///
    /// - Throws: `quantumKeyMaterialCorrupted` if the stored ciphertext exists but
    ///   cannot be decoded. A missing field (`nil`) is not an error — it simply means
    ///   no quantum material was exchanged and classical derivation should be used.
    fileprivate func resolveQuantumMaterial(
        for sender: Contact.Profile,
        using cryptoOps: Manager.Crypto
    ) throws -> QuantumKeyMaterial? {
        let validKey = sender.contactPublicKeys?.last(where: { $0.expiredOn == nil })
        guard
            let enc       = validKey?.quantumKeyMaterialEncrypted,
            let decrypted = try? cryptoOps.decrypt(data: enc)
        else { return nil }

        do {
            #if DEBUG
            debugPrint("Opening bundle using quantum material to derive session key...")
            #endif
            return try JSONDecoder().decode(QuantumKeyMaterial.self, from: decrypted)
        } catch {
            throw Errors.quantumKeyMaterialCorrupted
        }
    }
}
 
extension ContactManager {

    /// Resolve the wire format version to use when sending to a contact.
    /// Reads the encrypted `maxBundleVersion` byte and maps it back to a `Version`.
    static func resolveTargetVersion(for contact: Contact.Profile, using crypto: Manager.Crypto) -> OccultaBundle.Version {
        guard
            let enc  = contact.maxBundleVersion,
            let raw  = try? crypto.decrypt(data: enc),
            let byte = raw.first
        else { return .v3fs }
        return WireHandle.byteToVersion(byte) ?? .v3fs
    }

    private func verifyConsistency(for bundle: OccultaBundle) throws {
        guard bundle.version == .v3fs || bundle.version == .v4 else { throw Errors.unsupportedBundleVersion }
        // Defence-in-depth: never touch a bundle whose version or mode was
        // produced by a future build we don't understand. `Version`/`Mode` both
        // decode unknown raw values to `.unsupported` — see OccultaBundle.swift.
        guard bundle.secrecy.mode != .unsupported else { throw OccultaBundle.BundleError.unsupportedMode }
    }
    
    private func identifyOwner(for bundle: OccultaBundle) throws -> Contact.Profile {
        try self.verifyConsistency(for: bundle)
        
        let cryptoOps     = Manager.Crypto()
        
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
        
        guard let sender else { throw Errors.noPublicKeyToEncryptWith }
        
        return sender
    }
    
    func identifyOwner(of bundle: OccultaBundle) throws -> String? {
        let sender = try self.identifyOwner(for: bundle)
        
        return sender.identifier
    }
    /// Decrypt a v3fs bundle and return the plaintext message bytes.
    ///
    /// Regular message path. For identity-challenge traffic the caller needs
    /// the full `SealedPayload` so it can route on `identityChallenge` — use
    /// ``decryptSealed(bundle:)`` instead.
    func decrypt(bundle: OccultaBundle) throws -> (plaintext: Data, ownerID: String) {
        let (sealed, ownerID) = try self.decryptSealed(bundle: bundle)
        return (sealed.message, ownerID)
    }

    /// Decrypt a v3fs bundle and return the full decoded ``SealedPayload``.
    ///
    /// Needed by the identity-challenge routing hook in `OccultaApp`, which
    /// inspects `identityChallenge` to decide whether to hand the bundle to
    /// the basket pipeline or to the `IdentityChallenge.Coordinator`.
    func decryptSealed(bundle: OccultaBundle) throws -> (sealed: OccultaBundle.SealedPayload, ownerID: String) {
        try self.verifyConsistency(for: bundle)
        guard bundle.secrecy.mode != .group else { throw OccultaBundle.BundleError.unsupportedMode }

        let cryptoOps     = Manager.Crypto()
        let prekeyManager = Manager.PrekeyManager()

        // ── 1. Identify sender by fingerprint ───────────────────────────
        let sender = try self.identifyOwner(for: bundle)
        try sender.configureForwardSecrecy()

        // ── 2. Key derivation + open ─────────────────────────────────────
        debugPrint("Opening message, using mode: \(bundle.secrecy.mode)")

        let quantumMaterial = try self.resolveQuantumMaterialIfNeeded(mode: bundle.secrecy.mode, for: sender, using: cryptoOps)
        let senderPublicKey = try self.resolveSenderPublicKey(for: sender, using: cryptoOps)

        let (sessionKey, consumable) = try cryptoOps.deriveInboundKey(
            secrecy: bundle.secrecy,
            senderContactID: sender.identifier,
            senderPublicKey: senderPublicKey,
            quantumMaterial: quantumMaterial,
            prekeyManager: prekeyManager
        )
        let payloadData = try cryptoOps.open(bundle, using: sessionKey)

        // ── 3. Prekey management ─────────────────────────────────────────
        if let consumable {
            #if DEBUG
            debugPrint("Opened bundle using prekey = \(consumable), consuming key...")
            #endif
            prekeyManager.consume(prekey: consumable)
            try sender.clearPendingBatch()
            debugPrint("Message successfully opened in \(bundle.secrecy.mode) mode. Pending batch cleared.")
        } else if !sender.hasPendingBatch {
            try self.generateAndStoreFreshBatch(for: sender, using: prekeyManager)
        }

        // ── 4. Decode, update capability, store inbound batch ────────────
        let decodedPayload = try self.decodePayload(payloadData, version: bundle.version)
        try self.updateMaxVersion(from: decodedPayload.appVersion, for: sender, using: cryptoOps)
        try self.storeInboundBatch(decodedPayload.prekeyBatch, for: sender)

        // ── 5. Persist ───────────────────────────────────────────────────
        try self.modelContext.save()

        debugPrint("Saved after decrypt. Inbound prekeys now: \(sender.availableInboundPrekeyCount), sender: \(sender.givenName.decrypt()), pending batch: \(sender.hasPendingBatch)")

        return (decodedPayload, sender.identifier)
    }
}

// MARK: - Decrypt helpers (private)

extension ContactManager {

    private func resolveSenderPublicKey(for sender: Contact.Profile, using cryptoOps: Manager.Crypto) throws -> Data {
        guard
            let keyRecord = sender.contactPublicKeys?.first(where: { $0.expiredOn == nil }),
            let decrypted = try cryptoOps.decrypt(data: keyRecord.material)
        else { throw Errors.decryptionFailed }
        return decrypted
    }

    private func resolveQuantumMaterialIfNeeded(
        mode: OccultaBundle.Mode,
        for sender: Contact.Profile,
        using cryptoOps: Manager.Crypto
    ) throws -> QuantumKeyMaterial? {
        switch mode {
        case .forwardSecret, .longTermFallback:
            return try self.resolveQuantumMaterial(for: sender, using: cryptoOps)
        default:
            return nil
        }
    }

    private func generateAndStoreFreshBatch(for sender: Contact.Profile, using prekeyManager: Manager.PrekeyManager) throws {
        debugPrint("🔥 longTerm(fallback|NoPQ) detected — storing fresh pending batch for sender \(sender.identifier)")
        let prekeys = try prekeyManager.generateBatch(contactID: sender.identifier)
        let prekeysSuitableForTransport = prekeys.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(), prekeys: prekeysSuitableForTransport)
        try sender.store(batch: batch)
        debugPrint("Storage complete. Ready to send new prekey batch in the next message.")
    }

    private func decodePayload(_ data: Data, version: OccultaBundle.Version) throws -> OccultaBundle.SealedPayload {
        if version == .v4 {
            return try WireHandle.decode(payload: data)
        } else {
            return try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: data)
        }
    }

    private func updateMaxVersion(from appVersion: String?, for sender: Contact.Profile, using cryptoOps: Manager.Crypto) throws {
        guard let appVersion else { return }
        let maxVersion = OccultaBundle.Version.max(forAppVersion: appVersion)
        guard let byte = maxVersion.wireByte else { return }
        sender.maxBundleVersion = try cryptoOps.encrypt(data: Data([byte]))
    }

    private func storeInboundBatch(_ batch: OccultaBundle.SealedPayload.PrekeySyncBatch?, for sender: Contact.Profile) throws {
        guard let batch else { return }
        debugPrint("Decrypting bundle containing inbound prekey sync batch...")
        guard batch.prekeys.count <= Manager.PrekeyManager.defaultBatchSize * 2 else {
            throw Errors.invalidPrekeySyncBatch
        }
        guard batch.prekeys.allSatisfy({ $0.publicKey.count == 65 }) else {
            throw Errors.invalidBundleFormat
        }
        let blobs: [Data] = batch.prekeys.compactMap { wired in
            let prekey = Prekey(id: wired.id, contactID: sender.identifier, publicKey: wired.publicKey)
            return try? JSONEncoder().encode(prekey)
        }
        debugPrint("Sender's prekeys in our storage before syncInboundPrekeys: \(sender.availableInboundPrekeyCount)")
        try sender.syncInboundPrekeys(blobs, date: batch.generatedAt)
    }
}

// MARK: - Group bundle decryption

extension ContactManager {

    /// Decrypt a group bundle and return the payload, sender ID, and group ID.
    ///
    /// The caller resolves the local Group record from `groupID` by matching against
    /// each group's decrypted `encryptedID`.
    func openGroup(bundle: OccultaBundle) throws -> (sealed: OccultaBundle.SealedPayload, ownerID: String, groupID: UUID) {
        guard bundle.secrecy.mode == .group, let envelope = bundle.group else {
            throw OccultaBundle.BundleError.unsupportedMode
        }

        let cryptoOps     = Manager.Crypto()
        let prekeyManager = Manager.PrekeyManager()

        // ── 1. Identify sender ──────────────────────────────────────────
        let sender = try self.identifyOwner(for: bundle)
        try sender.configureForwardSecrecy()

        // ── 2. Find our recipient slot ──────────────────────────────────
        let entry = try cryptoOps.findRecipientSlot(in: bundle)

        // ── 3. Resolve key material for this slot ───────────────────────
        let quantumMaterial = try self.resolveQuantumMaterialIfNeeded(
            mode: entry.secrecyContext.mode, for: sender, using: cryptoOps
        )
        let senderPublicKey = try self.resolveSenderPublicKey(for: sender, using: cryptoOps)

        // ── 4. Derive wrapping key, open our slot ───────────────────────
        let (wrappingKey, consumable) = try cryptoOps.deriveInboundKey(
            secrecy: entry.secrecyContext,
            senderContactID: sender.identifier,
            senderPublicKey: senderPublicKey,
            quantumMaterial: quantumMaterial,
            prekeyManager: prekeyManager
        )
        let recipientPayload = try cryptoOps.openWrappedPayload(entry, groupID: envelope.id, using: wrappingKey)

        // ── 5. Prekey management ─────────────────────────────────────────
        if let consumable {
            prekeyManager.consume(prekey: consumable)
            try sender.clearPendingBatch()
        } else if !sender.hasPendingBatch {
            try self.generateAndStoreFreshBatch(for: sender, using: prekeyManager)
        }

        // ── 6. Open shared ciphertext ────────────────────────────────────
        let sessionKey  = SymmetricKey(data: recipientPayload.sessionKey)
        let payloadData = try cryptoOps.openGroupCiphertext(bundle, using: sessionKey)
        let decoded     = try WireHandle.decode(payload: payloadData)

        // ── 7. Post-processing ────────────────────────────────────────────
        try self.updateMaxVersion(from: decoded.appVersion, for: sender, using: cryptoOps)
        try self.storeInboundBatch(recipientPayload.prekeyBatch, for: sender)
        try self.modelContext.save()

        return (decoded, sender.identifier, envelope.id)
    }
}
