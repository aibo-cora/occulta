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
            // globalTrusteeDepth is always encrypted, never nil — -1 (not a trustee)
            // until explicitly marked one via VaultGlobalTrustees.
            newContact.globalTrusteeDepth = try JSONEncoder().encode(-1).encrypt()
            // originDepth is always encrypted, never nil — currentDepth directly, no
            // ternary needed: 0 already means "real depth, no confinement" (the sentinel),
            // and any N > 0 means "born at duress depth N" (see Contact.Profile.originDepth).
            newContact.originDepth = try JSONEncoder().encode(currentDepth).encrypt()
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
        // Not encrypted here despite the name this held before — `save` is dual-purpose
        // (create or update). For an edit, this is already the exact value stored at
        // creation time, and the lookup below only works comparing it as-is; encrypting
        // it here (a fresh nonce every call) would never match the stored ciphertext,
        // turning every edit into a duplicate-creating "not found". Only the genuinely
        // new-contact branch below encrypts it once, before it's ever stored.
        let rawIdentifier = contact.identifier
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
                #if DEBUG
                debugPrint("Contact not saved: \(error)")
                #endif
            }
        }

        var encryptedPhoneNumbers: [CNLabeledValue<CNPhoneNumber>] = []

        contact.phoneNumbers.forEach { phoneNumber in
            do {
                let label = try crypto.encrypt(data: phoneNumber.label.data(using: .utf8))?.base64EncodedString() ?? ""
                let value = try crypto.encrypt(data: phoneNumber.value.data(using: .utf8))?.base64EncodedString() ?? ""

                encryptedPhoneNumbers.append(CNLabeledValue(label: label, value: CNPhoneNumber(stringValue: value)))
            } catch {
                #if DEBUG
                debugPrint("Contact not saved: \(error)")
                #endif
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
                #if DEBUG
                debugPrint("Contact not saved: \(error)")
                #endif
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
                #if DEBUG
                debugPrint("Contact not saved: \(error)")
                #endif
            }
        }

        let encryptedBirthday: String = try crypto.encrypt(data: contact.birthday?.data(using: .utf8))?.base64EncodedString() ?? ""

        let encryptedNote = try crypto.encrypt(data: contact.note.data(using: .utf8))?.base64EncodedString() ?? ""
        
        /// Storing
        
        if let existing = try self.fetchContact(by: rawIdentifier) {
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
            // Encrypted once, here, before this identifier is ever stored — matching
            // createContacts' treatment of imported contacts' identifiers (SecurityReview
            // 2026-07-24, finding #11). Safe specifically because this is the
            // never-before-persisted branch: nothing later needs to re-derive this value
            // from the raw UUID, only read back whatever ends up stored.
            let encryptedIdentifier = try crypto.encrypt(data: rawIdentifier.data(using: .utf8))?.base64EncodedString() ?? rawIdentifier
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
            // globalTrusteeDepth is always encrypted, never nil — -1 (not a trustee)
            // until explicitly marked one via VaultGlobalTrustees.
            newContact.globalTrusteeDepth = try JSONEncoder().encode(-1).encrypt()
            // originDepth is always encrypted, never nil — currentDepth directly, no
            // ternary needed: 0 already means "real depth, no confinement" (the sentinel),
            // and any N > 0 means "born at duress depth N" (see Contact.Profile.originDepth).
            newContact.originDepth = try JSONEncoder().encode(currentDepth).encrypt()
            self.modelContext.insert(newContact)

            for key in contact.contactPublicKeys {
                try? self.update(key: key, for: newContact.identifier)
            }

            #if DEBUG
            debugPrint("Inserted new contact, id = \(encryptedIdentifier), name - \(String(describing: encryptedGivenName)) \(String(describing: encryptedFamilyName))")
            #endif
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
    ///
    /// A deleted contact is purged from every group's membership at every depth — see
    /// `Group.purgeMember(_:)`. Unlike classification's duress-only wipe, this is safe to
    /// run regardless of depth: it only ever touches the one identifier being removed
    /// and leaves every other member untouched, so it can't destroy decoy content
    /// prepared for a different depth.
    ///
    /// `vaultManager`/`shardCustodyManager` are optional, nil-safe parameters —
    /// following the same shape as `encryptGroupBundle`/`activateSecureMode` — so a
    /// call site without them just skips shard-custody cleanup rather than failing.
    /// When provided, purges `CustodyShard`/`PendingShardDistribute`/
    /// `PotentiallyLostShard` for this identifier (see
    /// `ShardCustodyManager.purgeCustody(for:)`) and marks any of this contact's
    /// outstanding vault shards lost. Global-trustee status needs no separate purge —
    /// it lives on the contact's own (now soft-deleted) row.
    func deleteContact(
        identifier: String,
        vaultManager: VaultManager? = nil,
        shardCustodyManager: ShardCustodyManager? = nil
    ) throws {
        guard let contact = try self.fetchContact(by: identifier) else {
            throw ContactManager.Errors.contactNotFound
        }

        let softDeleted = try self.fetchSoftDeletedContacts()
        if softDeleted.count >= 50, let victim = softDeleted.first {
            self.modelContext.delete(victim)
        }

        contact.deletionToken = try Data([1]).encrypt()
        Message.Draft.purge(recipientID: identifier, in: self.modelContext)
        Manager.PrekeyManager().deleteAllKeys(for: identifier)
        try self.modelContext.save()

        // Derived once and reused across every group in the pass below, instead of once
        // per group — see `ContactManager.cleanUpGroupDuressMembership`, which applies
        // the same fix for the identical cost on the classification path.
        guard let key = try Manager.Key().createHybridLocalEncryptionKey() else {
            throw GroupError.keyUnavailable
        }
        try self.forEachGroup { try $0.purgeMember(identifier, usingKey: key) }

        // Checkpoint after the group purge's own save, not before — see the identical
        // comment in ContactManager+Classification.swift's saveClassification/
        // setVisibility (SecurityReview2026-07-24, finding #10).
        self.security.checkpointStore()

        try shardCustodyManager?.purgeCustody(for: identifier)
        vaultManager?.markShardsLost(forContact: identifier)
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
    @MainActor static var preview: ContactManager {
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
 
// MARK: - Bundle encryption

extension ContactManager {
    /// Encrypt a bundle for a single contact.
    ///
    /// ## Path routing
    ///
    /// The send path is determined by `resolveTargetVersion(for:)`:
    ///
    /// **≥ 1.9.0 (`groupCapable`) → group bundle format**
    ///   - Calls `seal(message:groupID:recipients:)` with a single-entry ephemeral group.
    ///   - `groupID` is a fresh `UUID()` per bundle — not stored in the Group entity.
    ///   - Shard ops (`isCarryingShard == true`) require a prekey. If none is available,
    ///     shard operations are silently dropped and the basket is sent on `longTermFallback`.
    ///     This ensures message delivery is never blocked by prekey exhaustion — shard content
    ///     simply defers to the next bundle that has a prekey available.
    ///   - Shard-only sends (`basket == nil`) use `Data()` as the message sentinel. The
    ///     receiver detects the empty message and skips basket decode.
    ///   - Message sends pop a prekey (FS when available, longTermFallback when exhausted)
    ///     and attach a pending prekey sync batch.
    ///
    /// **< 1.9.0 → single-recipient legacy format (`seal(message:contactPrekey:...)`)**
    ///   - Shard ops on this path skip prekey pop and use longTermFallback (no FS mandate).
    ///   - Identity challenge sends are always on this path regardless of version.
    ///
    /// ## Pending batch delivery guarantee (message mode)
    /// A `pendingOutboundBatch` is attached to every message until the contact sends back
    /// a `.forwardSecret` bundle using one of our prekeys — cryptographic proof they stored
    /// it. Only then is the batch cleared.
    func encryptBundle(
        basket: Basket? = nil,
        for identifier: String,
        shardOperations: [OccultaBundle.ShardOperation]? = nil,
        custodyManifest: [UUID]? = nil,
        expectedShards: [UUID]? = nil
    ) throws -> Data {
        guard basket != nil || shardOperations != nil || custodyManifest != nil || expectedShards != nil else { throw Errors.messageHasNoData }
        
        guard let contact = try self.fetchContact(by: identifier) else { throw Errors.contactNotFound }

        // Shard ops carry private key material — ML-KEM is always required so a
        // quantum adversary cannot retroactively break the wrapping key.
        let isCarryingShard = shardOperations?.contains(where: { $0.attribute != nil }) == true

        // ── 1. Resolve recipient key material ─────────────────────────────
        let (recipientMaterial, quantumMaterial) = try self.resolveKeyMaterial(for: contact, requireQuantum: isCarryingShard)

        #if DEBUG
        let modeTag = isCarryingShard ? "shard (ML-KEM required)" : "message"
        debugPrint("Sealing \(modeTag) bundle, quantum: \(quantumMaterial != nil)")
        #endif

        // ── 2. Prekey handling ────────────────────────────────────────────
        // Message mode: pop prekey (→ .forwardSecret or .longTermFallback);
        //               attach pending batch if one exists.
        // Shard mode (group path): pop prekey — FS preferred for shards;
        //               shard ops dropped silently if no prekey available.
        // Shard mode (old path, <1.9.0): skip prekey — keep longTermFallback.
        var contactPrekey: Prekey? = nil
        var outboundBatch: OccultaBundle.SealedPayload.PrekeySyncBatch? = nil

        // ── 3. Resolve target wire format for this contact ────────────────
        let cryptoOps     = Manager.Crypto()
        let targetVersion = Self.resolveTargetVersion(for: contact, using: cryptoOps)
        // .groupCapable/.groupShardCapable are capability signals, not real wire
        // formats — the wire byte for .v4, .groupCapable, and .groupShardCapable is
        // all 0x04, and the receiver always decodes it back as .v4. Passing either
        // capability case to seal() would embed its own raw value in the AAD while
        // the receiver reconstructs "v4" → authentication failure.
        let wireVersion   = targetVersion.supportsGroups ? OccultaBundle.Version.v4 : targetVersion

        // Pop a prekey for forward secrecy.
        // Message sends always attempt FS; shard sends on the group path require it.
        // Old-path (<1.9.0) shard sends skip this and use longTermFallback.
        let needsPrekey = !isCarryingShard || targetVersion.supportsGroups
        if needsPrekey {
            try contact.configureForwardSecrecy()

            #if DEBUG
            debugPrint("Encrypting \(isCarryingShard ? "shard" : "message") bundle for contact. Inbound prekeys: \(contact.availableInboundPrekeyCount), pending batch: \(contact.hasPendingBatch)")
            #endif

            if let blob = try contact.popOldestPrekeyData() {
                contactPrekey = try JSONDecoder().decode(Prekey.self, from: blob)
            }
            if !isCarryingShard {
                outboundBatch = try contact.loadPendingBatch()
            }
        }

        // ── 4. Build and seal payload ─────────────────────────────────────
        let messageData: Data
        if let basket {
            messageData = wireVersion == .v4
                ? try WireHandle.encode(basket: basket)
                : try JSONEncoder().encode(basket)
        } else {
            messageData = Data("Occulta vault operation. Please update your app.".utf8)
        }

        // 1.9.0+ contacts: all sends use the group bundle format with an ephemeral
        // single-recipient envelope. Shard ops require forward secrecy — the FS
        // wrapping key is consumed after one use, so a harvested bundle cannot be
        // decrypted later even if the shard itself is later obtained.
        if targetVersion.supportsGroups {
            // Drop all shard-protocol fields — not just ops — if no prekey is
            // available. FS is required for shard content on this path (ops,
            // custody manifest, and expected-shards alike); message delivery must
            // not be blocked by prekey exhaustion.
            let hasShardContent = isCarryingShard || custodyManifest != nil || expectedShards != nil
            let onFallback       = hasShardContent && contactPrekey == nil
            // Shard-only bundles (basket == nil) use Data() as a sentinel so the
            // receiver can detect "no basket" without trying to parse the payload.
            let groupMessage = basket != nil ? messageData : Data()
            let sealedPayload = OccultaBundle.SealedPayload(
                message:         groupMessage,
                shardOperations: onFallback ? nil : shardOperations,
                custodyManifest: onFallback ? nil : custodyManifest,
                expectedShards:  onFallback ? nil : expectedShards,
                appVersion:      Bundle.main.appVersion
            )
            let bundle = try Manager.Crypto().seal(
                sealedPayload: sealedPayload,
                groupID:       UUID(),
                recipients:    [GroupRecipient(
                    publicKey:       recipientMaterial,
                    quantumMaterial: quantumMaterial,
                    contactPrekey:   contactPrekey,
                    pendingBatch:    outboundBatch
                )]
            )
            let encodedBundle = try bundle.encoded(version: .v4)
            if contactPrekey != nil { try self.modelContext.save() }
            return encodedBundle
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

/// Per-member intermediate between pass 1 (resolve key material + real shard
/// content) and pass 2 (pad to the shared tiers computed across all members)
/// in `ContactManager.encryptGroupBundle`.
private struct PendingGroupRecipient {
    let publicKey: Data
    let quantumMaterial: QuantumKeyMaterial?
    let contactPrekey: Prekey?
    let pendingBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?
    let realShardOperations: [OccultaBundle.ShardOperation]
    let realCustodyManifest: [UUID]
    let realExpectedShards: [UUID]
    /// Whether `realCustodyManifest`/`realExpectedShards` were actually attempted
    /// for this member (always both together — see
    /// `RecipientPayload.shardMetadataAttempted`). `false` means this member was
    /// ineligible, or the attempt failed (e.g. a locked vault) — in either case
    /// the empty arrays above carry no meaning and must not be sent as a real
    /// "zero" signal.
    let shardMetadataAttempted: Bool
}

extension ContactManager {

    /// Encrypt a basket for all members of a group in the given layer.
    ///
    /// Each member gets an independent wrapping key (FS or fallback) and a
    /// per-recipient prekey sync batch if their stock for this sender is below
    /// the replenishment threshold. The shared ciphertext is sealed once with a
    /// random session key bound to the group UUID.
    ///
    /// Shard distribution (`shardCustodyManager`/`vaultManager`) is per-member:
    /// a member only receives real shard ops/custody manifest/expected-shards if
    /// their build is `.groupShardCapable`, they have ML-KEM material, and a
    /// prekey was available for this send (forward secrecy required — shard
    /// content must never travel on the fallback path). Every member's shard
    /// arrays — real or not — are padded to the same per-field tier computed
    /// across this send's whole membership, so a recipient's ciphertext length
    /// never reveals whether they carry real shard content (see `ShardPadding`).
    func encryptGroupBundle(
        basket: Basket,
        groupID: UUID,
        shardCustodyManager: ShardCustodyManager? = nil,
        vaultManager: VaultManager? = nil
    ) throws -> Data {
        // Pass 1 below pops each member's oldest prekey (mutating
        // contact.forwardSecrecyEncrypted in memory) before any of the fallible work
        // that follows — the per-member `buildShardOperations` call still inside pass 1,
        // and `seal`/`WireHandle.encode`/`bundle.encoded` in pass 2. If any of that
        // throws, the explicit `self.modelContext.save()` near the bottom of this
        // function is never reached, but the in-memory pop is still live on
        // `self.modelContext` — SwiftData's autosave (backgrounding, or any other
        // incidental `.save()` on this same shared context) could flush it to disk
        // regardless, silently burning a contact's forward-secrecy prekey stock for a
        // message that was never actually sent. Disabling autosave for the duration of
        // this function closes that window; only the explicit save below can persist
        // the pop, and that only runs after the send has fully succeeded.
        self.modelContext.autosaveEnabled = false
        defer { self.modelContext.autosaveEnabled = true }

        guard let grp = try self.group(withID: groupID) else { throw Errors.groupIDMissing }

        let identifierList = grp.members(atDepth: self.security.currentDepth)

        guard !identifierList.isEmpty else { throw Errors.groupHasNoMembers }

        let predicate = #Predicate<Contact.Profile> {
            identifierList.contains($0.identifier) && $0.deletionToken == nil
        }
        // A group's stored membership is independent of each contact's own
        // visibleThroughDepth — a member classified as sensitive after being added to
        // this group's list at the current depth must still be excluded here, exactly
        // as GroupDetailV3 and Group+FormV3 already filter for display. Without this,
        // a message could be encrypted for a contact the UI shows as absent from the
        // group at the current security depth.
        let members = try self.modelContext.fetch(FetchDescriptor<Contact.Profile>(predicate: predicate))
            .filter { $0.isVisible(atDepth: self.security.currentDepth) }

        guard !members.isEmpty else { throw Errors.groupHasNoMembers }

        var prekeyConsumed = false
        let cryptoOps = Manager.Crypto()

        // ── Pass 1: resolve per-member key material + real (unpadded) shard content ──
        let pending: [PendingGroupRecipient] = try members.map { contact in
            let (recipientMaterial, quantumMaterial) = try self.resolveKeyMaterial(for: contact)

            try contact.configureForwardSecrecy()

            var contactPrekey: Prekey? = nil

            if let blob = try contact.popOldestPrekeyData() {
                contactPrekey = try JSONDecoder().decode(Prekey.self, from: blob)
                prekeyConsumed = true
            }

            let pendingBatch = try contact.loadPendingBatch()

            let memberIsShardCapable = Self.resolveTargetVersion(for: contact, using: cryptoOps) == .groupShardCapable
            let canReceiveShardContent = memberIsShardCapable && quantumMaterial != nil && contactPrekey != nil

            var realOps: [OccultaBundle.ShardOperation] = []
            var realManifest: [UUID] = []
            var realExpected: [UUID] = []
            if canReceiveShardContent, let shardCustodyManager {
                realOps = try shardCustodyManager.buildShardOperations(for: contact.identifier, currentContactPublicKey: recipientMaterial)
            }

            // custodyManifest/expectedShards are attempted together, and only together —
            // never one without the other. A count of 0 is genuinely ambiguous on its
            // own (see RecipientPayload.shardMetadataAttempted): "sender attempted this
            // and found nothing" (a real, meaningful signal — loss detection, or an
            // intentional revoke-all) is indistinguishable on the wire from "sender never
            // attempted this" (ineligible member, or a locked vault) unless the two
            // fields' attempt status can never disagree with each other. Requiring
            // `vaultManager` up front for both (rather than gating expectedShards alone
            // on it, as before) and rolling both back to "not attempted" on any failure
            // (do/catch, not `try?`) is what guarantees that.
            var metadataAttempted = false
            if canReceiveShardContent, let shardCustodyManager, let vaultManager {
                do {
                    realManifest = try shardCustodyManager.buildCustodyManifest(for: contact.identifier)
                    realExpected = try shardCustodyManager.buildExpectedShards(for: contact.identifier, vaultManager: vaultManager)
                    metadataAttempted = true
                } catch {
                    // Vault locked, or any other failure — leave both empty and
                    // unattempted rather than risk a half-built pair.
                    realManifest = []
                    realExpected = []
                }
            }

            return PendingGroupRecipient(
                publicKey:              recipientMaterial,
                quantumMaterial:        quantumMaterial,
                contactPrekey:          contactPrekey,
                pendingBatch:           pendingBatch,
                realShardOperations:    realOps,
                realCustodyManifest:    realManifest,
                realExpectedShards:     realExpected,
                shardMetadataAttempted: metadataAttempted
            )
        }

        // ── Shared per-field tiers across every member in this send ──
        let opsTier      = ShardPadding.tier(for: pending.map { $0.realShardOperations.count }.max() ?? 0)
        let manifestTier = ShardPadding.tier(for: pending.map { $0.realCustodyManifest.count }.max() ?? 0)
        let expectedTier = ShardPadding.tier(for: pending.map { $0.realExpectedShards.count }.max() ?? 0)

        // ── Pass 2: pad every member — including fully-ineligible ones — to those tiers ──
        let recipients: [GroupRecipient] = pending.map { p in
            let (paddedManifest, manifestCount) = Self.paddedUUIDs(p.realCustodyManifest, to: manifestTier)
            let (paddedExpected, expectedCount) = Self.paddedUUIDs(p.realExpectedShards, to: expectedTier)
            return GroupRecipient(
                publicKey:              p.publicKey,
                quantumMaterial:        p.quantumMaterial,
                contactPrekey:          p.contactPrekey,
                pendingBatch:           p.pendingBatch,
                shardOperations:        Self.paddedShardOperations(p.realShardOperations, to: opsTier),
                custodyManifest:        paddedManifest,
                custodyManifestCount:   manifestCount,
                expectedShards:         paddedExpected,
                expectedShardsCount:    expectedCount,
                shardMetadataAttempted: p.shardMetadataAttempted
            )
        }

        let bundle = try Manager.Crypto().seal(
            message:    try WireHandle.encode(basket: basket),
            groupID:    groupID,
            recipients: recipients
        )
        let encodedBundle = try bundle.encoded(version: .v4)

        if prekeyConsumed {
            try self.modelContext.save()
        }

        return encodedBundle
    }

    /// Pad `real` with random filler UUIDs up to `tier` entries. Filler is
    /// indistinguishable from real entries to anyone without this recipient's
    /// wrapping key; the legitimate recipient uses the returned count to know
    /// how many leading entries are real.
    private static func paddedUUIDs(_ real: [UUID], to tier: Int) -> (padded: [UUID], count: Int) {
        var padded = real
        while padded.count < tier { padded.append(UUID()) }
        return (padded, real.count)
    }

    /// Pad `real` with filler `ShardOperation`s (`kind: .unsupported`, already
    /// silently ignored by `ShardCustodyManager.handleInbound`'s dispatch) up to
    /// `tier` entries. Filler carries a plausibly-sized `SignedAttribute` — real
    /// `.shard` attributes are already near-constant size (fixed label, fixed-length
    /// share, near-constant signature) — so filler and real entries aren't
    /// distinguishable by size within the array.
    private static func paddedShardOperations(
        _ real: [OccultaBundle.ShardOperation],
        to tier: Int
    ) -> [OccultaBundle.ShardOperation] {
        var padded = real
        while padded.count < tier { padded.append(Self.fillerShardOperation()) }
        return padded
    }

    private static func fillerShardOperation() -> OccultaBundle.ShardOperation {
        let filler = SignedAttribute(
            label:     "vault-shard",
            value:     Data((0..<33).map { _ in UInt8.random(in: .min ... .max) }),
            category:  .shard,
            signature: Data((0..<72).map { _ in UInt8.random(in: .min ... .max) })
        )
        return OccultaBundle.ShardOperation(kind: .unsupported, attribute: filler)
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
        #if DEBUG
        debugPrint("Opening message, using mode: \(bundle.secrecy.mode)")
        #endif

        let quantumMaterial = try self.resolveQuantumMaterial(mode: bundle.secrecy.mode, for: sender, using: cryptoOps)
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
            #if DEBUG
            debugPrint("Message successfully opened in \(bundle.secrecy.mode) mode. Pending batch cleared.")
            #endif
        } else if !sender.hasPendingBatch {
            try self.generateAndStoreFreshBatch(for: sender, using: prekeyManager)
        }

        // ── 4. Decode, update capability, store inbound batch ────────────
        var decodedPayload = try self.decodePayload(payloadData, version: bundle.version)
        #if DEBUG
        debugPrint("Contact's reported app version: \(decodedPayload.appVersion ?? "nil"), bundle wire version: \(bundle.version), maps to: \(OccultaBundle.Version.max(forAppVersion: decodedPayload.appVersion ?? ""))")
        #endif
        try self.updateMaxVersion(from: decodedPayload.appVersion, for: sender, using: cryptoOps)
        #if DEBUG
        debugPrint("Stored maxBundleVersion for contact now resolves to: \(Self.resolveTargetVersion(for: sender, using: cryptoOps))")
        #endif
        try self.storeInboundBatch(decodedPayload.prekeyBatch, for: sender)

        // Shard-protocol content requires forward secrecy. If this bundle used the
        // long-term-key fallback path, treat any shard-protocol fields as
        // untrusted/unexpected and drop them here — regardless of what the sender
        // claims — rather than relying on the sender to have gated correctly.
        if bundle.secrecy.mode == .longTermFallback || bundle.secrecy.mode == .longTermNoPQ {
            decodedPayload = OccultaBundle.SealedPayload(
                message:           decodedPayload.message,
                prekeyBatch:       decodedPayload.prekeyBatch,
                identityChallenge: decodedPayload.identityChallenge,
                appVersion:        decodedPayload.appVersion,
                senderProof:       decodedPayload.senderProof,
                groupID:           decodedPayload.groupID
            )
        }

        // ── 5. Persist ───────────────────────────────────────────────────
        try self.modelContext.save()

        #if DEBUG
        debugPrint("Saved after decrypt. Inbound prekeys now: \(sender.availableInboundPrekeyCount), sender: \(sender.givenName.decrypt()), pending batch: \(sender.hasPendingBatch)")
        #endif

        return (decodedPayload, sender.identifier)
    }
}

// MARK: - Decrypt helpers (private)

extension ContactManager {

    private func resolveSenderPublicKey(for sender: Contact.Profile, using cryptoOps: Manager.Crypto) throws -> Data {
        guard
            let keyRecord = sender.contactPublicKeys?.last(where: { $0.expiredOn == nil }),
            let decrypted = try cryptoOps.decrypt(data: keyRecord.material)
        else { throw Errors.decryptionFailed }
        return decrypted
    }

    private func resolveQuantumMaterial(
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
        #if DEBUG
        debugPrint("🔥 longTerm(fallback|NoPQ) detected — storing fresh pending batch for sender \(sender.identifier)")
        #endif
        let prekeys = try prekeyManager.generateBatch(contactID: sender.identifier)
        let prekeysSuitableForTransport = prekeys.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(), prekeys: prekeysSuitableForTransport)
        try sender.store(batch: batch)
        #if DEBUG
        debugPrint("Storage complete. Ready to send new prekey batch in the next message.")
        #endif
    }

    private func decodePayload(_ data: Data, version: OccultaBundle.Version) throws -> OccultaBundle.SealedPayload {
        if version == .v4 {
            return try WireHandle.decode(payload: data)
        } else {
            return try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: data)
        }
    }

    /// Records the sender's capability tier as a **high-water mark** — it may rise, never fall.
    ///
    /// `appVersion` comes from the sealed payload, so it is authenticated only by the session
    /// key. In FS mode that key carries no sender identity (finding #8,
    /// SecurityReview2026-07-24), so whoever can build an FS bundle can also choose this value.
    /// Overwriting unconditionally — as this did until 2026-08-12 — made the
    /// `senderEphemeralSignature` gate in `openGroup` bypassable in two messages: claim an old
    /// `appVersion` in a signed bundle to lower the recorded tier, then send an unsigned one
    /// and watch the gate skip. Capability reflects an installed build and only moves upward in
    /// practice, so refusing to lower it costs nothing real and closes that path.
    ///
    /// A **stranded** marker (present, unreadable) is treated as the top tier rather than as
    /// unknown. `resolveTargetVersion` would report `.v3fs` for it, which any claim clears —
    /// letting an attacker convert "we cannot prove they are incapable" into a recorded "they
    /// are incapable" and reopen the gate. The cost is that a genuinely pre-1.10.0 contact
    /// whose marker was stranded stays gated until they update; that is the same interop trade
    /// the fail-closed check in `openGroup` makes, kept consistent here so the two cannot
    /// disagree.
    /// Not `private` so the high-water-mark rule can be unit tested directly; it is the
    /// security-relevant half of this function and asserting it through a full bundle round
    /// trip would test the transport more than the rule.
    func updateMaxVersion(from appVersion: String?, for sender: Contact.Profile, using cryptoOps: Manager.Crypto) throws {
        guard let appVersion else { return }
        let maxVersion = OccultaBundle.Version.max(forAppVersion: appVersion)
        guard let byte = maxVersion.wireByte else { return }

        let stranded = sender.maxBundleVersion != nil
            && !Self.hasReadableBundleVersion(sender, using: cryptoOps)
        let floor: OccultaBundle.Version = stranded
            ? .senderSignatureCapable
            : Self.resolveTargetVersion(for: sender, using: cryptoOps)

        guard maxVersion.isAtLeast(floor) else { return }

        sender.maxBundleVersion = try cryptoOps.encrypt(data: Data([byte]))
    }

    private func storeInboundBatch(_ batch: OccultaBundle.SealedPayload.PrekeySyncBatch?, for sender: Contact.Profile) throws {
        guard let batch else { return }
        #if DEBUG
        debugPrint("Decrypting bundle containing inbound prekey sync batch...")
        #endif
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
        #if DEBUG
        debugPrint("Sender's prekeys in our storage before syncInboundPrekeys: \(sender.availableInboundPrekeyCount)")
        #endif
        try sender.syncInboundPrekeys(blobs, date: batch.generatedAt)
    }
}

// MARK: - Group bundle decryption

extension ContactManager {

    /// The single decrypt entry point for all inbound bundles with `secrecy.mode == .group`.
    ///
    /// This handles every bundle type sent by ≥ 1.9.0 contacts: basket messages, shard
    /// operations, custody manifests, and identity challenge envelopes. The caller
    /// (`buildOwnedBasket`) dispatches to this function whenever `bundle.group != nil`,
    /// then inspects `sealed` to route identity challenges, shard/custody ops, and the
    /// empty-message sentinel before returning a basket to the UI.
    ///
    /// `groupID` in the return value comes from the decrypted `SealedPayload.groupID`,
    /// not the cleartext `GroupEnvelope`. Callers use it to locate the matching Group record.
    ///
    /// `ownerID`: pass the identifier already returned by `identifyOwner(of:)` to skip
    /// the O(contacts) fingerprint re-scan inside this method.
    ///
    /// The three `recipient*` return fields are this recipient's own shard-related
    /// content, already stripped of the fixed-size tier padding `encryptGroupBundle`
    /// applies to every recipient (real ops filtered by `kind != .unsupported`;
    /// manifest/expected-shards truncated to their real-count fields) — same
    /// nil-or-populated shape as `SealedPayload`'s own shard fields, so callers can
    /// feed either into `ShardCustodyManager.handleInbound` interchangeably.
    func openGroup(bundle: OccultaBundle, ownerID: String? = nil) throws -> (
        sealed:                   OccultaBundle.SealedPayload,
        ownerID:                  String,
        groupID:                  UUID,
        recipientShardOperations: [OccultaBundle.ShardOperation]?,
        recipientCustodyManifest: [UUID]?,
        recipientExpectedShards:  [UUID]?
    ) {
        guard bundle.secrecy.mode == .group, let envelope = bundle.group else {
            throw OccultaBundle.BundleError.unsupportedMode
        }

        switch envelope.version {
        case 1:
            break
        default:
            throw GroupDecryptError.unknownEnvelopeVersion
        }

        let cryptoOps     = Manager.Crypto()
        let prekeyManager = Manager.PrekeyManager()

        // ── 1. Identify sender ──────────────────────────────────────────
        // Skip the fingerprint scan when the caller already identified the sender.
        let sender: Contact.Profile
        if let ownerID {
            guard let found = try self.fetchContact(by: ownerID) else { throw Errors.contactNotFound }
            sender = found
        } else {
            sender = try self.identifyOwner(for: bundle)
        }
        try sender.configureForwardSecrecy()

        // ── 2. Resolve sender key material ─────────────────────────────
        let senderPublicKey = try self.resolveSenderPublicKey(for: sender, using: cryptoOps)
        let quantumMaterial = try self.resolveQuantumMaterial(for: sender, using: cryptoOps)

        // ── 3. Trial-decrypt: find our slot and open it ─────────────────
        let (recipientPayload, consumable, recipientMode) = try cryptoOps.findAndOpenRecipientSlot(
            in: bundle,
            blind: envelope.blind,
            senderContactID: sender.identifier,
            senderPublicKey: senderPublicKey,
            quantumMaterial: quantumMaterial,
            prekeyManager: prekeyManager
        )

        // ── 3.5. Enforce sender-ephemeral-signature once the sender is known-capable ──
        // FS mode's session key never involves the sender's long-term identity (finding
        // #8, SecurityReview2026-07-24) — senderEphemeralSignature is the actual binding
        // for that mode, verified inside findAndOpenRecipientSlot if present. Require it
        // only once this contact has previously demonstrated (via appVersion) that their
        // build produces one; older contacts can't, so their absence is accepted as before.
        //
        // Fails closed on a stranded marker (Bug 80). `resolveTargetVersion` reports `.v3fs`
        // both when a contact has never been seen and when their recorded version was
        // stranded by a pre-1.10.2 key rotation — and `.v3fs` is not
        // `senderSignatureCapable`, so a stranded marker silently skipped this check on
        // every install that had ever activated Secure Mode. Absence still accepts (a contact
        // we have genuinely never heard from cannot be assumed capable, and rejecting would
        // break first contact); unreadable-but-present now rejects, because it means we
        // cannot establish that the sender is incapable, and this check is the only thing
        // binding an FS-mode bundle to the sender's identity.
        let isFSMode = recipientMode == .forwardSecret || recipientMode == .forwardSecretNoPQ
        if isFSMode, recipientPayload.senderEphemeralSignature == nil {
            let recorded = Self.resolveTargetVersion(for: sender, using: cryptoOps)
            let stranded = sender.maxBundleVersion != nil
                && !Self.hasReadableBundleVersion(sender, using: cryptoOps)

            guard !recorded.isAtLeast(.senderSignatureCapable), !stranded else {
                throw GroupDecryptError.missingSenderEphemeralSignature
            }
        }

        // ── 4. Prekey management ─────────────────────────────────────────
        #if DEBUG
        debugPrint("Opening group bundle, recipient mode: \(recipientMode), consumable: \(consumable != nil), sender pending batch: \(sender.hasPendingBatch)")
        #endif
        if let consumable {
            prekeyManager.consume(prekey: consumable)
            try sender.clearPendingBatch()
        } else if !sender.hasPendingBatch {
            try self.generateAndStoreFreshBatch(for: sender, using: prekeyManager)
        }

        // ── 5. Open shared ciphertext ────────────────────────────────────
        let sessionKey  = SymmetricKey(data: recipientPayload.sessionKey)
        let payloadData = try cryptoOps.openGroupCiphertext(bundle, using: sessionKey)
        let decoded     = try WireHandle.decode(payload: payloadData)

        // ── 5.5. Verify sender proof ─────────────────────────────────────
        // Confirms the cleartext senderFingerprint / fingerprintNonce routing fields
        // were not replaced after sealing. A mismatch means a group member tampered
        // with the bundle to frame a different sender.
        guard let proof = decoded.senderProof,
              HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: senderPublicKey, using: sessionKey) else {
            throw GroupDecryptError.senderProofMismatch
        }

        // ── 6. Post-processing ────────────────────────────────────────────
        #if DEBUG
        debugPrint("Contact's reported app version: \(decoded.appVersion ?? "nil"), maps to: \(OccultaBundle.Version.max(forAppVersion: decoded.appVersion ?? ""))")
        #endif
        try self.updateMaxVersion(from: decoded.appVersion, for: sender, using: cryptoOps)
        #if DEBUG
        debugPrint("Stored maxBundleVersion for contact now resolves to: \(Self.resolveTargetVersion(for: sender, using: cryptoOps))")
        debugPrint("Recipient payload prekeyBatch present: \(recipientPayload.prekeyBatch != nil), count: \(recipientPayload.prekeyBatch?.prekeys.count ?? -1)")
        #endif
        try self.storeInboundBatch(recipientPayload.prekeyBatch, for: sender)
        try self.modelContext.save()

        #if DEBUG
        debugPrint("Saved after group decrypt. Inbound prekeys now: \(sender.availableInboundPrekeyCount), sender: \(sender.givenName.decrypt()), pending batch: \(sender.hasPendingBatch)")
        #endif

        guard let groupID = decoded.groupID else { throw GroupDecryptError.missingGroupID }

        // ── 7. De-pad this recipient's shard content ──────────────────────
        // Shard-protocol content requires forward secrecy. If THIS recipient's own
        // slot used the long-term-key fallback path, treat any shard-protocol fields
        // as untrusted/unexpected and drop them here — regardless of what the sender
        // claims — rather than relying on the sender to have gated correctly.
        let isFallback = recipientMode == .longTermFallback || recipientMode == .longTermNoPQ
        let recipOps = isFallback ? [] : recipientPayload.shardOperations.filter { $0.kind != .unsupported }

        // custodyManifest/expectedShards: `custodyManifestCount == 0` is genuinely
        // ambiguous on its own — it means either "sender attempted this and found
        // nothing" (a real signal: e.g. loss detection, or an intentional revoke-all,
        // which must reach ShardCustodyManager.processInboundManifest/
        // processExpectedShards below) or "sender never attempted this at all"
        // (ineligible member, or their vault was locked at send time — no signal was
        // intended). `shardMetadataAttempted` is the explicit flag that tells the two
        // apart (see its doc comment on RecipientPayload); a fallback slot is treated
        // as not-attempted regardless of what the sender claims, same as shardOperations
        // above. Returning `nil` means "skip verification"; a real, possibly-empty
        // array means "process it" — silently converting a real empty array to `nil`
        // here would drop that signal exactly the way this fix closes.
        let metadataAttempted = !isFallback && recipientPayload.shardMetadataAttempted
        let recipManifest: [UUID]? = metadataAttempted
            ? Array(recipientPayload.custodyManifest.prefix(recipientPayload.custodyManifestCount))
            : nil
        let recipExpected: [UUID]? = metadataAttempted
            ? Array(recipientPayload.expectedShards.prefix(recipientPayload.expectedShardsCount))
            : nil

        return (
            decoded,
            sender.identifier,
            groupID,
            recipOps.isEmpty ? nil : recipOps,
            recipManifest,
            recipExpected
        )
    }
}
