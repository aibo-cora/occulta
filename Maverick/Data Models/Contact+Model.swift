import SwiftData
import Contacts
import Foundation

// MARK: - Main Contact Model

enum Contact { }

extension Contact {
    @Model
    final class Profile {
        var identifier: String
        
        var givenName: String = ""
        var familyName: String = ""
        var middleName: String = ""
        var namePrefix: String = ""
        var nameSuffix: String = ""
        var nickname: String = ""
        
        var organizationName: String = ""
        var departmentName: String = ""
        var jobTitle: String = ""
        
        var phoneticGivenName: String = ""
        var phoneticMiddleName: String = ""
        var phoneticFamilyName: String = ""
        
        var birthday: String?
        var note: String = ""
        
        var thumbnailImageData: Data?
        var imageData: Data?
        
        // Relationships
        @Relationship(deleteRule: .cascade)
        var phoneNumbers: [PhoneNumber] = []
        
        @Relationship(deleteRule: .cascade)
        var emailAddresses: [EmailAddress] = []
        
        @Relationship(deleteRule: .cascade)
        var postalAddresses: [PostalAddress] = []
        
        @Relationship(deleteRule: .cascade)
        var urlAddresses: [URLAddress] = []
        
        var importedAt: Date = Date()
        
        // MARK: Application specific metadata - encrypted
        
        @Relationship(deleteRule: .cascade)
        /// Public key of the trusted contact.
        var contactPublicKeys: [Key] = []
        /// Identifier to determine the owner of the public key.
        var identifierFromOutside: String?
        /// Identifier of the user that originally acquired this contact's public key.
        var identifierAcquirer: String?
        
        // MARK: - Full Designated Initializer
        
        init(
            identifier: String,
            givenName: String,
            familyName: String,
            middleName: String,
            namePrefix: String = "",
            nameSuffix: String = "",
            nickname: String,
            organizationName: String,
            departmentName: String,
            jobTitle: String,
            phoneticGivenName: String = "",
            phoneticMiddleName: String = "",
            phoneticFamilyName: String = "",
            birthday: String? = nil,
            note: String = "",
            imageData: Data? = nil,
            thumbnailImageData: Data? = nil,
            phoneNumbers: [PhoneNumber] = [],
            emailAddresses: [EmailAddress] = [],
            postalAddresses: [PostalAddress] = [],
            urlAddresses: [URLAddress] = [],
            importedAt: Date = Date()
        ) {
            self.identifier = identifier
            self.givenName = givenName
            self.familyName = familyName
            self.middleName = middleName
            self.namePrefix = namePrefix
            self.nameSuffix = nameSuffix
            self.nickname = nickname
            self.organizationName = organizationName
            self.departmentName = departmentName
            self.jobTitle = jobTitle
            self.phoneticGivenName = phoneticGivenName
            self.phoneticMiddleName = phoneticMiddleName
            self.phoneticFamilyName = phoneticFamilyName
            self.birthday = birthday
            self.note = note
            self.imageData = imageData
            self.thumbnailImageData = thumbnailImageData
            self.phoneNumbers = phoneNumbers
            self.emailAddresses = emailAddresses
            self.postalAddresses = postalAddresses
            self.urlAddresses = urlAddresses
            self.importedAt = importedAt
        }
        
        var fullName: String {
            PersonNameComponents(
                namePrefix: self.namePrefix,
                givenName: self.givenName,
                middleName: self.middleName,
                familyName: self.familyName,
                nameSuffix: self.nameSuffix,
                nickname: self.nickname
            ).formatted(.name(style: .long))
        }
    }
}

extension Contact.Profile {
    @Model
    final class PhoneNumber {
        var label: String
        var value: String // e.g., "+1 (555) 123-4567"
        
        init(label: String = "mobile", value: String = "") {
            self.label = label
            self.value = value
        }
        
        convenience init(from labeled: CNLabeledValue<CNPhoneNumber>) {
            let label = labeled.label ?? "other"
            let cleanedLabel = CNLabeledValue<CNPhoneNumber>.localizedString(forLabel: label)
            self.init(label: cleanedLabel, value: labeled.value.stringValue)
        }
    }

    @Model
    final class EmailAddress {
        var label: String
        var value: String
        
        init(label: String = "work", value: String = "") {
            self.label = label
            self.value = value
        }
        
        convenience init(from labeled: CNLabeledValue<NSString>) {
            let label = labeled.label ?? "other"
            let cleanedLabel = CNLabeledValue<NSString>.localizedString(forLabel: label)
            self.init(label: cleanedLabel, value: labeled.value as String)
        }
    }

    @Model
    final class PostalAddress {
        var label: String
        
        var street: String = ""
        var city: String = ""
        var state: String = ""
        var postalCode: String = ""
        var country: String = ""
        var isoCountryCode: String = ""
        
        init(label: String = "home", street: String, city: String, state: String, postalCode: String, country: String, isoCountryCode: String) {
            self.label = label
        }
        
        convenience init(from labeled: CNLabeledValue<CNMutablePostalAddress>) {
            let label = labeled.label ?? "other"
            let address = labeled.value
            
            let street = [address.street, address.subLocality, address.subAdministrativeArea]
                .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
            let city = address.city
            let state = address.state
            let postalCode = address.postalCode
            let country = address.country
            let isoCountryCode = address.isoCountryCode
            
            self.init(label: label, street: street, city: city, state: state, postalCode: postalCode, country: country, isoCountryCode: isoCountryCode)
        }
    }

    @Model
    final class URLAddress {
        var label: String
        var value: String
        
        init(label: String = "homepage", value: String = "") {
            self.label = label
            self.value = value
        }
        
        convenience init(from labeled: CNLabeledValue<NSString>) {
            let label = labeled.label ?? "other"
            let cleanedLabel = CNLabeledValue<NSString>.localizedString(forLabel: label)
            
            self.init(label: cleanedLabel, value: labeled.value as String)
        }
    }
}

extension Contact.Profile {
    @Model
    class Key {
        var material: Data?
        var acquiredAt: Data?
        /// Encrypted hash of public key belonging to the user who acquired it through exchange.
        var owner: Data
        
        /// List of possible operations.
        var scopes: [Data] {
            []
        }
        
        var expiredOn: Data?
        
        init(material: Data? = nil, owner: Data, date: Data) {
            self.material = material
            self.owner = owner
            self.acquiredAt = date
        }
    }
}

enum Scopes: Codable {
    /// Key can encrypt and decrypt.
    case crypto
    /// Key was acquired through `Nearby Interaction` and we have full confidence who it belongs to.
    case sign
    case none
}
