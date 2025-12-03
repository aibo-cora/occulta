//
//  ContactDraft.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//

import Foundation
import Contacts

// MARK: - Main Contact Struct

extension Contact {
    struct Draft {
        let identifier: String
        
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
        
        var birthday: Date?
        var note: String = ""
        
        var thumbnailImageData: Data?
        var imageData: Data?
        
        var phoneNumbers: [PhoneNumber] = []
        var emailAddresses: [EmailAddress] = []
        var postalAddresses: [PostalAddressEntry] = []
        var urlAddresses: [URLAddress] = []
        
        var importedAt: Date = Date()
        
        // MARK: - Initializers
        
        init(
            identifier: String,
            givenName: String = "",
            familyName: String = "",
            middleName: String = "",
            namePrefix: String = "",
            nameSuffix: String = "",
            nickname: String = "",
            organizationName: String = "",
            departmentName: String = "",
            jobTitle: String = "",
            phoneticGivenName: String = "",
            phoneticMiddleName: String = "",
            phoneticFamilyName: String = "",
            birthday: Date? = nil,
            note: String = "",
            imageData: Data? = nil,
            thumbnailImageData: Data? = nil,
            phoneNumbers: [PhoneNumber] = [],
            emailAddresses: [EmailAddress] = [],
            postalAddresses: [PostalAddressEntry] = [],
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
        
        init(from cnContact: CNContact) {
            self.identifier = cnContact.identifier
            
            self.givenName = cnContact.givenName
            self.familyName = cnContact.familyName
            self.middleName = cnContact.middleName
            self.namePrefix = cnContact.namePrefix
            self.nameSuffix = cnContact.nameSuffix
            self.nickname = cnContact.nickname
            
            self.organizationName = cnContact.organizationName
            self.departmentName = cnContact.departmentName
            self.jobTitle = cnContact.jobTitle
            
            self.phoneticGivenName = cnContact.phoneticGivenName
            self.phoneticMiddleName = cnContact.phoneticMiddleName
            self.phoneticFamilyName = cnContact.phoneticFamilyName
            
            self.birthday = cnContact.birthday?.date
            self.note = cnContact.note
            self.imageData = cnContact.imageData
            self.thumbnailImageData = cnContact.thumbnailImageData
            
            self.phoneNumbers = cnContact.phoneNumbers.map { PhoneNumber(from: $0) }
            self.emailAddresses = cnContact.emailAddresses.map { EmailAddress(from: $0) }
            self.postalAddresses = cnContact.postalAddresses.map { PostalAddressEntry(from: $0) }
            self.urlAddresses = cnContact.urlAddresses.map { URLAddress(from: $0) }
            
            self.importedAt = Date()
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

extension Contact.Draft {
    struct PhoneNumber {
        var label: String
        var value: String
        
        init(label: String = "mobile", value: String = "") {
            self.label = label
            self.value = value
        }
        
        init(from labeled: CNLabeledValue<CNPhoneNumber>) {
            let rawLabel = labeled.label ?? "_$!<Other>!$>_"
            let localizedLabel = CNLabeledValue<CNPhoneNumber>.localizedString(forLabel: rawLabel)
            self.init(label: localizedLabel, value: labeled.value.stringValue)
        }
    }

    struct EmailAddress {
        var label: String
        var value: String
        
        init(label: String = "work", value: String = "") {
            self.label = label
            self.value = value
        }
        
        init(from labeled: CNLabeledValue<NSString>) {
            let rawLabel = labeled.label ?? "_$!<Other>!$>_"
            let localizedLabel = CNLabeledValue<NSString>.localizedString(forLabel: rawLabel)
            self.init(label: localizedLabel, value: labeled.value as String)
        }
    }

    struct PostalAddressEntry {
        var label: String
        
        var street: String = ""
        var city: String = ""
        var state: String = ""
        var postalCode: String = ""
        var country: String = ""
        var isoCountryCode: String = ""
        
        init(label: String = "home",
             street: String = "",
             city: String = "",
             state: String = "",
             postalCode: String = "",
             country: String = "",
             isoCountryCode: String = "") {
            self.label = label
            self.street = street
            self.city = city
            self.state = state
            self.postalCode = postalCode
            self.country = country
            self.isoCountryCode = isoCountryCode
        }
        
        init(from labeled: CNLabeledValue<CNPostalAddress>) {
            let rawLabel = labeled.label ?? "_$!<Other>!$>_"
            let localizedLabel = CNLabeledValue<CNPostalAddress>.localizedString(forLabel: rawLabel)
            let addr = labeled.value
            
            let streetComponents = [addr.street, addr.subLocality, addr.subAdministrativeArea]
                .compactMap { $0 }
                .filter { !$0.isEmpty }
            
            self.init(
                label: localizedLabel,
                street: streetComponents.joined(separator: ", "),
                city: addr.city,
                state: addr.state,
                postalCode: addr.postalCode,
                country: addr.country,
                isoCountryCode: addr.isoCountryCode
            )
        }
    }

    struct URLAddress {
        var label: String
        var value: String
        
        init(label: String = "homepage", value: String = "") {
            self.label = label
            self.value = value
        }
        
        init(from labeled: CNLabeledValue<NSString>) {
            let rawLabel = labeled.label ?? "_$!<Other>!$>_"
            let localizedLabel = CNLabeledValue<NSString>.localizedString(forLabel: rawLabel)
            self.init(label: localizedLabel, value: labeled.value as String)
        }
    }
}
