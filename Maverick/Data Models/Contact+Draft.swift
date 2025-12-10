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
    struct Draft: Codable {
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
        
        var birthday: String?
        var note: String = ""
        
        var thumbnailImageData: Data?
        var imageData: Data?
        
        var phoneNumbers: [PhoneNumber] = []
        var emailAddresses: [EmailAddress] = []
        var postalAddresses: [PostalAddress] = []
        var urlAddresses: [URLAddress] = []
        
        var importedAt: Date = Date()
        
        enum Status: Codable {
            case encrypted, decrypted
        }
        
        let status: Status
        
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
            birthday: String? = nil,
            note: String = "",
            imageData: Data? = nil,
            thumbnailImageData: Data? = nil,
            phoneNumbers: [PhoneNumber] = [],
            emailAddresses: [EmailAddress] = [],
            postalAddresses: [PostalAddress] = [],
            urlAddresses: [URLAddress] = [],
            importedAt: Date = Date(),
            status: Status = .decrypted
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
            self.status = status
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
    struct PhoneNumber: Identifiable, Codable {
        var id: UUID = UUID()
        var label: String
        var value: String
        
        init(label: String = PhoneType.mobile.rawValue, value: String = "") {
            self.label = label
            self.value = value
        }
        
        init(from labeled: CNLabeledValue<CNPhoneNumber>) {
            let rawLabel = labeled.label ?? PhoneType.other.rawValue
            let localizedLabel = CNLabeledValue<CNPhoneNumber>.localizedString(forLabel: rawLabel)
            
            self.init(label: localizedLabel, value: labeled.value.stringValue)
        }
        
        enum PhoneType: String, CaseIterable, Codable {
            case mobile = "Mobile"
            case home = "Home"
            case work = "Work"
            case other = "Other"
            
            var systemImage: String {
                switch self {
                case .mobile:
                    return "phone.fill"
                case .home:
                    return "house.fill"
                case .work:
                    return "building.2.fill"
                case .other:
                    return "phone"
                }
            }
        }
        
        var type: PhoneType = .mobile
    }

    struct EmailAddress: Identifiable, Codable {
        var id: UUID = UUID()
        var label: String
        var value: String
        
        enum EmailType: String, CaseIterable, Codable {
            case personal = "Personal"
            case work = "Work"
            case school = "School"
            case other = "Other"
            
            var systemImage: String {
                switch self {
                case .personal:
                    return "person.fill"
                case .work:
                    return "briefcase.fill"
                case .school:
                    return "graduationcap.fill"
                case .other:
                    return "envelope"
                }
            }
        }
        
        var type: EmailType = .personal
        
        init(label: String = EmailType.personal.rawValue, value: String = "") {
            self.label = label
            self.value = value
        }
        
        init(from labeled: CNLabeledValue<NSString>) {
            let rawLabel = labeled.label ?? EmailType.other.rawValue
            let localizedLabel = CNLabeledValue<NSString>.localizedString(forLabel: rawLabel)
            
            self.init(label: localizedLabel, value: labeled.value as String)
        }
    }

    struct PostalAddress: Identifiable, Codable {
        var id: UUID = UUID()
        var label: String
        
        var street: String = ""
        var city: String = ""
        var state: String = ""
        var postalCode: String = ""
        var country: Country = .init(code: "MD")
        
        enum AddressType: String, CaseIterable, Codable {
            case home = "Home"
            case work = "Work"
            case billing = "Billing"
            case shipping = "Shipping"
            case other = "Other"
            
            var systemImage: String {
                switch self {
                case .home:
                    return "house.fill"
                case .work:
                    return "building.2.fill"
                case .billing:
                    return "creditcard.fill"
                case .shipping:
                    return "shippingbox.fill"
                case .other:
                    return "mappin.and.ellipse"
                }
            }
        }
        
        var type: AddressType = .home
        
        init(label: String = "home",
             street: String = "",
             city: String = "",
             state: String = "",
             postalCode: String = "",
             country: Country = .init(code: "MD")) {
            self.label = label
            self.street = street
            self.city = city
            self.state = state
            self.postalCode = postalCode
            self.country = country
        }
        
        init(from labeled: CNLabeledValue<CNPostalAddress>) {
            let rawLabel = labeled.label ?? AddressType.other.rawValue
            let localizedLabel = CNLabeledValue<CNPostalAddress>.localizedString(forLabel: rawLabel)
            let address = labeled.value
            
            let streetComponents = [address.street, address.subLocality, address.subAdministrativeArea]
                .compactMap { $0 }
                .filter { !$0.isEmpty }
            let country = Country(code: address.postalCode)
            
            self.init(
                label: localizedLabel,
                street: streetComponents.joined(separator: ", "),
                city: address.city,
                state: address.state,
                postalCode: address.postalCode,
                country: country
            )
        }
        
        struct Country: Identifiable, Hashable, Codable {
            let code: String           // "US", "FR", etc.
            var name: String           // Localized name
            var flag: String           // Computed flag emoji
            
            var id: String { self.code }
            
            init(code: String) {
                self.code = code
                self.name = Locale.current.localizedString(forRegionCode: code) ?? ""
                self.flag = Country.flagEmoji(from: code)
            }
            
            static func flagEmoji(from countryCode: String) -> String {
                countryCode
                    .unicodeScalars
                    .map({ 127397 + $0.value })
                    .compactMap(UnicodeScalar.init)
                    .map(String.init)
                    .joined()
            }
            
            static var all: [Country] {
                let codes = Locale.Region.isoRegions
                
                return codes
                    .compactMap { Country(code: $0.identifier) }
                    .sorted {
                        $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedDescending
                    }
            }
        }
    }

    struct URLAddress: Identifiable, Codable {
        var id = UUID()
        
        var label: String
        var value: String
        
        enum WebsiteType: String, CaseIterable, Codable {
            case website = "Website"
            case linkedin = "LinkedIn"
            case github = "GitHub"
            case twitter = "Twitter / X"
            case instagram = "Instagram"
            case facebook = "Facebook"
            case youtube = "YouTube"
            case portfolio = "Portfolio"
            case blog = "Blog"
            case other = "Other Link"
            
            var systemImage: String {
                switch self {
                case .website:
                    return "globe"
                case .linkedin:
                    return "link"
                case .github:
                    return "terminal"
                case .twitter:
                    return "bird"
                case .instagram:
                    return "camera"
                case .facebook:
                    return "f.square"
                case .youtube:
                    return "play.rectangle"
                case .portfolio:
                    return "briefcase.fill"
                case .blog:
                    return "pencil"
                case .other:
                    return "link"
                }
            }
            
            var placeholder: String {
                switch self {
                case .website:
                    return "https://example.com"
                case .linkedin:
                    return "https://linkedin.com/in/yourname"
                case .github:
                    return "https://github.com/yourname"
                case .twitter:
                    return "https://x.com/yourname"
                case .instagram:
                    return "https://instagram.com/yourname"
                case .facebook:
                    return "https://facebook.com/yourname"
                case .youtube:
                    return "https://youtube.com/@yourname"
                case .portfolio:
                    return "https://yourportfolio.com"
                case .blog:
                    return "https://yourblog.com"
                case .other:
                    return "https://"
                }
            }
        }
        
        init(label: String = WebsiteType.website.rawValue, value: String = "") {
            self.label = label
            self.value = value
        }
        
        init(from labeled: CNLabeledValue<NSString>) {
            let rawLabel = labeled.label ?? WebsiteType.other.rawValue
            let localizedLabel = CNLabeledValue<NSString>.localizedString(forLabel: rawLabel)
            
            self.init(label: localizedLabel, value: labeled.value as String)
        }
        
        var type: WebsiteType = .website
    }
}
