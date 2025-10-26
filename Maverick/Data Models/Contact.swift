//
//  Contact.swift
//  Maverick
//
//  Created by Yura on 10/25/25.
//

import Foundation
import SwiftData
import Contacts

/// Local representation of a trusted contact.
@Model
final class Contact {
    // MARK: Imported contact metadata - encrypted
    
    @Attribute(.unique) var identifier: String
    
    var givenName: String
    var familyName: String
    var middleName: String
    var imageData: Data?
    var imageDataAvailable: Bool
    var thumbnailImageData: Data?
    var emailAddresses: [LabeledValue]
    var phoneNumbers: [LabeledValue]

    // MARK: Application specific metadata - encrypted
    
    /// Public key of the trusted contact.
    var publicKey: Data?
    
    init(
        identifier: String,
        givenName: String = "",
        familyName: String = "",
        middleName: String = "",
        imageData: Data? = nil,
        imageDataAvailable: Bool = false,
        thumbnailImageData: Data? = nil,
        emailAddresses: [LabeledValue] = [],
        phoneNumbers: [LabeledValue] = []
    ) {
        self.identifier = identifier
        self.givenName = givenName
        self.familyName = familyName
        self.middleName = middleName
        self.imageData = imageData
        self.imageDataAvailable = imageDataAvailable
        self.thumbnailImageData = thumbnailImageData
        self.emailAddresses = emailAddresses
        self.phoneNumbers = phoneNumbers
    }
    
    /// Convert from `CNContact` to our contact.
    /// - Parameter cnContact: Contact.
    init(from cnContact: CNContact) {
        self.identifier = cnContact.identifier
        self.givenName = cnContact.givenName
        self.familyName = cnContact.familyName
        self.middleName = cnContact.middleName
        self.imageData = cnContact.imageData
        self.imageDataAvailable = cnContact.imageDataAvailable
        self.thumbnailImageData = cnContact.thumbnailImageData
        self.emailAddresses = cnContact.emailAddresses.map { LabeledValue(from: $0) }
        self.phoneNumbers = cnContact.phoneNumbers.map { LabeledValue(from: $0) }
    }
}

@Model
class LabeledValue {
    var label: String?
    var value: String
    
    init(label: String?, value: String) {
        self.label = label
        self.value = value
    }
    
    init(from cnLabeledValue: CNLabeledValue<NSString>) {
        self.label = cnLabeledValue.label
        self.value = cnLabeledValue.value as String
    }
    
    init(from cnLabeledValue: CNLabeledValue<CNPhoneNumber>) {
        self.label = cnLabeledValue.label
        self.value = cnLabeledValue.value.stringValue
    }
}
