//
//  Contact.swift
//  Maverick
//
//  Created by Yura on 10/25/25.
//

import Foundation
import SwiftData
import Contacts

// TODO: Explore subclassing `CNContact`

/// Local representation of a trusted contact.
@Model
final class Contact {
    // MARK: Imported contact metadata - encrypted
    
    /// Identifier assigned by the contact store.
    ///
    /// When we share our publish key, this identifier is included so that the recipient can attach it to the message which will make it easier to identify which key needs to be used to decrypt the message without choosing the contact.
    ///
    /// The recipient will store it in the `identifierFromOutside` property.
    @Attribute(.unique) var identifier: String
    
    var givenName: String
    var familyName: String
    var middleName: String
    var imageData: Data?
    var imageDataAvailable: Data?
    var thumbnailImageData: Data?
    var emailAddresses: [LabeledValue]
    var phoneNumbers: [LabeledValue]

    // MARK: Application specific metadata - encrypted
    
    /// Public key of the trusted contact.
    var contactPublicKeys: [Data?] = []
    /// Identifier to determine the owner of the public key.
    var identifierFromOutside: String?
    
    // MARK: Initializers
    
    /// Create a contact with encrypted properties for storage.
    /// - Parameters:
    ///   - identifier: <#identifier description#>
    ///   - givenName: <#givenName description#>
    ///   - familyName: <#familyName description#>
    ///   - middleName: <#middleName description#>
    ///   - imageData: <#imageData description#>
    ///   - imageDataAvailable: <#imageDataAvailable description#>
    ///   - thumbnailImageData: <#thumbnailImageData description#>
    ///   - emailAddresses: <#emailAddresses description#>
    ///   - phoneNumbers: <#phoneNumbers description#>
    init(identifier: String, givenName: String, familyName: String, middleName: String, imageData: Data?, imageDataAvailable: Data?, thumbnailImageData: Data?, emailAddresses: [CNLabeledValue<NSString>], phoneNumbers: [CNLabeledValue<CNPhoneNumber>]) {
        self.identifier = identifier
        self.givenName = givenName
        self.familyName = familyName
        self.middleName = middleName
        self.imageData = imageData
        self.imageDataAvailable = imageDataAvailable
        self.thumbnailImageData = thumbnailImageData
        self.emailAddresses = emailAddresses.map { LabeledValue(from: $0) }
        self.phoneNumbers = phoneNumbers.map { LabeledValue(from: $0) }
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
