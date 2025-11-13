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
    var imageDataAvailable: Bool
    var thumbnailImageData: Data?
    var emailAddresses: [LabeledValue]
    var phoneNumbers: [LabeledValue]

    // MARK: Application specific metadata - encrypted
    
    /// Public key of the trusted contact.
    var contactPublicKey: Data?
    /// Identifier for the private key used for this contact - key stored locally in Secure Enclave
    var privateKeyIdentifier: String = UUID().uuidString
    /// Identifier to determine the owner of the public key.
    var identifierFromOutside: String?
    
    // MARK: Initializers
    
    /// Convert from `CNContact` to our contact.
    /// - Parameter cnContact: Contact.
    init?(from cnContact: CNContact) throws {
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
