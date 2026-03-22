//
//  Contact+Tests.swift
//  OccultaTests
//
//  Created by Yura on 11/22/25.
//

import Testing
@testable import Occulta
import Foundation
import CryptoKit
import Contacts

@MainActor
struct ContactTests {
    let cryptoOps: CryptoProtocol = Manager.Crypto()
    
    @Test("Contact creation")
    func createContact() throws {
        let identifier = UUID().uuidString
        let givenName = "John"
        let familyName = "Snow"
        let middleName: String = ""
        let imageData: Data = Data(repeating: 0x05, count: 100)
        let emailAddresses: [CNLabeledValue<NSString>] = .init(repeating: .init(label: "work", value: "john@snow.com") as CNLabeledValue<NSString>, count: 1)
        let phoneNumbers: [CNLabeledValue<CNPhoneNumber>] = .init(repeating: .init(label: "work", value: CNPhoneNumber(stringValue: "+380501234567")) as CNLabeledValue<CNPhoneNumber>, count: 1)
        
        let encryptedIdentifier = try self.cryptoOps.encrypt(data: identifier.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedGivenName = try self.cryptoOps.encrypt(data: givenName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedFamilyName = try self.cryptoOps.encrypt(data: familyName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedMiddleName = try self.cryptoOps.encrypt(data: middleName.data(using: .utf8))?.base64EncodedString() ?? ""
        let encryptedImageData = try self.cryptoOps.encrypt(data: imageData)?.base64EncodedString() ?? ""
        
        var encryptedEmailAddresses: [CNLabeledValue<NSString>] = []
        
        emailAddresses.forEach { email in
            do {
                let label = try self.cryptoOps.encrypt(data: email.label?.data(using: .utf8))?.base64EncodedString() ?? ""
                let value = try self.cryptoOps.encrypt(data: String(email.value).data(using: .utf8))?.base64EncodedString() ?? ""
                
                encryptedEmailAddresses.append(CNLabeledValue(label: label, value: value as NSString))
            } catch {
                
            }
        }
        
        var encryptedPhoneNumbers: [CNLabeledValue<CNPhoneNumber>] = []
        
        phoneNumbers.forEach { phoneNumber in
            do {
                let label = try self.cryptoOps.encrypt(data: phoneNumber.label?.data(using: .utf8))?.base64EncodedString() ?? ""
                let value = try self.cryptoOps.encrypt(data: phoneNumber.value.stringValue.data(using: .utf8))?.base64EncodedString() ?? ""
                
                encryptedPhoneNumbers.append(CNLabeledValue(label: label, value: CNPhoneNumber(stringValue: value)))
            } catch {
                
            }
        }
        
        #expect(encryptedIdentifier.isEmpty == false)
        #expect(encryptedGivenName.isEmpty == false)
        #expect(encryptedFamilyName.isEmpty == false)
        #expect(encryptedMiddleName.isEmpty == false)
        #expect(encryptedImageData.isEmpty == false)
        #expect(encryptedEmailAddresses.isEmpty == false)
        #expect(encryptedPhoneNumbers.isEmpty == false)
        
        let decryptedIdentifier = try self.cryptoOps.decrypt(data: Data(base64Encoded: encryptedIdentifier))
        
        #expect(decryptedIdentifier?.isEmpty == false)
        #expect(String(data: decryptedIdentifier ?? Data(), encoding: .utf8) == identifier)
    }
    
    @Test("Store Contact in the local database")
    func storeContact() async throws {
        
    }
}
