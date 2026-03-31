//
//  Features.swift
//  Occulta
//
//  Created by Yura on 12/24/25.
//

import Foundation

struct FeatureFlags {
    private static let flags: [String: Bool] = {
        guard
            let path = Bundle.main.path(forResource: "features", ofType: "plist"),
            let dict = NSDictionary(contentsOfFile: path) as? [String: Bool]
        else {
            print("Warning: features.plist not found or invalid")
            
            return [:]
        }
        
        return dict
    }()
    
    static func isEnabled(_ feature: Feature) -> Bool {
        return self.flags[feature.rawValue] ?? false
    }
}

enum Feature: String {
    case signature
    /// I don't feel like using a passphrase to move contacts to a new phone is very secure. There are a lot of ways to attack, including social engineering.
    case usePassphraseToExportContacts
    /// Option to sync between user devices.
    case allowSynchingBetweenDevices
    /// Advanced messaging with different content types in a single message
    case useComposableMessage
    /// Make it more convenient for users to share messages with multiple contacts.
    ///
    /// Instead of build messages from scratch for each contact, we are going to include an array of capsules holding session key that was encrypted with the shared key of each contact.
    case useMultipleRecipientMessageFormat
}
