//
//  Features.swift
//  Maverick
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
}
