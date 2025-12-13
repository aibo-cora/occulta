//
//  Export.swift
//  Maverick
//
//  Created by Yura on 12/13/25.
//

import Foundation

extension Contact {
    struct Export: Codable {
        let payload: Data
        let type: `Type`
        
        enum `Type`: Codable {
            case contacts
        }
        
        init?(payload: Data, type: `Type`) {
            guard
                payload.isEmpty == false
            else {
                return nil
            }
            
            self.payload = payload
            self.type = type
        }
    }
}
