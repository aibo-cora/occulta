//
//  Exchange.swift
//  Maverick
//
//  Created by Yura on 11/18/25.
//

import Foundation
import NearbyInteraction

struct Exchange: Codable {
    let id: String
    let token: Data
    let version: Version
    
    enum Version: Int8, Codable {
        case v1 = 1
    }
}
