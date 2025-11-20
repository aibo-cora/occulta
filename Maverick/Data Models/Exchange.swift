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
    let identity: Data?
    
    init(id: String, token: Data, version: Version, identity: Data? = nil) {
        self.id = id
        self.token = token
        self.version = version
        self.identity = identity
    }
    
    enum Version: Int8, Codable {
        case v1 = 1
    }
}
