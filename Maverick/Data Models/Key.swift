//
//  Key.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//

import Foundation
import SwiftData

@Model
class Key {
    var material: Data?
    
    init(material: Data? = nil) {
        self.material = material
    }
}
