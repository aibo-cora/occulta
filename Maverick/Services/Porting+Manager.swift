//
//  Porting+Manager.swift
//  Maverick
//
//  Created by Yura on 12/9/25.
//

import Foundation

protocol Portable {
    func export(data: Data) throws
    func `import`(data: Data) throws
}

extension Manager {
    @Observable
    class Porter {
        var startImport = false
        var startExport = false
        
        func export(data: Data) throws {
            
        }
        
        func `import`(data: Data) throws {
            
        }
    }
}
