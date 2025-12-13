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
        func export(data: Data) throws -> URL {
            guard
                let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            else {
                throw Errors.documentsDirectoryCouldNotBeAccessed
            }
            
            let filename = "export.\(UUID().uuidString).maverick"
            let fileURL = documentsURL.appendingPathComponent(filename)
            
            debugPrint("Writing file...")
            
            try data.write(to: fileURL)
            
            debugPrint("Finished writing file", separator: "")
            
            let contents = try Data(contentsOf: fileURL)
            
            debugPrint(contents)
            
            return fileURL
        }
        
        func `import`(data: Data) throws {
            
        }
        
        enum Errors: Error {
            case dataCouldNotBeSaved
            case documentsDirectoryCouldNotBeAccessed
        }
    }
}
