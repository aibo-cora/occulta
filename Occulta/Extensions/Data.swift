//
//  Data.swift
//  Occulta
//
//  Created by Yura on 12/10/25.
//

import Foundation
import CryptoKit

extension Data {
    var sha256: Data {
        Data(self.withUnsafeBytes { Data(CryptoKit.SHA256.hash(data: $0)) })
    }

    nonisolated func writeProtected(to url: URL) throws {
        var url = url
        
        try self.write(to: url, options: .completeFileProtection)
        
        var resourceValues = URLResourceValues()
        
        resourceValues.isExcludedFromBackup = true
        try? url.setResourceValues(resourceValues)
    }
}
