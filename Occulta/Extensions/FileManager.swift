//
//  FileManager.swift
//  Occulta
//
//  Created by Yura on 3/7/26.
//

import Foundation

extension FileManager {
    /// Deletes ALL contents of the app's temporary directory (but keeps the folder itself)
    func clearTemporaryDirectory() {
        Task.detached {
            let tempURL = self.temporaryDirectory
            
            let contents = try self.contentsOfDirectory(at: tempURL, includingPropertiesForKeys: nil, options: .skipsHiddenFiles)
            
            for file in contents {
                try self.removeItem(at: file)
            }
        }
    }
}
