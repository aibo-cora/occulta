//
//  Import.swift
//  Maverick
//
//  Created by Yura on 12/15/25.
//

import Foundation

extension Contact {
    struct Import: Identifiable {
        let id: UUID = .init()
        /// Encrypted file content
        let content: Data
    }
}
