//
//  Passphrase+Manager.swift
//  Maverick
//
//  Created by Yura on 12/11/25.
//

import Foundation
import CryptoKit

extension Manager {
    @Observable
    class PassphraseGenerator {
        private let wordlist: [String]
            
        init() {
            guard
                let url = Bundle.main.url(forResource: "eff_large_wordlist", withExtension: "txt"),
                let content = try? String(contentsOf: url, encoding: .utf8)
            else {
                fatalError("Could not load eff_large_wordlist.txt – make sure it's in the app bundle!")
            }
            
            let lines = content.components(separatedBy: .newlines)
            var words: [String] = []
            words.reserveCapacity(7776)
            
            for line in lines {
                let parts = line.split(separator: "\t", maxSplits: 1)
                if parts.count == 2, let _ = Int(parts[0]) {
                    words.append(String(parts[1]))
                }
            }
            
            self.wordlist = words
            
            assert(words.count == 7776, "EFF wordlist should have exactly 7776 words")
        }
        
        /// Generates a 5-word passphrase using cryptographically secure randomness
        /// - Parameters:
        ///   - words: <#words description#>
        ///   - separator: <#separator description#>
        ///   - capitalize: <#capitalize description#>
        ///   - sharedKey: <#sharedKey description#>
        /// - Returns: <#description#>
        func generate(words: Int = 5, separator: String = "-", capitalize: Bool = false, sharedKey: Data? = nil) -> String {
            var result: [String] = []
            result.reserveCapacity(words)
            
            let data: Data
            
            if let sharedKey {
                guard
                    sharedKey.count == 32
                else {
                    fatalError("Shared key must be exactly 32 bytes long")
                }
                
                data = sharedKey
            } else {
                data = Data.randomBytes(32)
            }
            
            for _ in 0..<words {
                let randomIndex = Int(CryptoKit.SHA256.hash(data: data).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian } % 7776)
                
                var word = self.wordlist[randomIndex]
                
                if capitalize {
                    word = word.capitalized
                }
                result.append(word)
            }
            
            return result.joined(separator: separator)
        }
    }
}

extension Data {
    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        
        if status == errSecSuccess {
            return Data(bytes)
        }
        return Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }
}
