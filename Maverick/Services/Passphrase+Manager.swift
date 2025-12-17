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
            
            let baseData: Data
            
            if let sharedKey = sharedKey {
                guard sharedKey.count == 32 else {
                    fatalError("Shared key must be exactly 32 bytes long")
                }
                baseData = sharedKey
            } else {
                baseData = Data.randomBytes(32)  // Or use a secure random source
            }
            
            // Sequentially derive "random" data for each word using HMAC-SHA256 as a PRNG
            var counter: UInt32 = 0
            
            for _ in 0..<words {
                // Use counter to make each derivation unique
                let counterData = withUnsafeBytes(of: counter.littleEndian) { Data($0) }
                let input = counterData + baseData  // counter || sharedKey
                
                let hash = HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: baseData))
                let hashData = Data(hash)
                
                // Take first 4 bytes as UInt32, reduce mod 7776
                let randomValue = hashData.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                let randomIndex = Int(randomValue % 7776)
                
                var word = self.wordlist[randomIndex]
                
                if capitalize {
                    word = word.capitalized
                }
                result.append(word)
                
                counter += 1
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
