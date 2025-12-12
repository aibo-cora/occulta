//
//  Passphrase+Generator.swift
//  MaverickTests
//
//  Created by Yura on 12/11/25.
//

import Testing
import Foundation

@testable import Maverick

struct PassphraseGeneratorTests {
    @Test("Create 5 word passphrase")
    func createPassphrase() throws {
        guard
            let url = Bundle.main.url(forResource: "eff_large_wordlist", withExtension: "txt"),
            let content = try? String(contentsOf: url, encoding: .utf8)
        else {
            fatalError("Could not load eff_large_wordlist.txt – make sure it's in the app bundle!")
        }
        
        let lines = content.components(separatedBy: .newlines)
        var list: [String] = []
        list.reserveCapacity(7776)
        
        for line in lines {
            let parts = line.split(separator: "\t", maxSplits: 1)
            if parts.count == 2, let _ = Int(parts[0]) {
                list.append(String(parts[1]))
            }
        }
        
        let capitalized = true
        let passphrase = Manager.PassphraseGenerator().generate(words: 5, separator: "-", capitalize: capitalized)
        
        let generatedWords = passphrase.components(separatedBy: "-")
        
        generatedWords.forEach { word in
            #expect(list.contains(capitalized ? word.lowercased() : word))
        }
        
        #expect(generatedWords.count == 5)
        
        debugPrint(passphrase)
    }
}
