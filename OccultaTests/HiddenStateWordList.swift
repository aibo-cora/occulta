//
//  HiddenStateWordList.swift
//  OccultaTests
//
//  The words text shown at every depth must not contain: it is compiled into the binary and read on an
//  unlocked phone, so it must not name hidden state. Shared by `WhatsNewTests` and `TrustScenarioCopyTests`
//  so the two can't drift.
//
//  Tripwire, not a guarantee: it catches the obvious names and nothing subtler. The copy needs a person's
//  review too.
//

import Foundation

enum HiddenStateWordList {
    static let forbidden = [
        "secure mode", "duress", "depth", "decoy", "hidden", "coerc",
        "trustee", "shard", "panic", "plausible", "deniab"
    ]

    /// The forbidden words `text` contains.
    static func violations(in text: String) -> [String] {
        let lowered = text.lowercased()
        return self.forbidden.filter { lowered.contains($0) }
    }
}
