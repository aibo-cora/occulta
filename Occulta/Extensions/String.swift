//
//  String.swift
//  Occulta
//
//  Created by Yura on 3/6/26.
//

import Foundation
import SwiftUI

extension String {
    func withDetectedLinks() -> AttributedString {
        var attributed = AttributedString(self)

        let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
        let range = NSRange(self.startIndex..., in: self)
        let matches = detector?.matches(in: self, range: range) ?? []

        for match in matches {
            guard let range = Range(match.range, in: self),
                  let url = match.url else { continue }

            if let attributedRange = Range(range, in: attributed) {
                attributed[attributedRange].link = url
                attributed[attributedRange].foregroundColor = .blue
                attributed[attributedRange].underlineStyle = .single
            }
        }
        
        return attributed
    }
}
