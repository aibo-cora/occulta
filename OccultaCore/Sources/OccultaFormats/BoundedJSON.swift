//
//  BoundedJSON.swift
//  OccultaFormats
//
//  `JSONDecoder` for bytes that came from outside the device.
//
//  Foundation's JSON scanner allows 512 levels of nesting and is meant to throw past that, but it traps on a
//  document that is exactly 513 `[` and nothing else (observed on macOS 26 and the iOS 26.2 Simulator runtime,
//  `JSONScanner.scanArray()`, `EXC_BREAKPOINT`). A trap is not a throw: no `try?` and no `catch` sees it, and the
//  process ends. 513 bytes in a `.occ` file or in a nearby phone's message were enough (`bugs.md` Bug 189).
//
//  Nothing Occulta writes nests more than a handful of levels. This counts the nesting first, which is a single
//  pass over the bytes, and refuses a document past `maxDepth` as it refuses any other malformed one, with a
//  `DecodingError`. A document within the limit is handed to `JSONDecoder` unchanged, so what decodes is what
//  decoded before.
//

import Foundation

public enum BoundedJSON {

    /// Deepest nesting accepted. The most any Occulta encoding reaches is under ten.
    public static let maxDepth = 64

    /// `JSONDecoder().decode(type, from: data)`, after refusing a document nested deeper than `maxDepth`.
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard Self.nesting(of: data) <= Self.maxDepth else {
            throw DecodingError.dataCorrupted(DecodingError.Context(
                codingPath: [], debugDescription: "The JSON nests more than \(Self.maxDepth) levels deep."
            ))
        }
        return try JSONDecoder().decode(type, from: data)
    }

    /// The deepest level of `[` and `{` in `data`, outside strings. Stops counting once past `maxDepth`: the answer is
    /// then "too deep" and the rest of the document doesn't matter.
    static func nesting(of data: Data) -> Int {
        data.withUnsafeBytes { bytes in
            var depth = 0
            var deepest = 0
            var inString = false
            var escaped = false
            for byte in bytes {
                if inString {
                    if escaped { escaped = false } else if byte == 0x5C { escaped = true } else if byte == 0x22 { inString = false }
                    continue
                }
                switch byte {
                case 0x22:
                    inString = true
                case 0x5B, 0x7B:
                    depth += 1
                    deepest = max(deepest, depth)
                    if deepest > BoundedJSON.maxDepth { return deepest }
                case 0x5D, 0x7D:
                    depth = max(0, depth - 1)
                default:
                    break
                }
            }
            return deepest
        }
    }
}
