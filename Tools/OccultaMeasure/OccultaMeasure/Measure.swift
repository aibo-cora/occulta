//
//  Measure.swift
//  OccultaMeasure
//
//  Timing helpers shared by every measurement: one clock, one way to summarise a set of passes.
//

import Foundation

/// Milliseconds `work` takes to run.
func timed(_ work: () throws -> Void) rethrows -> Double {
    let (seconds, attoseconds) = try ContinuousClock().measure(work).components
    return Double(seconds) * 1_000 + Double(attoseconds) / 1e15
}

/// The passes of one measurement, in milliseconds.
struct Samples {
    private var values: [Double] = []

    var first: Double { self.values[0] }

    var median: Double {
        let sorted = self.values.sorted()
        let middle = sorted.count / 2
        return sorted.count % 2 == 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
    }

    var summary: String {
        let sorted = self.values.sorted()
        // Under a millisecond two decimals hide the difference between one pass and the next.
        let format = self.median < 1 ? "median %.3f ms (min %.3f, max %.3f, n = %d)"
                                     : "median %.2f ms (min %.2f, max %.2f, n = %d)"
        return String(format: format, self.median, sorted[0], sorted[sorted.count - 1], sorted.count)
    }

    mutating func add(_ milliseconds: Double) {
        self.values.append(milliseconds)
    }
}

struct MeasureError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

enum Random {
    static func bytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
        return Data(bytes)
    }
}
