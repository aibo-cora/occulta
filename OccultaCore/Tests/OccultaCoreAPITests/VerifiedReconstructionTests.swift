//
//  VerifiedReconstructionTests.swift
//  OccultaCoreAPITests
//
//  `ShamirSecretSharing.reconstruct(shares:maxAttempts:isCorrect:)` across thresholds, group
//  sizes, and the number, kind and position of bad shares. Pure and fast, so it covers far more
//  combinations than the app's end-to-end restore tests (`VaultRestoreTrustTests`, Bug 95).
//
//  Work is measured by counting calls to the check, not by timing: attempt counts are exact
//  and deterministic, and timing assertions would be flaky on CI's runners.
//

import Testing
import Foundation
import OccultaCore

/// Ways a share handed to `reconstruct` can be bad.
private enum BadShare: CaseIterable, CustomStringConvertible {
    /// Well-formed, with an x no honest share uses, and random values.
    case freshX
    /// Reuses an honest share's x, so every subset holding both is rejected for its shape.
    case reusedX
    /// x = 0, the secret's own coordinate, which is rejected for its shape.
    case zeroX
    /// The wrong length, rejected for its shape.
    case wrongLength
    /// A genuine share, from a split of a different secret.
    case otherSplit

    var description: String { "\(self)" }
}

private func randomBytes(_ count: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
}

private func randomSecret() -> Data { Data(randomBytes(32)) }

/// The `index`-th bad share of `kind` to mix with `honest`. Fresh x-coordinates start at 200,
/// clear of every honest share in these tests.
private func badShare(_ kind: BadShare, index: Int, honest: [[UInt8]]) throws -> [UInt8] {
    switch kind {
    case .freshX:      return [UInt8(200 + index)] + randomBytes(32)
    case .reusedX:     return [honest[index % honest.count][0]] + randomBytes(32)
    case .zeroX:       return [0] + randomBytes(32)
    case .wrongLength: return randomBytes(20)
    case .otherSplit:
        let other = try ShamirSecretSharing.split(secret: randomSecret(), threshold: 2, shares: 200 + index)
        return other[199 + index]   // x = 200 + index
    }
}

/// `bad` inserted into `honest` at the front, the middle or the back.
private enum Placement: CaseIterable { case front, middle, back }

private func mix(_ honest: [[UInt8]], with bad: [[UInt8]], at placement: Placement) -> [[UInt8]] {
    var shares = honest
    let position = switch placement {
    case .front:  0
    case .middle: honest.count / 2
    case .back:   honest.count
    }
    shares.insert(contentsOf: bad, at: position)
    return shares
}

@Suite("Shamir — reconstruction checked against the caller's test")
struct VerifiedReconstructionTests {

    @Test("Recovers the secret across thresholds, group sizes, and the number, kind and position of bad shares")
    func recoversAcrossTheMatrix() throws {
        for k in [2, 3, 5] {
            for n in k...10 {
                let secret = randomSecret()
                let honest = try ShamirSecretSharing.split(secret: secret, threshold: k, shares: n)

                #expect(try ShamirSecretSharing.reconstruct(shares: honest) { $0 == secret } == secret,
                        "k=\(k) n=\(n), no bad shares")

                for kind in BadShare.allCases {
                    // One bad share, in every position.
                    for placement in Placement.allCases {
                        let shares = mix(honest, with: [try badShare(kind, index: 0, honest: honest)], at: placement)
                        #expect(try ShamirSecretSharing.reconstruct(shares: shares) { $0 == secret } == secret,
                                "k=\(k) n=\(n) one \(kind) at \(placement)")
                    }
                    // Two and three bad shares of the same kind, spread through the group.
                    for count in 2...3 {
                        var shares = honest
                        for i in 0..<count {
                            shares.insert(try badShare(kind, index: i, honest: honest), at: (i * shares.count) / count)
                        }
                        #expect(try ShamirSecretSharing.reconstruct(shares: shares) { $0 == secret } == secret,
                                "k=\(k) n=\(n) \(count) × \(kind)")
                    }
                }
            }
        }
    }

    @Test("Fewer honest shares than the threshold throws noVerifiedSubset, whatever else is there")
    func tooFewHonestShares() throws {
        for k in [2, 3, 5] {
            let secret = randomSecret()
            let honest = Array(try ShamirSecretSharing.split(secret: secret, threshold: k, shares: k + 2).prefix(k - 1))
            for kind in BadShare.allCases {
                for count in 1...2 {
                    let bad = try (0..<count).map { try badShare(kind, index: $0, honest: honest) }
                    #expect(throws: ShamirSecretSharing.Error.noVerifiedSubset, "k=\(k) \(count) × \(kind)") {
                        try ShamirSecretSharing.reconstruct(shares: honest + bad) { $0 == secret }
                    }
                }
            }
        }
    }

    @Test("Shuffling the shares doesn't change the result")
    func orderDoesNotMatter() throws {
        let secret = randomSecret()
        let honest = try ShamirSecretSharing.split(secret: secret, threshold: 3, shares: 6)
        let bad = [try badShare(.freshX, index: 0, honest: honest), try badShare(.reusedX, index: 1, honest: honest)]
        for _ in 0..<20 {
            let shares = (honest + bad).shuffled()
            #expect(try ShamirSecretSharing.reconstruct(shares: shares) { $0 == secret } == secret)
        }
    }

    @Test("One bad share at position p is found on check p + 2: the whole set, then each share left out in turn")
    func oneBadShareAttemptCount() throws {
        let secret = randomSecret()
        let honest = try ShamirSecretSharing.split(secret: secret, threshold: 3, shares: 8)
        let bad = try badShare(.freshX, index: 0, honest: honest)
        for position in 0...honest.count {
            var shares = honest
            shares.insert(bad, at: position)
            var checks = 0
            let result = try ShamirSecretSharing.reconstruct(shares: shares) { candidate in
                checks += 1
                return candidate == secret
            }
            #expect(result == secret)
            #expect(checks == position + 2, "bad share at \(position)")
            #expect(checks <= shares.count + 1)
        }
    }

    @Test("The search stops exactly at maxAttempts")
    func capStopsTheSearch() throws {
        let shares = try ShamirSecretSharing.split(secret: randomSecret(), threshold: 2, shares: 12)
        for cap in [1, 10, 100] {
            var checks = 0
            #expect(throws: ShamirSecretSharing.Error.noVerifiedSubset) {
                try ShamirSecretSharing.reconstruct(shares: shares, maxAttempts: cap) { _ in checks += 1; return false }
            }
            #expect(checks == cap)
        }
    }

    @Test("Without a cap in the way, every subset of two or more is tried once, and subsets with a bad shape count but aren't checked")
    func exhaustiveSearch() throws {
        let shares = try ShamirSecretSharing.split(secret: randomSecret(), threshold: 2, shares: 4)

        // 5 shares: 2^5 − 5 − 1 = 26 subsets of two or more.
        var checks = 0
        #expect(throws: ShamirSecretSharing.Error.noVerifiedSubset) {
            try ShamirSecretSharing.reconstruct(shares: shares + [try badShare(.freshX, index: 0, honest: shares)]) { _ in
                checks += 1; return false
            }
        }
        #expect(checks == 26)

        // With an x = 0 share instead, the 15 subsets holding it are rejected for their shape
        // before the check, leaving 11. They still count toward the cap.
        checks = 0
        #expect(throws: ShamirSecretSharing.Error.noVerifiedSubset) {
            try ShamirSecretSharing.reconstruct(shares: shares + [try badShare(.zeroX, index: 0, honest: shares)]) { _ in
                checks += 1; return false
            }
        }
        #expect(checks == 11)

        // A cap of 16 covers the whole set, the 5 with one left out and the 10 with two left
        // out. Only the subsets without the x = 0 share reach the check: one with one left out,
        // and the four pairs that include it. So 16 attempts, 5 checks.
        checks = 0
        #expect(throws: ShamirSecretSharing.Error.noVerifiedSubset) {
            try ShamirSecretSharing.reconstruct(shares: shares + [try badShare(.zeroX, index: 0, honest: shares)], maxAttempts: 16) { _ in
                checks += 1; return false
            }
        }
        #expect(checks == 5)
    }

    @Test("The result is only as good as the check: one that accepts anything gets a wrong secret back")
    func checkIsTrusted() throws {
        let secret = randomSecret()
        let honest = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 3)
        let shares = honest + [try badShare(.freshX, index: 0, honest: honest)]
        let result = try ShamirSecretSharing.reconstruct(shares: shares) { _ in true }
        #expect(result != secret)
        #expect(result.count == 32)
    }

    /// The bad share goes first, so this costs two reconstructions. Last would cost 256 (the
    /// p + 2 rule above, still well within the cap), about 30 s in a Debug build for no extra
    /// coverage: what's being checked here is the size, and the position cost is pinned above.
    @Test("A group of 255 shares, the most there can be, recovers past a bad share")
    func largestGroup() throws {
        let secret = randomSecret()
        let honest = try ShamirSecretSharing.split(secret: secret, threshold: 3, shares: 254)
        let shares = [[255] + randomBytes(32)] + honest
        var checks = 0
        let result = try ShamirSecretSharing.reconstruct(shares: shares) { candidate in
            checks += 1
            return candidate == secret
        }
        #expect(result == secret)
        #expect(checks == 2)
    }
}
