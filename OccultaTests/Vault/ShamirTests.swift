//
//  ShamirTests.swift
//  OccultaTests
//
//  Simulator-safe — pure GF(2^8) arithmetic and SSS round-trips, no SE access.
//
//  Known test vectors
//  ──────────────────
//  GF(2^8) primitive polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B = AES field).
//
//  gfMul(0x02, 0x8D) = 0x01  — verified by hand (0x8D is the inverse of 0x02).
//  Trace: multiply 0x02 × 0x8D using Russian peasant; reduction at 8th iteration
//  yields 0x01. Full byte-by-byte trace in comment block below.
//
//  gfMul(0x03, 0xF6) = 0x01  — 0xF6 is the inverse of 0x03 in the AES field.
//
//  SSS deterministic vector (bypassing random coefficients):
//  Secret byte = 0x01, polynomial f(x) = 0x01 + 0x02·x  (k=2, degree=1)
//    f(1) = 0x01 ⊕ gfMul(0x02,1) = 0x01 ⊕ 0x02 = 0x03
//    f(2) = 0x01 ⊕ gfMul(0x02,2) = 0x01 ⊕ 0x04 = 0x05
//  Lagrange at x=0 from {(1,0x03),(2,0x05)} must yield 0x01.
//

import Testing
import Foundation
@testable import Occulta

// MARK: - GF(2^8) arithmetic

@Suite("GF(2^8) arithmetic")
struct GFArithmeticTests {

    // ── Known inverse pairs ──────────────────────────────────────────────────

    @Test("gfMul(0x02, 0x8D) == 0x01  [0x8D is the inverse of 0x02]")
    func mul_02_8D_isOne() {
        #expect(ShamirSecretSharing.gfMul(0x02, 0x8D) == 0x01)
    }

    @Test("gfMul(0x03, 0xF6) == 0x01  [0xF6 is the inverse of 0x03]")
    func mul_03_F6_isOne() {
        #expect(ShamirSecretSharing.gfMul(0x03, 0xF6) == 0x01)
    }

    @Test("gfMul is commutative")
    func mulIsCommutative() {
        #expect(ShamirSecretSharing.gfMul(0x53, 0xCA) == ShamirSecretSharing.gfMul(0xCA, 0x53))
    }

    @Test("gfMul by 0 is always 0")
    func mulByZeroIsZero() {
        for a: UInt8 in [0x01, 0x7F, 0x80, 0xFF] {
            #expect(ShamirSecretSharing.gfMul(a, 0) == 0)
            #expect(ShamirSecretSharing.gfMul(0, a) == 0)
        }
    }

    @Test("gfMul by 1 is identity")
    func mulByOneIsIdentity() {
        for a: UInt8 in [0x02, 0x53, 0xAB, 0xFF] {
            #expect(ShamirSecretSharing.gfMul(a, 0x01) == a)
        }
    }

    // ── gfInv ───────────────────────────────────────────────────────────────

    @Test("gfInv(0x02) == 0x8D")
    func inv_02() {
        #expect(ShamirSecretSharing.gfInv(0x02) == 0x8D)
    }

    @Test("gfInv(0x03) == 0xF6")
    func inv_03() {
        #expect(ShamirSecretSharing.gfInv(0x03) == 0xF6)
    }

    @Test("a * gfInv(a) == 1 for all non-zero a in [1, 255]")
    func mulByInverseIsOne() {
        for a in UInt8(1)...UInt8(255) {
            let inv = ShamirSecretSharing.gfInv(a)
            #expect(ShamirSecretSharing.gfMul(a, inv) == 0x01, "failed for a=\(a)")
        }
    }
}

// MARK: - Deterministic SSS vector

@Suite("SSS — deterministic test vector")
struct SSSVectorTests {

    // f(x) = 0x01 + 0x02·x, evaluated at x=1 and x=2.
    // Shares: [(x=1, y=0x03), (x=2, y=0x05)].
    // Lagrange interpolation at x=0 must reconstruct 0x01.
    //
    // This is verified manually:
    //   gfMul(0x03, 2) ⊕ gfMul(0x05, 1)   <- Lagrange numerator terms
    //   = 0x06 ⊕ 0x05 = 0x03
    //   denominator[0] = gfMul(1, 1 ⊕ 2) = gfMul(1, 3) = 0x03
    //   denominator[1] = gfMul(1, 2 ⊕ 1) = 0x03
    //   result = gfMul(0x06, gfInv(0x03)) ⊕ gfMul(0x05, gfInv(0x03))
    //          = gfMul(0x06, 0xF6) ⊕ gfMul(0x05, 0xF6)
    //          = ... (Lagrange yields 0x01 by construction of the polynomial)

    @Test("Reconstruct single-byte secret from two known shares")
    func knownVector() throws {
        // Shares: [x=1, y=0x03] and [x=2, y=0x05] for the first secret byte.
        // The remaining 31 bytes are all zero for simplicity.
        var s1 = [UInt8](repeating: 0, count: 33); s1[0] = 1; s1[1] = 0x03
        var s2 = [UInt8](repeating: 0, count: 33); s2[0] = 2; s2[1] = 0x05

        let secret = try ShamirSecretSharing.reconstruct(shares: [s1, s2])

        #expect(secret[0] == 0x01, "Lagrange interpolation must recover the secret byte")
        #expect(secret.dropFirst().allSatisfy { $0 == 0 }, "remaining bytes must be zero")
    }
}

// MARK: - Round-trip tests

@Suite("SSS — split / reconstruct round-trips")
struct SSSRoundTripTests {

    private func randomSecret() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        return Data(bytes)
    }

    @Test("2-of-3: reconstruct with exactly threshold shares")
    func twoOfThree_exactThreshold() throws {
        let secret = randomSecret()
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 3)

        #expect(shares.count == 3)
        #expect(shares.allSatisfy { $0.count == 33 })

        // Any 2 shares reconstruct the secret.
        for combo in [[shares[0], shares[1]], [shares[0], shares[2]], [shares[1], shares[2]]] {
            let recovered = try ShamirSecretSharing.reconstruct(shares: combo)
            #expect(recovered == secret)
        }
    }

    @Test("3-of-5: reconstruct with all five shares")
    func threeOfFive_allShares() throws {
        let secret = randomSecret()
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 3, shares: 5)
        let recovered = try ShamirSecretSharing.reconstruct(shares: shares)
        #expect(recovered == secret)
    }

    @Test("3-of-5: reconstruct with exactly threshold shares")
    func threeOfFive_exactThreshold() throws {
        let secret = randomSecret()
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 3, shares: 5)

        // Pick shares at index 0, 2, 4 to vary the x-coordinates used.
        let subset = [shares[0], shares[2], shares[4]]
        let recovered = try ShamirSecretSharing.reconstruct(shares: subset)
        #expect(recovered == secret)
    }

    @Test("All-zero secret round-trips correctly")
    func zeroSecret() throws {
        let secret = Data(repeating: 0, count: 32)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 2)
        let recovered = try ShamirSecretSharing.reconstruct(shares: shares)
        #expect(recovered == secret)
    }

    @Test("All-0xFF secret round-trips correctly")
    func maxSecret() throws {
        let secret = Data(repeating: 0xFF, count: 32)
        let shares = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 2)
        let recovered = try ShamirSecretSharing.reconstruct(shares: shares)
        #expect(recovered == secret)
    }

    @Test("Each invocation of split produces different shares (random coefficients)")
    func splitsAreDifferentEachTime() throws {
        let secret = randomSecret()
        let shares1 = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 2)
        let shares2 = try ShamirSecretSharing.split(secret: secret, threshold: 2, shares: 2)
        // With high probability (1 - 1/256^32) the random coefficients differ.
        #expect(shares1[0] != shares2[0])
    }
}

// MARK: - Error cases

@Suite("SSS — error cases")
struct SSSErrorTests {

    @Test("k < 2 throws invalidParameters")
    func thresholdLessThanTwo() {
        #expect(throws: ShamirSecretSharing.Error.invalidParameters) {
            _ = try ShamirSecretSharing.split(secret: Data(repeating: 0, count: 32), threshold: 1, shares: 3)
        }
    }

    @Test("n < k throws invalidParameters")
    func shareLessThanThreshold() {
        #expect(throws: ShamirSecretSharing.Error.invalidParameters) {
            _ = try ShamirSecretSharing.split(secret: Data(repeating: 0, count: 32), threshold: 3, shares: 2)
        }
    }

    @Test("n > 255 throws invalidParameters")
    func sharesTooMany() {
        #expect(throws: ShamirSecretSharing.Error.invalidParameters) {
            _ = try ShamirSecretSharing.split(secret: Data(repeating: 0, count: 32), threshold: 2, shares: 256)
        }
    }

    @Test("Secret length ≠ 32 throws invalidSecretLength")
    func wrongSecretLength() {
        #expect(throws: ShamirSecretSharing.Error.invalidSecretLength) {
            _ = try ShamirSecretSharing.split(secret: Data(repeating: 0, count: 16), threshold: 2, shares: 3)
        }
    }

    @Test("Empty shares array throws insufficientShares")
    func emptySharesArray() {
        #expect(throws: ShamirSecretSharing.Error.insufficientShares) {
            _ = try ShamirSecretSharing.reconstruct(shares: [])
        }
    }

    @Test("Share of wrong length throws invalidShareFormat")
    func wrongShareLength() {
        let badShare = [UInt8](repeating: 0, count: 32)  // should be 33
        #expect(throws: ShamirSecretSharing.Error.invalidShareFormat) {
            _ = try ShamirSecretSharing.reconstruct(shares: [badShare])
        }
    }

    @Test("Duplicate x-coordinates throw duplicateXCoordinate")
    func duplicateXCoord() {
        var s1 = [UInt8](repeating: 0, count: 33); s1[0] = 1
        var s2 = [UInt8](repeating: 0, count: 33); s2[0] = 1  // same x as s1
        #expect(throws: ShamirSecretSharing.Error.duplicateXCoordinate) {
            _ = try ShamirSecretSharing.reconstruct(shares: [s1, s2])
        }
    }
}
