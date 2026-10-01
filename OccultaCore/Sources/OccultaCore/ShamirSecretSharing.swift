//
//  ShamirSecretSharing.swift
//  Occulta
//
//  In-house Shamir's Secret Sharing over GF(2^8).
//  Primitive polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B — the AES field).
//  No third-party dependency.
//
//  CRYPTO_REVIEW_CHECKLIST — SSS Math Path
//  ════════════════════════════════════════
//  1. Key ownership map
//     - split() input: 32 raw bytes (vault key material), caller-owned.
//     - Each share: a distinct polynomial evaluation point — no two shares
//       carry the same secret material.
//     - reconstruct() output: 32 raw bytes. ⚠️ Caller must zero this buffer
//       immediately after re-encrypting with it.
//     - Key material shared between contacts: No. Each contact receives a
//       different share (distinct x-coordinate → distinct y-values).
//
//  2. Consumption events
//     - No keys are consumed inside this file. Shares are generated once and
//       returned to the caller as [[UInt8]]. All zeroing responsibility is
//       documented at the call sites (prepareShards).
//
//  3. Multi-party trace — example: 2-of-3 with contacts Bob, Carol, Dave
//     - split(secret, k=2, n=3) → [s1(x=1), s2(x=2), s3(x=3)]
//     - s1 ≠ s2 ≠ s3 (distinct x-coordinates; polynomial evaluated at each)
//     - Any 2 of {s1,s2,s3} reconstruct the 32-byte secret via Lagrange.
//     - 1 share alone: information-theoretically independent of the secret
//       (perfect secrecy of (k−1)-out-of-n SSS over a finite field).
//     - Duplicate x-coordinate check in reconstruct() rejects malformed input.
//
//  4. Security property verification
//     - Property: (k−1)-out-of-n perfect secrecy + correct reconstruction
//       with exactly k or more shares.
//     - Attacker with t < k shares sees a uniformly random distribution over
//       GF(2^8)^32 for the secret — information-theoretic, not computational.
//     - Not achieved: authentication (each shard is signed at the VaultManager
//       layer, outside this file), forward secrecy, post-quantum resistance.
//     - GF(2^8) with 0x11B is the AES field — extensively studied, no known
//       algebraic weakness for the secret-sharing use case.
//     - No prekey public keys involved. Checklist item 4.6: N/A.
//
//  5. Layer boundary check
//     - No SwiftData access. No KeyManagerProtocol calls. No UI.
//     - Input: Data / [[UInt8]]. Output: [[UInt8]] / Data. Pure functions only.
//     - SecRandomCopyBytes is the only external call, for coefficient generation.
//

import Foundation
import Security

// MARK: - ShamirSecretSharing

public enum ShamirSecretSharing {

    // MARK: Errors

    public enum Error: Swift.Error {
        /// `k < 2`, `n < k`, or `n > 255`.
        case invalidParameters
        /// Secret must be exactly 32 bytes.
        case invalidSecretLength
        /// `reconstruct()` received fewer than two shares.
        ///
        /// SSS requires at least two points to define a polynomial. A single share
        /// trivially evaluates to a deterministic value that is NOT the secret.
        case insufficientShares
        /// A share has the wrong length (expected 33 bytes each) or shares have
        /// inconsistent lengths.
        case invalidShareFormat
        /// Two shares carry the same x-coordinate — Lagrange interpolation is
        /// undefined and the call is rejected.
        case duplicateXCoordinate
        /// `SecRandomCopyBytes` failed during polynomial coefficient generation.
        case randomGenerationFailed
    }

    // MARK: - Public API

    /// Split a 32-byte secret into `n` shares with reconstruction threshold `k`.
    ///
    /// Share wire format — each share is exactly 33 bytes:
    ///   share[0]    — x-coordinate in GF(2^8), range [1, n]
    ///   share[1..32] — polynomial evaluations yᵢ for secret bytes i = 0..31
    ///
    /// - Parameters:
    ///   - secret:    Exactly 32 bytes (the vault key material). Must be zeroed
    ///                by the caller after this call returns.
    ///   - threshold: Minimum shares to reconstruct (k ≥ 2).
    ///   - shares:    Total shares to produce (k ≤ n ≤ 255).
    /// - Returns: Array of `n` shares, each 33 bytes.
    ///
    /// ⚠️ Caller must zero the `secret` buffer after this call returns.
    public static func split(secret: Data, threshold k: Int, shares n: Int) throws -> [[UInt8]] {
        guard k >= 2, n >= k, n <= 255 else { throw Error.invalidParameters }
        guard secret.count == 32       else { throw Error.invalidSecretLength }

        let secretBytes = [UInt8](secret)
        // Pre-fill with x-coordinates; y-values are written per byte below.
        var result = (1...n).map { x -> [UInt8] in
            var share = [UInt8](repeating: 0, count: 33)
            share[0] = UInt8(x)
            return share
        }

        // For each secret byte: generate an independent random degree-(k−1)
        // polynomial whose constant term is that byte, then evaluate at x=1..n.
        for byteIdx in 0..<32 {
            var coeffs = try Self.randomPolynomial(constant: secretBytes[byteIdx], degree: k - 1)
            defer { for i in 0..<coeffs.count { coeffs[i] = 0 } }

            for shareIdx in 0..<n {
                result[shareIdx][byteIdx + 1] = eval(poly: coeffs, at: UInt8(shareIdx + 1))
            }
        }

        return result
    }

    /// Reconstruct the 32-byte secret from at least `k` shares.
    ///
    /// Applies Lagrange interpolation at x = 0 over GF(2^8) independently for
    /// each of the 32 secret bytes.
    ///
    /// Extra shares beyond the threshold are accepted and used; the result is
    /// the same regardless of which subset of k or more shares is supplied,
    /// as long as they were produced by the same split() call.
    ///
    /// - Parameter shares: Array of shares from split(). Must contain ≥ k shares.
    /// - Returns: 32-byte secret.
    ///
    /// ⚠️ Caller must zero this buffer after re-encrypting the vault entry.
    public static func reconstruct(shares: [[UInt8]]) throws -> Data {
        guard shares.count >= 2        else { throw Error.insufficientShares }
        guard shares[0].count == 33    else { throw Error.invalidShareFormat }
        guard shares.allSatisfy({ $0.count == 33 }) else { throw Error.invalidShareFormat }

        let xCoords = shares.map { $0[0] }
        // x=0 is the secret itself; a share with that coordinate bypasses the threshold.
        guard !xCoords.contains(0)     else { throw Error.invalidShareFormat }
        guard Set(xCoords).count == xCoords.count else { throw Error.duplicateXCoordinate }

        let weights = Self.lagrangeWeights(xCoords: xCoords)
        var secret  = [UInt8](repeating: 0, count: 32)
        for byteIdx in 0..<32 {
            for i in shares.indices {
                secret[byteIdx] ^= Self.gfMul(shares[i][byteIdx + 1], weights[i])
            }
        }
        return Data(secret)
    }

    // MARK: - GF(2^8) arithmetic
    //
    // Primitive polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B).
    // The low 8 bits of the reduction are 0x1B (= x^4 + x^3 + x + 1),
    // applied when the high bit overflows during left-shift.

    /// Multiply two elements in GF(2^8) using the Russian peasant algorithm.
    ///
    /// Branch-free: each conditional step is an all-ones or all-zero mask, so every
    /// iteration does the same work whatever the inputs (`bugs.md` Bug 131). Secret bytes
    /// pass through here in `split` and `reconstruct`. The optimizer happened to emit
    /// conditional selects for the old `if` form, but the source didn't guarantee it and
    /// unoptimized builds branched.
    ///
    /// Internal visibility for unit testing.
    static func gfMul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var p: UInt8 = 0
        var a = a
        var b = b
        for _ in 0..<8 {
            p ^= a & (0 &- (b & 1))         // add a when b's low bit is set
            let carry = 0 &- (a >> 7)       // all ones when a's high bit is set
            a = (a << 1) ^ (0x1B & carry)   // reduce: x^8 mod 0x11B ≡ 0x1B
            b >>= 1
        }
        return p
    }

    /// Multiplicative inverse in GF(2^8) via Fermat's little theorem: a^254 = a^(−1).
    ///
    /// |GF(2^8)*| = 255, so a^255 = 1 for all a ≠ 0, therefore a^254 = a^(−1).
    ///
    /// Internal visibility for unit testing. Precondition: a ≠ 0.
    static func gfInv(_ a: UInt8) -> UInt8 {
        precondition(a != 0, "zero has no multiplicative inverse in GF(2^8)")
        var result: UInt8 = 1
        var base          = a
        var exp           = 254
        while exp > 0 {
            if exp & 1 != 0 { result = self.gfMul(result, base) }
            base = Self.gfMul(base, base)
            exp >>= 1
        }
        return result
    }

    // MARK: - Private

    /// Generate a random polynomial of degree `degree` over GF(2^8) with
    /// `constant` as the degree-0 coefficient.
    ///
    /// The leading coefficient (degree `degree`) is guaranteed non-zero,
    /// ensuring the polynomial has exactly the requested degree and therefore
    /// exactly `k` points are required for reconstruction.
    private static func randomPolynomial(constant: UInt8, degree: Int) throws -> [UInt8] {
        var coeffs    = [UInt8](repeating: 0, count: degree + 1)
        coeffs[0]     = constant

        for i in 1...degree {
            var byte = [UInt8](repeating: 0, count: 1)
            repeat {
                guard SecRandomCopyBytes(kSecRandomDefault, 1, &byte) == errSecSuccess
                else { throw Error.randomGenerationFailed }
            } while i == degree && byte[0] == 0   // leading coefficient must be non-zero
            coeffs[i] = byte[0]
        }
        return coeffs
    }

    /// Evaluate polynomial `poly` at `x` using Horner's method in GF(2^8).
    ///
    /// Horner: p(x) = (…((pₙ·x + pₙ₋₁)·x + pₙ₋₂)·…·x + p₀)
    private static func eval(poly: [UInt8], at x: UInt8) -> UInt8 {
        poly.reversed().reduce(UInt8(0)) { acc, coeff in
            Self.gfMul(acc, x) ^ coeff
        }
    }

    /// Lagrange basis weights at x = 0 over GF(2^8), one per share.
    ///
    /// f(0) = Σᵢ [ yᵢ · wᵢ ],  wᵢ = ∏ⱼ≠ᵢ (0 − xⱼ) / (xᵢ − xⱼ)
    ///
    /// In GF(2^8): subtraction = XOR, so (0 − xⱼ) = xⱼ and (xᵢ − xⱼ) = xᵢ ⊕ xⱼ.
    ///
    /// The weights depend only on the x-coordinates, which every byte shares, so
    /// `reconstruct` computes them once rather than once per byte. `verifiedKey`'s subset
    /// search (`bugs.md` Bug 95) calls `reconstruct` up to 1,024 times, which is what made
    /// the per-byte recomputation, and its 32 inversions per share, worth removing.
    private static func lagrangeWeights(xCoords: [UInt8]) -> [UInt8] {
        xCoords.indices.map { i in
            var num: UInt8 = 1
            var den: UInt8 = 1
            for j in xCoords.indices where j != i {
                num = Self.gfMul(num, xCoords[j])              // numerator  × xⱼ
                den = Self.gfMul(den, xCoords[i] ^ xCoords[j]) // denominator × (xᵢ ⊕ xⱼ)
            }
            return Self.gfMul(num, Self.gfInv(den))
        }
    }
}
