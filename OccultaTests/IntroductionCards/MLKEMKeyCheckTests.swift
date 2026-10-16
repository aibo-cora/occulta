//
//  MLKEMKeyCheckTests.swift
//  OccultaTests
//
//  The FIPS 203 §7.2 modulus check on an ML-KEM-1024 encapsulation key. CryptoKit's own parse checks only the length.
//

import Testing
import CryptoKit
import Foundation

@testable import Occulta
@testable import OccultaFormats

@Suite("ML-KEM key check — FIPS 203 modulus check")
struct MLKEMKeyCheckTests {

    /// A key of all-zero coefficients, with coefficient `index` (0 ..< 1024) set to `value`.
    private func key(coefficient index: Int, value: UInt16) -> Data {
        var bytes = [UInt8](repeating: 0, count: 1_568)
        let base = (index / 2) * 3
        if index % 2 == 0 {
            // c0 = b0 | (b1 & 0x0F) << 8
            bytes[base] = UInt8(value & 0xFF)
            bytes[base + 1] = (bytes[base + 1] & 0xF0) | UInt8(value >> 8)
        } else {
            // c1 = b1 >> 4 | b2 << 4
            bytes[base + 1] = (bytes[base + 1] & 0x0F) | UInt8((value & 0x0F) << 4)
            bytes[base + 2] = UInt8(value >> 4)
        }
        return Data(bytes)
    }

    @Test("A coefficient of exactly 3328 passes and exactly 3329 fails, in both the c0 and the c1 position")
    func boundaryOnBothPositions() {
        for index in [0, 1, 2, 3, 510, 511, 512, 513, 1_022, 1_023] {
            #expect(MLKEMKeyCheck.isValidEncapsulationKey1024(self.key(coefficient: index, value: 3_328)), "coefficient \(index) = 3328")
            #expect(!MLKEMKeyCheck.isValidEncapsulationKey1024(self.key(coefficient: index, value: 3_329)), "coefficient \(index) = 3329")
            #expect(!MLKEMKeyCheck.isValidEncapsulationKey1024(self.key(coefficient: index, value: 4_095)), "coefficient \(index) = 4095")
        }
    }

    @Test("Every one of the 1,024 coefficients is checked")
    func everyCoefficientIsChecked() {
        for index in 0 ..< 1_024 {
            #expect(!MLKEMKeyCheck.isValidEncapsulationKey1024(self.key(coefficient: index, value: 3_329)), "coefficient \(index)")
        }
    }

    @Test("The test helper puts the value where the check reads it: 3328 is not the same bytes as 3329")
    func helperControl() {
        #expect(self.key(coefficient: 0, value: 3_328) != self.key(coefficient: 0, value: 3_329))
        #expect(self.key(coefficient: 1, value: 3_328) != self.key(coefficient: 1, value: 3_329))
        #expect(self.key(coefficient: 0, value: 3_328)[0 ... 1] == Data([0x00, 0x0D]), "3328 = 0xD00")
        #expect(self.key(coefficient: 1, value: 3_328)[1 ... 2] == Data([0x00, 0xD0]), "3328 = 0xD00 in the high nibbles")
    }

    @Test("An all-zero key passes; ρ, the last 32 bytes, is not checked")
    func allZeroAndRho() {
        #expect(MLKEMKeyCheck.isValidEncapsulationKey1024(Data(count: 1_568)))
        var withRho = [UInt8](repeating: 0, count: 1_568)
        for index in 1_536 ..< 1_568 { withRho[index] = 0xFF }
        #expect(MLKEMKeyCheck.isValidEncapsulationKey1024(Data(withRho)))
    }

    @Test("Wrong lengths fail")
    func wrongLengths() {
        for count in [0, 1, 1_536, 1_567, 1_569, 3_136] {
            #expect(!MLKEMKeyCheck.isValidEncapsulationKey1024(Data(count: count)), "\(count) bytes")
        }
    }

    @Test("All 0xFF and random bytes fail")
    func garbageFails() {
        #expect(!MLKEMKeyCheck.isValidEncapsulationKey1024(Data(repeating: 0xFF, count: 1_568)))
        #expect(!MLKEMKeyCheck.isValidEncapsulationKey1024(randomBytes(1_568)))
    }

    @Test("A slice is checked by its bytes, not its indices")
    func sliceWorks() {
        let framed = Data(repeating: 0xFF, count: 5) + plausibleMLKEMKeyBytes()
        #expect(MLKEMKeyCheck.isValidEncapsulationKey1024(framed.dropFirst(5)))
    }

    @Test("The plausible-key helper passes")
    func plausibleHelper() {
        for _ in 0 ..< 20 { #expect(MLKEMKeyCheck.isValidEncapsulationKey1024(plausibleMLKEMKeyBytes())) }
    }

    @available(iOS 26, *)
    @Test("A real key passes, and so does everything CryptoKit can encapsulate to")
    func realKeysPass() throws {
        for _ in 0 ..< 50 {
            let raw = try MLKEM1024.PrivateKey().publicKey.rawRepresentation
            #expect(MLKEMKeyCheck.isValidEncapsulationKey1024(raw))
        }
    }

    @available(iOS 26, *)
    @Test("The check agrees with CryptoKit's encapsulate on random keys with plausible and implausible coefficients")
    func agreesWithEncapsulate() throws {
        let plausible = (0 ..< 20).map { _ in plausibleMLKEMKeyBytes() }
        for key in plausible + [randomBytes(1_568), Data(repeating: 0xFF, count: 1_568)] {
            let encapsulates = (try? MLKEM1024.PublicKey(rawRepresentation: key).encapsulate()) != nil
            #expect(MLKEMKeyCheck.isValidEncapsulationKey1024(key) == encapsulates)
        }
    }
}
