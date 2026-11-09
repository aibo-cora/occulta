//
//  PairingTestSupport.swift
//  OccultaTests
//
//  What the pair-key suites share: two phones' mirrored pair keys, a provider whose every key refuses to import, and sample
//  pair keys with recognisable bytes.
//

import Foundation
@testable import Occulta

/// Two phones' pair keys, mirrored: `a` holds its own blobs and `b`'s public keys, and the other way round. Software keys.
struct MirroredPairKeys {
    let a: PairKeys
    let b: PairKeys

    init() throws {
        let provider = SoftwareCardKeys()
        let aa = try provider.makeAgreementKey(), asig = try provider.makeSigningKey()
        let ba = try provider.makeAgreementKey(), bsig = try provider.makeSigningKey()
        self.a = PairKeys(
            ourAgreementBlob: aa.blob, ourAgreementKey: aa.publicKey, ourSigningBlob: asig.blob, ourSigningKey: asig.publicKey,
            peerAgreementKey: ba.publicKey, peerSigningKey: bsig.publicKey, ourMLDSABlob: nil, peerMLDSAKey: nil
        )
        self.b = PairKeys(
            ourAgreementBlob: ba.blob, ourAgreementKey: ba.publicKey, ourSigningBlob: bsig.blob, ourSigningKey: bsig.publicKey,
            peerAgreementKey: aa.publicKey, peerSigningKey: asig.publicKey, ourMLDSABlob: nil, peerMLDSAKey: nil
        )
    }
}

/// A provider whose keys never import: the Enclave refusing a blob.
struct BrokenCardKeys: CardKeyProviding {
    struct Refused: Error {}
    func makeAgreementKey() throws -> (publicKey: Data, blob: Data) { throw Refused() }
    func makeSigningKey() throws -> (publicKey: Data, blob: Data) { throw Refused() }
    func signRaw(_ payload: Data, signingBlob: Data) throws -> Data { throw Refused() }
    func signDER(_ payload: Data, signingBlob: Data) throws -> Data { throw Refused() }
    func sharedSecret(agreementBlob: Data, peerPublicKey: Data) throws -> Data { throw Refused() }
    func agreementPublicKey(blob: Data) throws -> Data { throw Refused() }
    func signingPublicKey(blob: Data) throws -> Data { throw Refused() }
    func makeMLDSAKey() throws -> (publicKey: Data, blob: Data) { throw Refused() }
    func mldsaSign(_ payload: Data, blob: Data) throws -> Data { throw Refused() }
    func mldsaPublicKey(blob: Data) throws -> Data { throw Refused() }
}

/// Pair keys with recognisable bytes, for tests of storage. `mldsa` adds our ML-DSA blob, `peerMLDSA` the peer's public key.
func samplePairKeys(mldsa: Bool = false, peerMLDSA: Bool = false, blob: Int = 143) -> PairKeys {
    func key(_ byte: UInt8) -> Data { Data(repeating: byte, count: 65) }
    return PairKeys(
        ourAgreementBlob: Data(repeating: 0xA1, count: blob), ourAgreementKey: key(0xA2),
        ourSigningBlob: Data(repeating: 0xA3, count: 143), ourSigningKey: key(0xA4),
        peerAgreementKey: key(0xB1), peerSigningKey: key(0xB2),
        ourMLDSABlob: mldsa ? Data(repeating: 0xC1, count: 7_540) : nil,
        peerMLDSAKey: peerMLDSA ? Data(repeating: 0xD1, count: PairingCodec.mldsaKeySize) : nil
    )
}
