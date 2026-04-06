//
//  QuantumKeyMaterial.swift
//  Occulta
//
//  All ML-KEM artifacts from a hybrid PQ key exchange, grouped as a single
//  Codable struct. Encrypted as one AES-GCM blob before storage in SwiftData.
//
//  Decrypt once when needed, read fields, discard. Never store plaintext.
//

import Foundation

/// ML-KEM artifacts from a hybrid PQ key exchange.
struct QuantumKeyMaterial: Codable {
    /// ML-KEM shared secret from our encapsulation of the contact's key (32 bytes).
    /// Cannot be rederived — encapsulation used one-time internal randomness.
    let encapsulatedSecret: Data

    /// ML-KEM shared secret from decapsulating the contact's ciphertext (32 bytes).
    /// The SE decapsulation key was released after use — also non-rederivable.
    let decapsulatedSecret: Data

    /// ML-KEM ciphertext we sent to the contact.
    /// Stored for audit and potential future re-derivation if SE key storage is added.
    let ourCiphertext: Data

    /// ML-KEM ciphertext the contact sent to us.
    let peerCiphertext: Data

    /// Whether both shared secrets are present and correctly sized.
    var isValid: Bool {
        self.encapsulatedSecret.count == 32 && self.decapsulatedSecret.count == 32
    }

    // MARK: - Convenience initializer from exchange result

    init(from result: ExchangeManager.HybridExchangeResult) {
        self.encapsulatedSecret = result.mlkemSecret1
        self.decapsulatedSecret = result.mlkemSecret2
        self.ourCiphertext = result.ourCiphertext
        self.peerCiphertext = result.peerCiphertext
    }

    init(
        encapsulatedSecret: Data,
        decapsulatedSecret: Data,
        ourCiphertext: Data,
        peerCiphertext: Data
    ) {
        self.encapsulatedSecret = encapsulatedSecret
        self.decapsulatedSecret = decapsulatedSecret
        self.ourCiphertext = ourCiphertext
        self.peerCiphertext = peerCiphertext
    }
}
