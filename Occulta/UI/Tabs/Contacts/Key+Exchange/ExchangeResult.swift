//
//  ExchangeResult.swift
//  Occulta
//
//  Diceware verification supporting both classical (v1) and hybrid PQ exchanges.
//
//  ⚠️ Backward compatibility: `exchangeResult` is optional.
//  Nil → classical Diceware (ECDH only). Non-nil → hybrid (ECDH + ML-KEM + nonces).
//

import SwiftUI
import CryptoKit

struct ExchangeResult: View {
    let identifier: String
    let receivedKey: Contact.Draft.Key
    let exchangeResult: ExchangeManager.HybridExchangeResult?

    init(identifier: String, receivedKey: Contact.Draft.Key) {
        self.identifier = identifier
        self.receivedKey = receivedKey
        self.exchangeResult = nil
    }

    init(identifier: String, receivedKey: Contact.Draft.Key, exchangeResult: ExchangeManager.HybridExchangeResult) {
        self.identifier = identifier
        self.receivedKey = receivedKey
        self.exchangeResult = exchangeResult
    }

    var body: some View {
        VStack {
            VStack(spacing: 20) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.title)
                Text("Congrats, you successfully exchanged keys with your contact.")
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal)

            Divider()

            VStack(spacing: 20) {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.yellow)
                    Text("Please confirm bad guys did not swap your keys with their own. Verify with your contact that the words you are seeing match and are in the correct order.")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding()

                VerifyExchangeWords(
                    identifier: self.identifier,
                    key: self.receivedKey,
                    exchangeResult: self.exchangeResult
                )
            }
        }
        .presentationDetents([.large])
    }
}

struct VerifyExchangeWords: View {
    let passphraseGenerator = Manager.PassphraseGenerator()
    let keyManager = Manager.Key()

    let identifier: String
    let key: Contact.Draft.Key
    let exchangeResult: ExchangeManager.HybridExchangeResult?

    @Environment(ContactManager.self) private var contactManager: ContactManager?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack {
            let dicewareKey = self.deriveDicewareKey()
            let separator = "-"
            let passphrase = self.passphraseGenerator.generate(separator: separator, sharedKey: dicewareKey)
            let components = passphrase.components(separatedBy: separator)

            VStack(spacing: 20) {
                ForEach(components, id: \.self) { word in
                    Text(word)
                        .transition(.move(edge: .bottom))
                        .font(.custom("Courier", size: 20))
                        .bold()
                }
            }

            Text("By confirming these words, you are agreeing to use this contact's key to encrypt data between you two.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding()

            if self.exchangeResult != nil {
                Label("Quantum-resistant exchange", systemImage: "shield.checkered")
                    .font(.caption2)
                    .foregroundStyle(.green)
                    .padding(.bottom)
            } else {
                Label("Classical exchange", systemImage: "lock.shield")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.bottom)
            }

            Button("Confirm") {
                if let exchangeResult {
                    let quantum = QuantumKeyMaterial(encapsulatedSecret: exchangeResult.mlkemSecret1, decapsulatedSecret: exchangeResult.mlkemSecret2, ourCiphertext: exchangeResult.ourCiphertext, peerCiphertext: exchangeResult.peerCiphertext)
                    
                    if let key = Contact.Draft.Key(material: self.key.material, owner: self.key.owner, date: self.key.acquiredAt, quantumKeyMaterial: quantum) {
                        do {
                            try self.contactManager?.update(key: key, for: self.identifier)
                        } catch {
                            
                        }
                    }
                }
                
                self.dismiss()
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private func deriveDicewareKey() -> Data? {
        if let result = self.exchangeResult {
            let material = QuantumKeyMaterial(from: result)
            
            return self.keyManager.createDicewareKey(peerP256Material: result.peerP256PublicKey, quantumMaterial: material, ourNonce: result.ourNonce, peerNonce: result.peerNonce)?.withUnsafeBytes { Data($0) }
        } else {
            return self.keyManager.createSharedSecret(
                using: self.key.material
            )?.withUnsafeBytes { Data($0) }
        }
    }
}
