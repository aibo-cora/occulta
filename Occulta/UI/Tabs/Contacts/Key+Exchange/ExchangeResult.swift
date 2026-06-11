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

    init(identifier: String, receivedKey: Contact.Draft.Key, exchangeResult: ExchangeManager.HybridExchangeResult? = nil) {
        self.identifier = identifier
        self.receivedKey = receivedKey
        self.exchangeResult = exchangeResult
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                self.keyMaterialSection
                
                Divider()
                
                VerifyExchangeWords(identifier: self.identifier, key: self.receivedKey, exchangeResult: self.exchangeResult)
            }
            .padding()
        }
        .presentationDetents([.large])
    }

    // MARK: - Key material

    private var keyMaterialSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            self.keyRow(
                label: "IDENTITY KEY · P-256",
                hex: self.identityHex,
                color: Color(red: 58/255, green: 92/255, blue: 191/255)
            )

            if let result = self.exchangeResult {
                self.keyRow(
                    label: "ML-KEM-1024 · POST-QUANTUM",
                    hex: self.mlkemHex(result),
                    color: Color(red: 90/255, green: 74/255, blue: 176/255)
                )
            }
        }
    }

    private func keyRow(label: String, hex: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(.system(size: 9, design: .monospaced).weight(.semibold))
                .foregroundStyle(color)
                .kerning(0.5)
            Text(hex)
                .font(.system(size: 13, design: .monospaced).weight(.medium))
                .foregroundStyle(.primary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.07))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(color.opacity(0.25), lineWidth: 0.5)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var identityHex: String {
        guard let material = self.receivedKey.material else { return "—" }
        let fp = material.sha256
        return fp.prefix(12).map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    private func mlkemHex(_ result: ExchangeManager.HybridExchangeResult) -> String {
        result.peerCiphertext.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}

struct VerifyExchangeWords: View {
    let passphraseGenerator = Manager.PassphraseGenerator()
    let keyManager = Manager.Key()

    let identifier: String
    let key: Contact.Draft.Key
    let exchangeResult: ExchangeManager.HybridExchangeResult?

    @Environment(ContactManager.self) private var contactManager: ContactManager?
    @Environment(ExchangeManager.self) private var exchangeManager: ExchangeManager?

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Confirm these words match your contact's screen — in the same order.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            let dicewareKey = self.deriveDicewareKey()
            let words = (self.passphraseGenerator.generate(separator: "-", sharedKey: dicewareKey))
                .components(separatedBy: "-")

            VStack(spacing: 12) {
                ForEach(Array(words.enumerated()), id: \.offset) { idx, word in
                    HStack {
                        Text("\(idx + 1)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(width: 20, alignment: .trailing)
                        Text(word)
                            .font(.system(size: 20, design: .monospaced).weight(.semibold))
                    }
                }
            }

            if self.exchangeResult != nil {
                Label("Quantum-resistant exchange", systemImage: "shield.checkered")
                    .font(.caption2)
                    .foregroundStyle(Color.occultaVerified)
            }

            Button("Confirm") {
                do {
                    try self.contactManager?.update(key: self.key, for: self.identifier)
                } catch { }
                self.exchangeManager?.confirm()
                self.dismiss()
            }
            .buttonStyle(.borderedProminent)
            .tint(.occultaAccent)
            .frame(maxWidth: .infinity)
        }
    }

    private func deriveDicewareKey() -> Data? {
        if let result = self.exchangeResult {
            let material = QuantumKeyMaterial(from: result)
            return self.keyManager.createDicewareKey(
                peerP256Material: result.peerP256PublicKey,
                quantumMaterial: material,
                ourNonce: result.ourNonce,
                peerNonce: result.peerNonce
            )?.withUnsafeBytes { Data($0) }
        } else {
            return self.keyManager.createSharedSecret(using: self.key.material)?.withUnsafeBytes { Data($0) }
        }
    }
}

#Preview {
    VerifyExchangeWords(
        identifier: UUID().uuidString,
        key: Contact.Draft.Key(material: nil, owner: Data.randomBytes(32), date: "")!,
        exchangeResult: nil
    )
}
