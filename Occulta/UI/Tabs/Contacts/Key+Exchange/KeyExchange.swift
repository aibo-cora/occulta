//
//  KeyExchange.swift
//  Occulta
//
//  Created by Yura on 11/25/25.
//

import SwiftData
import SwiftUI
import CryptoKit

struct KeyExchange: View {
    @State private var exchangeManager: ExchangeManager = .init()
    @State private var displayingInfo: Bool = true
    @State private var confirmingPayload: ExchangeManager.ExchangePhase.Payload?

    @Query(Contact.Profile.descriptor) var contacts: [Contact.Profile]

    @Environment(ContactManager.self) private var contactManager: ContactManager?
    @Environment(\.dismiss) private var dismiss

    init(identifier: String) {
        let predicate = #Predicate<Contact.Profile> {
            $0.identifier == identifier
        }
        self._contacts = Query(filter: predicate)
    }

    var name: String {
        self.contacts.first?.givenName.decrypt() ?? "Anonymous"
    }

    var identifier: String {
        self.contacts.first?.identifier ?? ""
    }

    var body: some View {
        Group {
            if let payload = self.confirmingPayload {
                ConfirmationView(payload: payload, identifier: self.identifier, manager: self.exchangeManager)
            } else if self.exchangeManager.phase != .resting {
                KeyExchangeLiveView(manager: self.exchangeManager)
            } else {
                if self.exchangeManager.isExchangePossible {
                    VStack(spacing: 24) {
                        if self.displayingInfo {
                            VStack(alignment: .leading, spacing: 16) {
                                Text("Exchange keys with **\(self.name)**")
                                    .font(.title3.weight(.semibold))

                                Divider()

                                VStack(alignment: .leading, spacing: 12) {
                                    Label("Allow **Nearby Interaction** if prompted.", systemImage: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.primary)
                                        .symbolRenderingMode(.hierarchical)
                                        .tint(.occultaWarn)

                                    Label("Allow **Finding and Connecting** to nearby devices if prompted.", systemImage: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.primary)
                                        .symbolRenderingMode(.hierarchical)
                                        .tint(.occultaWarn)
                                }

                                Divider()

                                Text("Bring both devices within 25 cm to begin.")
                                    .foregroundStyle(.secondary)
                                    .font(.subheadline)
                            }
                            .padding()
                        }

                        HStack(spacing: 16) {
                            Button {
                                self.exchangeManager.start()
                            } label: {
                                Label("Exchange Keys", systemImage: "key.horizontal")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.occultaAccent)

                            Button {
                                self.displayingInfo.toggle()
                            } label: {
                                Image(systemName: self.displayingInfo ? "info.bubble.fill" : "info.bubble")
                            }
                            .tint(.occultaAccent)
                        }
                        .padding(.horizontal)
                    }
                } else {
                    Text("Key exchange requires a UWB chip (iPhone 11 or later).")
                        .padding()
                        .foregroundStyle(Color.occultaDanger)
                }
            }
        }
        .toolbar(.hidden, for: .tabBar)
        .onChange(of: self.exchangeManager.phase) { _, newPhase in
            if case .confirming(let payload) = newPhase {
                self.confirmingPayload = payload
            }
            if newPhase == .timedOut || newPhase == .failed {
                self.confirmingPayload = nil
                self.exchangeManager.finish()
                self.dismiss()
            }
        }
    }

    // MARK: - Confirmation screen

    private struct ConfirmationView: View {
        let payload: ExchangeManager.ExchangePhase.Payload
        let identifier: String
        let manager: ExchangeManager

        private let keyManager = Manager.Key()
        private let passphraseGenerator = Manager.PassphraseGenerator()

        @Environment(ContactManager.self) private var contactManager: ContactManager?
        @Environment(\.dismiss) private var dismiss
        
        var identity: Data {
            let identity = try? Manager.Key().retrieveIdentity()
            let compareWith = identity ?? Data()
            
            return compareWith
        }

        var body: some View {
            ScrollView {
                VStack(alignment: .center, spacing: 20) {
                    self.keyRow(label: "MY IDENTITY KEY · P-256 SHA256", hex: self.identity.sha256.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " "), color: Color(red: 58/255, green: 92/255, blue: 191/255))
                    
                    self.keyRow(label: "PEER IDENTITY KEY · P-256 SHA256", hex: self.payload.classicalKey.sha256.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " "), color: Color(red: 58/255, green: 92/255, blue: 191/255))

                    Divider()

                    Text("Confirm these words match your contact's screen — in the same order.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    VStack(spacing: 12) {
                        ForEach(Array(self.words.enumerated()), id: \.offset) { idx, word in
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

                    if self.payload.hybridResult != nil {
                        Label("Quantum-resistant exchange", systemImage: "shield.checkered")
                            .font(.caption2)
                            .foregroundStyle(Color.occultaVerified)
                    }

                    Button("Confirm") {
                        self.save()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.occultaAccent)
                    .frame(maxWidth: .infinity)
                    
                    Button("Cancel") {
                        self.manager.finish()
                        self.dismiss()
                    }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)
                }
                .padding()
            }
            .navigationBarBackButtonHidden(true)
        }

        private var words: [String] {
            let sharedKey: Data?
            
            if let result = self.payload.hybridResult {
                let material = QuantumKeyMaterial(from: result)
                sharedKey = self.keyManager.createDicewareKey(
                    peerP256Material: result.peerP256PublicKey,
                    quantumMaterial: material,
                    ourNonce: result.ourNonce,
                    peerNonce: result.peerNonce
                )?.withUnsafeBytes { Data($0) }
            } else {
                sharedKey = self.keyManager.createSharedSecret(using: self.payload.classicalKey)?.withUnsafeBytes { Data($0) }
            }
            return self.passphraseGenerator.generate(separator: "-", sharedKey: sharedKey)
                .components(separatedBy: "-")
        }

        private func keyRow(label: String, hex: String, color: Color) -> some View {
            VStack(alignment: .center, spacing: 6) {
                Text(label)
                    .font(.system(size: 9, design: .monospaced).weight(.semibold))
                    .foregroundStyle(color)
                    .kerning(0.5)
                Text(hex)
                    .font(.system(size: 11, design: .monospaced).weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(nil)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(0.07))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(color.opacity(0.25), lineWidth: 0.5))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }

        private func save() {
            let myIdentity = (try? self.keyManager.retrieveIdentity()) ?? Data()
            let date = String(Date.now.timeIntervalSince1970)
            let quantum = self.payload.hybridResult.map {
                QuantumKeyMaterial(
                    encapsulatedSecret: $0.mlkemSecret1,
                    decapsulatedSecret: $0.mlkemSecret2,
                    ourCiphertext: $0.ourCiphertext,
                    peerCiphertext: $0.peerCiphertext
                )
            }
            if let key = Contact.Draft.Key(material: self.payload.classicalKey, owner: myIdentity, date: date, quantumKeyMaterial: quantum) {
                try? self.contactManager?.update(key: key, for: self.identifier)
            }
            self.manager.finish()
            self.dismiss()
        }
    }
}

#Preview {
    KeyExchange(identifier: UUID().uuidString)
}
