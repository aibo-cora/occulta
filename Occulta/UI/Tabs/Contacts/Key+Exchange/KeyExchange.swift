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
    @State private var showTimeoutBanner: Bool = false

    @Query(Contact.Profile.descriptor) var contacts: [Contact.Profile]

    @Environment(ContactManager.self) private var contactManager: ContactManager?

    /// - Parameter exchangeManager: injectable so tests can observe teardown without starting radios.
    init(identifier: String, exchangeManager: ExchangeManager = .init()) {
        let predicate = #Predicate<Contact.Profile> {
            $0.identifier == identifier
        }
        self._contacts = Query(filter: predicate)
        self._exchangeManager = State(initialValue: exchangeManager)
    }

    var name: String {
        self.contacts.first?.givenName.decrypt() ?? "Anonymous"
    }

    var identifier: String {
        self.contacts.first?.identifier ?? ""
    }

    private var fullName: String {
        [self.contacts.first?.givenName.decrypt(), self.contacts.first?.familyName.decrypt()]
            .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
    }

    var body: some View {
        SwiftUI.Group {
            if let payload = self.confirmingPayload {
                ConfirmationView(payload: payload, identifier: self.identifier, fullName: self.fullName, manager: self.exchangeManager)
            } else if self.exchangeManager.phase != .resting {
                KeyExchangeLiveView(manager: self.exchangeManager)
            } else {
                if self.exchangeManager.isExchangePossible {
                    VStack(spacing: 24) {
                        if self.showTimeoutBanner {
                            Label("Didn't connect — make sure both devices are within 25 cm and try again.", systemImage: "exclamationmark.triangle.fill")
                                .font(.subheadline)
                                .foregroundStyle(Color.occultaWarn)
                                .padding(.horizontal)
                        }

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
                                self.showTimeoutBanner = false
                                // The meeting check (SPEC §7) runs against this contact's card field, if it holds one.
                                let cardMeeting = self.contacts.first.flatMap { self.contactManager?.cardMeetingContext(for: $0) } ?? .none
                                self.exchangeManager.start(cardMeeting: cardMeeting)
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
                self.showTimeoutBanner = true
                self.exchangeManager.finish()
            }
        }
        // Leaving the screen must stop advertising `_peer-data-ex`, which identifies Occulta to
        // anyone scanning nearby, rather than leave it to the watchdog (hardening step 10).
        .onDisappear {
            self.exchangeManager.finish()
        }
    }

    // MARK: - Confirmation screen

    private struct ConfirmationView: View {
        let payload: ExchangeManager.ExchangePhase.Payload
        let identifier: String
        let fullName: String
        let manager: ExchangeManager

        private let keyManager = Manager.Key()
        private let passphraseGenerator = Manager.PassphraseGenerator()

        @Environment(ContactManager.self) private var contactManager: ContactManager?
        @Environment(\.dismiss) private var dismiss

        private enum SaveState { case confirming, saving, saved, failed, refusedWeaker }
        @State private var saveState: SaveState = .confirming
        /// What the in-person check found about an earlier card conversation. Held only while its screen is up;
        /// nothing about it is stored.
        @State private var cardVerdict: CardMeetingVerdict = .none

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

                    // We sent pair keys and the other phone sent none we could use: the pairing is made as before, and
                    // both people can see it here, where a phone on an older version looks the same as one whose message
                    // was interfered with. Shown on this screen only; nothing about it is stored.
                    if self.payload.offeredPairing && self.payload.pairing == nil {
                        Text("Pair keys weren't exchanged. If both phones are on the latest version, try again.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }

                    switch self.saveState {
                    case .confirming, .saving:
                        Button {
                            self.save()
                        } label: {
                            if self.saveState == .saving {
                                ProgressView().tint(.white)
                            } else {
                                Text("Confirm")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.occultaAccent)
                        .frame(maxWidth: .infinity)
                        .disabled(self.saveState == .saving)

                        Button("Cancel") {
                            self.manager.finish()
                            self.dismiss()
                        }
                        .buttonStyle(.bordered)
                        .frame(maxWidth: .infinity)
                        .disabled(self.saveState == .saving)

                    case .saved:
                        Label("Key saved", systemImage: "checkmark.circle.fill")
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(Color.occultaVerified)

                    case .refusedWeaker:
                        // A retry runs the same exchange and is refused the same way, so none is offered: the way on is a new
                        // exchange once the other person's phone can give pair keys (Bug 196).
                        Label("Not saved: the other phone gave no pair keys", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(Color.occultaDanger)

                        Text("You and this contact already share a stronger pairing than this exchange would make, so it was kept as it was. Ask them to update Occulta, then exchange keys again.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)

                        Button("Done") {
                            self.manager.finish()
                            self.dismiss()
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.occultaAccent)
                        .frame(maxWidth: .infinity)

                    case .failed:
                        Label("Couldn't save key", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(Color.occultaDanger)

                        Button("Retry") {
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
                }
                .padding()
            }
            .navigationBarBackButtonHidden(true)
            // A cover, not a pushed screen: W-11 can't be swiped away or dismissed from outside, only acknowledged.
            .fullScreenCover(isPresented: Binding(get: { self.cardVerdict != .none }, set: { _ in })) {
                CardMeetingVerdictView(verdict: self.cardVerdict, identifier: self.identifier, fullName: self.fullName) {
                    self.cardVerdict = .none
                    Task { @MainActor in self.dismiss() }
                }
            }
        }

        private var words: [String] {
            let sharedKey: Data?
            
            if let pairing = self.payload.pairing {
                // A pair-key exchange: the words cover both phones' pair keys and the identity ECDH (Bug 196, stage 2), so a
                // key a man in the middle added, removed or swapped changes them. A failure to derive shows words that
                // cannot match, and `save()` refuses the pairing.
                sharedKey = pairing.wordsKey(
                    withPeer: self.payload.classicalKey, quantum: self.payload.hybridResult.map(QuantumKeyMaterial.init(from:)),
                    using: self.keyManager
                )
            } else if let result = self.payload.hybridResult {
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
            self.saveState = .saving

            switch KeyExchange.saveExchange(self.payload, for: self.identifier, in: self.contactManager, using: self.keyManager) {
            case .refusedWeaker:
                self.saveState = .refusedWeaker
            case .failed:
                self.saveState = .failed
            case .saved:
                // After the key is saved and before `finish()`, which discards the peer's proof (SPEC §7).
                let verdict = self.manager.cardMeetingVerdict(for: self.payload)

                self.saveState = .saved
                self.manager.finish()

                if verdict == .none {
                    Task {
                        try? await Task.sleep(for: .seconds(1))
                        self.dismiss()
                    }
                } else {
                    // The exchange closes from the verdict screen: after "I understand", or when W-12 is closed.
                    self.cardVerdict = verdict
                }
            }
        }
    }
}

extension KeyExchange {

    /// What Save did, for the confirmation screen to show.
    enum SaveOutcome: Equatable {
        case saved
        /// The contact's pairing has pair keys and this exchange gave none: nothing is saved, and the exchange can be run again.
        case refusedWeaker
        case failed
    }

    /// Saves a confirmed exchange: derives the routing key, builds the key row and hands both to `update(key:for:pairing:)`.
    /// Anything it can't do leaves nothing saved.
    @MainActor
    static func saveExchange(
        _ payload: ExchangeManager.ExchangePhase.Payload, for identifier: String,
        in contactManager: ContactManager?, using keyManager: any KeyManagerProtocol
    ) -> SaveOutcome {
        do {
            let myIdentity = try keyManager.retrieveIdentity()
            let date = String(Date.now.timeIntervalSince1970)
            let quantum = payload.hybridResult.map {
                QuantumKeyMaterial(
                    encapsulatedSecret: $0.mlkemSecret1,
                    decapsulatedSecret: $0.mlkemSecret2,
                    ourCiphertext: $0.ourCiphertext,
                    peerCiphertext: $0.peerCiphertext
                )
            }

            // Both phones sent a `pairing` field, so both hold a routing key and a pair of keys and derive the same one
            // (Bug 196). One we can't derive is not a weaker pairing to save: nothing is saved, and the screen says so.
            var pairing = PairingState.empty
            if let offer = payload.pairing {
                guard let derived = offer.routingKey(withPeer: payload.classicalKey, quantum: quantum, using: keyManager) else {
                    return .failed
                }
                pairing = .paired(routingKey: derived, keys: offer.pairKeys)
            }

            guard let key = Contact.Draft.Key(
                material: payload.classicalKey, owner: myIdentity, date: date, quantumKeyMaterial: quantum,
                pairing: pairing
            ) else {
                return .failed
            }

            // No manager is not a save: the caller discards the exchange's keys right after "saved".
            guard let contactManager else { return .failed }
            try contactManager.update(key: key, for: identifier, pairing: payload.pairing)
            return .saved
        } catch ContactManager.Errors.pairingWouldBeWeaker {
            return .refusedWeaker
        } catch {
            return .failed
        }
    }
}

#Preview {
    KeyExchange(identifier: UUID().uuidString)
}
