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
    /// Why the last exchange ended without a result. Shown on this screen only; nothing is stored.
    @State private var notice: Notice?

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
                        if let notice = self.notice {
                            Label(notice.text, systemImage: "exclamationmark.triangle.fill")
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
                                self.notice = nil
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
            if let notice = KeyExchange.notice(for: newPhase) {
                self.confirmingPayload = nil
                self.notice = notice
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

        private enum SaveState { case confirming, saving, saved, failed, refusedWeaker, refusedNoQuantum }
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

                    // This phone sent a quantum-resistant key and none came back: an older phone, or a message that was
                    // interfered with, look the same here (Bug 199). Shown on this screen only; nothing about it is stored.
                    if self.payload.offeredQuantum && self.payload.hybridResult == nil {
                        Text("Quantum-resistant keys weren't exchanged. The other phone may be on an older version of iOS or Occulta. If you expected it to be up to date, cancel and try again.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
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

                    case .refusedNoQuantum:
                        // As above, a retry runs the same exchange. The way on is the person's choice: revoke, then exchange again.
                        Label("Not saved: no quantum-resistant key in this exchange", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(Color.occultaDanger)

                        Text("You and this contact already share a quantum-resistant pairing, and this exchange had no ML-KEM key, so it was kept as it was. The other phone may be on an older version of iOS, or the exchange may have been interfered with. To save a classical pairing on purpose, use Revoke Key in this contact's details, then exchange keys again.")
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
            KeyExchange.words(for: self.payload, using: self.keyManager, generator: self.passphraseGenerator)
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
            case .refusedNoQuantum:
                self.saveState = .refusedNoQuantum
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

    /// The key the verification words come from. Every shape of exchange has one derivation, over both nonces and every
    /// message of the exchange, so what was added, removed or changed in transit changes the words, ML-KEM included
    /// (Bugs 198 and 199). An exchange whose peer did not commit to its nonce never reaches this screen. Nil when the key
    /// manager can't derive it.
    @MainActor
    static func wordsKey(for payload: ExchangeManager.ExchangePhase.Payload, using keyManager: any KeyManagerProtocol) -> Data? {
        let quantum = payload.hybridResult.map(QuantumKeyMaterial.init(from:))

        if let pairing = payload.pairing {
            return pairing.wordsKey(withPeer: payload.classicalKey, quantum: quantum, using: keyManager)
        }
        return keyManager.createCommittedDicewareKey(
            peerP256Material: payload.classicalKey, pairwiseECDH: nil, quantumMaterial: quantum,
            ourNonce: payload.committed.ourNonce, peerNonce: payload.committed.peerNonce,
            exchangeTranscript: payload.committed.transcript
        )?.withUnsafeBytes { Data($0) }
    }

    @MainActor
    static func words(
        for payload: ExchangeManager.ExchangePhase.Payload, using keyManager: any KeyManagerProtocol,
        generator: Manager.PassphraseGenerator? = nil
    ) -> [String] {
        (generator ?? Manager.PassphraseGenerator()).generate(separator: "-", sharedKey: self.wordsKey(for: payload, using: keyManager))
            .components(separatedBy: "-")
    }

    /// How an exchange ended without a result, for the screen to say. Each has words of its own: a failed exchange is a message that
    /// did not check out, which the person should not read as poor ranging and simply retry.
    enum Notice: Equatable {
        case timedOut, failed, peerNeedsUpdate

        var text: String {
            switch self {
            case .timedOut:
                "Didn't connect — make sure both devices are within 25 cm and try again."
            case .failed:
                "This exchange didn't check out, so nothing was saved. Try again. If it happens again, try somewhere else."
            case .peerNeedsUpdate:
                // The same words whatever the cause: a phone on an older version, or a message that was interfered with, look the
                // same to this one.
                "The other phone needs to update Occulta to exchange keys with this one."
            }
        }
    }

    /// The notice for a phase that ends an exchange, nil for any other.
    static func notice(for phase: ExchangeManager.ExchangePhase) -> Notice? {
        switch phase {
        case .timedOut: .timedOut
        case .failed: .failed
        case .peerNeedsUpdate: .peerNeedsUpdate
        default: nil
        }
    }

    /// What Save did, for the confirmation screen to show.
    enum SaveOutcome: Equatable {
        case saved
        /// The contact's pairing has pair keys and this exchange gave none: nothing is saved, and the exchange can be run again.
        case refusedWeaker
        /// The contact's pairing is hybrid and this exchange gave no ML-KEM key (Bug 199): nothing is saved, and revoking the
        /// contact's key first saves a classical pairing on purpose.
        case refusedNoQuantum
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
        } catch ContactManager.Errors.pairingWouldLoseQuantum {
            return .refusedNoQuantum
        } catch {
            return .failed
        }
    }
}

#Preview {
    KeyExchange(identifier: UUID().uuidString)
}
