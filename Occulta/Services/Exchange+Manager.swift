//
//  Exchange+Manager.swift
//  Occulta
//
//  Sequential hybrid post-quantum key exchange.
//  Roles are determined at MC connect by comparing UUID display names —
//  lexicographically lower = initiator. Initiator sends first at every step;
//  responder waits and replies. Eliminates all parallel send races and the
//  MITM timing window present in the previous parallel design.
//
//  ⚠️ Backward compatibility contract:
//  - All messages use `version: .v1` on the wire.
//  - Classical (P-256-only) exchanges use hybridResult: nil in the Payload.
//  - If PQProvider is nil (iOS < 26), exchange is classical-only.
//  - If peer sends identity without `encapsulationKey`, exchange is classical-only.
//
//  ⚠️ Thread safety:
//  MC and NI delegate callbacks arrive on arbitrary background threads.
//  All state mutations are dispatched to the main queue via `DispatchQueue.main.async`.
//  Main queue is serial + FIFO, preserving MC's per-peer ordering guarantee.
//  This also ensures @Observable property changes are UI-safe.
//

import Foundation
import NearbyInteraction
import MultipeerConnectivity
import os

@Observable
class ExchangeManager: NSObject {
    private var nearbySession: NISession?
    private var lastNIConfiguration: NINearbyPeerConfiguration?

    private var multipeerSession: MCSession?
    private var receivedDiscoveryTokens: [NIDiscoveryToken: MCPeerID] = [:]

    private let serviceType = "peer-data-ex"
    private let log = Logger(subsystem: "com.occulta.multipeer", category: "multipeer")

    private var watchdog: DispatchSourceTimer?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?

    var isExchangePossible: Bool {
        NISession.deviceCapabilities.supportsPreciseDistanceMeasurement
    }

    // MARK: - Sequential protocol state

    /// Peer we connected to via MC. Identity/ciphertext from any other peer is rejected.
    private var connectedPeerID: MCPeerID?
    /// True if our UUID display name sorts below the peer's — set once at MC connect.
    private var isInitiator: Bool = false
    /// Drives the sequential send/wait ordering for both identity and quantum phases.
    private var exchangeStatus: ExchangeStatus?
    /// Identity message that arrived before NI confirmed proximity (exchangeStatus was nil).
    /// Replayed immediately after NI fires and sets the initial status.
    private var bufferedIdentityMessage: (peerID: MCPeerID, data: Data)?

    // MARK: - PQ exchange state

    /// PQ provider — nil on iOS < 26.
    private let pqProvider: PQProvider? = PQProviderFactory.create()
    /// Our 16-byte nonce, generated at session start and committed in discovery.
    private var ourNonce: Data?
    /// Peer's nonce from their discovery message. Nil if peer is v1.
    private var peerNonce: Data?
    /// Opaque handle to our SE-backed ML-KEM-1024 private key.
    private var privateKeyHandle: Any?
    /// Peer's P-256 identity key — stored for hybrid result assembly.
    private var peerIdentity: Data?
    /// Our ML-KEM encapsulation key, included in the identity message.
    var encapsulationKeyData: Data?

    // MARK: - Exchange status state machine

    private struct QuantumPayload {
        let secret: Data
        let ciphertext: Data
    }

    private enum ExchangeStatus {
        /// About to send our identity. `ours` is pre-computed only for the responder —
        /// who encapsulates the initiator's ML-KEM key upon receiving their identity,
        /// before sending back their own.
        case sendingMyIdentity(ours: QuantumPayload?)
        /// Sent our identity; waiting for the peer's.
        case waitingForPeerIdentity
        /// About to send our ML-KEM ciphertext. `theirs` is set only for the responder —
        /// who already decapsulated the initiator's ciphertext before sending theirs.
        case sendingMyQuantum(ours: QuantumPayload, theirs: QuantumPayload?)
        /// Sent our ciphertext; waiting for the peer's.
        case waitingForPeerQuantum(ours: QuantumPayload)
        /// Both ciphertexts exchanged — ready to assemble the final result.
        case complete(ours: QuantumPayload, theirs: QuantumPayload)
        /// Terminal state for classical-only exchanges; prevents re-processing stray messages.
        case done

    }

    // MARK: - Result type

    struct HybridExchangeResult: Equatable {
        let peerP256PublicKey: Data
        let mlkemSecret1: Data
        let mlkemSecret2: Data
        let ourNonce: Data
        let peerNonce: Data
        let ourCiphertext: Data
        let peerCiphertext: Data
    }

    // MARK: - Exchange phase

    enum ExchangePhase: Equatable {
        case resting
        case searching
        case found
        case connected
        case identityExchanged(fingerprint: Data)
        case mlKemExchanged(Payload)
        case confirming(Payload)
        case complete
        case timedOut
        case failed

        struct Payload: Equatable {
            let fingerprint: Data
            let classicalKey: Data
            let hybridResult: HybridExchangeResult?
        }
    }

    var phase: ExchangePhase = .resting
    var distance: Float? = nil
    var direction: SIMD3<Float>? = nil

    override init() {
        super.init()
    }

    private func setupMC() {
        let peerID = MCPeerID(displayName: UUID().uuidString)

        self.multipeerSession = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
        self.multipeerSession?.delegate = self

        self.advertiser = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: nil, serviceType: self.serviceType)
        self.browser = MCNearbyServiceBrowser(peer: peerID, serviceType: self.serviceType)

        self.advertiser?.delegate = self
        self.browser?.delegate = self
    }

    func start() {
        self.finish()
        self.nearbySession = NISession()
        self.nearbySession?.delegate = self

        self.setupMC()

        let keyManager = Manager.Key()
        self.ourNonce = keyManager.generateExchangeNonce()

        if let provider = self.pqProvider, let keyPair = provider.generateKeyPair() {
            self.privateKeyHandle = keyPair.privateKeyHandle
            self.encapsulationKeyData = keyPair.publicKeyData
            #if DEBUG
            debugPrint("[KE] ML-KEM keypair generated (\(self.encapsulationKeyData?.count ?? 0) bytes)")
            #endif
        }

        self.phase = .searching

        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self, case .searching = self.phase else { return }
            self.advertiser?.startAdvertisingPeer()
            self.browser?.startBrowsingForPeers()
            self.scheduleWatchdog()
            #if DEBUG
            debugPrint("[KE] Advertising and browsing started")
            #endif
        }
    }

    func finish() {
        self.teardownSessions()
        self.phase = .resting
    }

    func confirm() {
        self.phase = .complete
    }

    private func teardownSessions() {
        self.watchdog?.cancel()
        self.watchdog = nil

        self.nearbySession?.invalidate()
        self.nearbySession = nil
        self.lastNIConfiguration = nil

        self.advertiser?.stopAdvertisingPeer()
        self.advertiser?.delegate = nil
        self.advertiser = nil

        self.browser?.stopBrowsingForPeers()
        self.browser?.delegate = nil
        self.browser = nil

        self.multipeerSession?.disconnect()
        self.multipeerSession?.delegate = nil
        self.multipeerSession = nil

        // ⚠️ Release SE-backed ML-KEM private key handle.
        // For SecureEnclave.MLKEM1024, releasing the reference means the SE key
        // can no longer be used. No explicit SE delete needed — CryptoKit SE keys
        // are accessed via their object reference, not a keychain tag.
        self.privateKeyHandle = nil

        self.connectedPeerID = nil
        self.isInitiator = false
        self.exchangeStatus = nil
        self.bufferedIdentityMessage = nil
        self.ourNonce = nil
        self.peerNonce = nil
        self.peerIdentity = nil
        self.encapsulationKeyData = nil
        self.distance = nil
        self.direction = nil

        #if DEBUG
        debugPrint("[KE] Exchange sessions torn down")
        #endif
    }

    // MARK: - Watchdog

    private func scheduleWatchdog() {
        self.watchdog?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 30)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            #if DEBUG
            debugPrint("[KE] Watchdog fired — no NI updates in 30s")
            #endif
            self.phase = .timedOut
            self.teardownSessions()
        }
        timer.resume()
        self.watchdog = timer
    }

    // MARK: - Send helpers

    private func sendIdentity(to peerID: MCPeerID) {
        guard let session = self.multipeerSession,
              let token = self.nearbySession?.discoveryToken else { return }
        do {
            let keyManager = Manager.Key()
            #if targetEnvironment(simulator)
            let keyingMaterial = keyManager.fixedX963
            #else
            let keyingMaterial = try keyManager.retrieveIdentity()
            #endif
            let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
            let exchange = Exchange(
                id: UUID().uuidString,
                token: archivedToken,
                version: .v1,
                identity: keyingMaterial,
                encapsulationKey: self.encapsulationKeyData
            )
            let encoded = try JSONEncoder().encode(exchange)
            try session.send(encoded, toPeers: [peerID], with: .reliable)
            #if DEBUG
            debugPrint("[KE] Identity sent to \(peerID.displayName)")
            #endif
        } catch {
            #if DEBUG
            debugPrint("[KE] Identity send failed: \(error)")
            #endif
        }
    }

    private func sendCiphertext(_ ciphertext: Data, to peerID: MCPeerID) {
        guard let session = self.multipeerSession,
              let token = self.nearbySession?.discoveryToken else { return }
        do {
            let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
            let exchange = Exchange(
                id: UUID().uuidString,
                token: archivedToken,
                version: .v1,
                ciphertext: ciphertext
            )
            let encoded = try JSONEncoder().encode(exchange)
            try session.send(encoded, toPeers: [peerID], with: .reliable)
            #if DEBUG
            debugPrint("[KE] Ciphertext sent to \(peerID.displayName)")
            #endif
        } catch {
            #if DEBUG
            debugPrint("[KE] Ciphertext send failed: \(error)")
            #endif
        }
    }

    // MARK: - Final assembly

    private func assembleHybridResult(ours: QuantumPayload, theirs: QuantumPayload) {
        guard let peerIdentity, let ourNonce, let peerNonce else { return }

        let result = HybridExchangeResult(
            peerP256PublicKey: peerIdentity,
            mlkemSecret1: ours.secret,
            mlkemSecret2: theirs.secret,
            ourNonce: ourNonce,
            peerNonce: peerNonce,
            ourCiphertext: ours.ciphertext,
            peerCiphertext: theirs.ciphertext
        )

        #if DEBUG
        debugPrint("[KE] Hybrid exchange complete")
        #endif

        let payload = ExchangePhase.Payload(
            fingerprint: peerIdentity.sha256,
            classicalKey: peerIdentity,
            hybridResult: result
        )
        self.phase = .mlKemExchanged(payload)
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self, case .mlKemExchanged(let p) = self.phase else { return }
            self.phase = .confirming(p)
        }
    }

    // MARK: - Phase handlers (always called on main queue)

    private func handleSessionStateChange(peerID: MCPeerID, state: MCSessionState) {
        guard state == .connected else { return }

        self.phase = .found
        self.connectedPeerID = peerID
        self.isInitiator = self.multipeerSession!.myPeerID.displayName < peerID.displayName

        #if DEBUG
        debugPrint("[KE] MC connected: \(peerID.displayName) — role: \(self.isInitiator ? "initiator" : "responder")")
        #endif

        guard let discoveryToken = self.nearbySession?.discoveryToken else {
            #if DEBUG
            debugPrint("[KE] Discovery token unavailable — NI session not ready")
            #endif
            return
        }

        do {
            let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: discoveryToken, requiringSecureCoding: true)
            let exchange = Exchange(
                id: UUID().uuidString,
                token: archivedToken,
                version: .v1,
                nonce: self.ourNonce
            )
            let encoded = try JSONEncoder().encode(exchange)
            try self.multipeerSession?.send(encoded, toPeers: [peerID], with: .reliable)
            #if DEBUG
            debugPrint("[KE] Discovery token sent to \(peerID.displayName)")
            #endif
        } catch {
            #if DEBUG
            debugPrint("[KE] Discovery send failed: \(error)")
            #endif
        }
    }

    private func handleReceivedData(_ data: Data, from peerID: MCPeerID) {
        do {
            let decoded = try JSONDecoder().decode(Exchange.self, from: data)

            // MARK: Phase 1 — Discovery (token + optional nonce)

            if decoded.isDiscovery {
                let token: NIDiscoveryToken
                do {
                    guard let unarchived = try NSKeyedUnarchiver.unarchivedObject(
                        ofClass: NIDiscoveryToken.self, from: decoded.token
                    ) else {
                        #if DEBUG
                        debugPrint("[KE] Discovery: token unarchive returned nil")
                        #endif
                        return
                    }
                    token = unarchived
                } catch {
                    #if DEBUG
                    debugPrint("[KE] Discovery: token unarchive threw: \(error)")
                    #endif
                    return
                }

                if let nonce = decoded.nonce, nonce.count == 16 {
                    self.peerNonce = nonce
                }

                self.receivedDiscoveryTokens[token] = peerID

                #if DEBUG
                debugPrint("[KE] Discovery token received from \(peerID.displayName)")
                #endif

                let configuration = NINearbyPeerConfiguration(peerToken: token)
                self.lastNIConfiguration = configuration
                self.nearbySession?.run(configuration)
                return
            }

            // MARK: Phase 2 — Identity (P-256 + optional ML-KEM encapsulation key)

            if decoded.isIdentity {
                guard peerID == self.connectedPeerID else {
                    #if DEBUG
                    debugPrint("[KE] MITM guard: identity from unexpected peer \(peerID.displayName)")
                    #endif
                    return
                }
                switch self.exchangeStatus {
                case .waitingForPeerIdentity, .sendingMyIdentity:
                    break
                case nil:
                    // NI hasn't confirmed proximity yet — buffer and replay when it does.
                    self.bufferedIdentityMessage = (peerID: peerID, data: data)
                    return
                default:
                    #if DEBUG
                    debugPrint("[KE] Identity received but not waiting — ignoring")
                    #endif
                    return
                }
                guard let peersP256Key = decoded.identity, peersP256Key.count == 65 else { return }

                #if DEBUG
                debugPrint("[KE] Identity received from \(peerID.displayName) — encapsulationKey: \(decoded.encapsulationKey != nil)")
                #endif

                self.peerIdentity = peersP256Key
                self.phase = .identityExchanged(fingerprint: peersP256Key.sha256)

                if let peerEncapKey = decoded.encapsulationKey,
                   let provider = self.pqProvider,
                   self.privateKeyHandle != nil {
                    // PQ path
                    #if DEBUG
                    debugPrint("[KE] PQ path — encapsulating peer's ML-KEM key")
                    #endif
                    guard let result = provider.encapsulate(peerPublicKeyData: peerEncapKey) else { return }
                    let ours = QuantumPayload(secret: result.sharedSecret, ciphertext: result.ciphertext)

                    if case .sendingMyIdentity = self.exchangeStatus {
                        // Backward compat: old peer sent identity in parallel before our send Task fired.
                        // Store quantum now; the existing Task will chain the ciphertext send after identity.
                        self.exchangeStatus = .sendingMyIdentity(ours: ours)
                    } else if self.isInitiator {
                        // Received responder's identity → send our ciphertext.
                        self.exchangeStatus = .sendingMyQuantum(ours: ours, theirs: nil)
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: .seconds(3))
                            guard let self,
                                  case .sendingMyQuantum(let ours, _) = self.exchangeStatus else { return }
                            self.sendCiphertext(ours.ciphertext, to: peerID)
                            self.exchangeStatus = .waitingForPeerQuantum(ours: ours)
                        }
                    } else {
                        // Received initiator's identity → send our identity (quantum pre-computed).
                        self.exchangeStatus = .sendingMyIdentity(ours: ours)
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: .seconds(3))
                            guard let self,
                                  case .sendingMyIdentity(let ours?) = self.exchangeStatus else { return }
                            self.sendIdentity(to: peerID)
                            self.exchangeStatus = .waitingForPeerQuantum(ours: ours)
                        }
                    }
                } else {
                    // Classical fallback: no PQ provider, no private key, or peer has no encapsulation key.
                    #if DEBUG
                    debugPrint("[KE] Classical path — provider: \(self.pqProvider != nil), privateKey: \(self.privateKeyHandle != nil), peerKey: \(decoded.encapsulationKey != nil)")
                    #endif

                    if case .sendingMyIdentity = self.exchangeStatus {
                        // Backward compat: old peer sent identity in parallel.
                        // peerIdentity is stored; the existing Task will confirm after sending.
                    } else if self.isInitiator {
                        // Already sent identity at NI fire — just confirm on receiving peer's.
                        self.exchangeStatus = .done
                        let payload = ExchangePhase.Payload(
                            fingerprint: peersP256Key.sha256,
                            classicalKey: peersP256Key,
                            hybridResult: nil
                        )
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: .seconds(3))
                            guard let self else { return }
                            self.phase = .mlKemExchanged(payload)
                            try? await Task.sleep(for: .seconds(3))
                            guard case .mlKemExchanged(let p) = self.phase else { return }
                            self.phase = .confirming(p)
                        }
                    } else {
                        // Send our identity in response, then confirm.
                        self.exchangeStatus = .done
                        let payload = ExchangePhase.Payload(
                            fingerprint: peersP256Key.sha256,
                            classicalKey: peersP256Key,
                            hybridResult: nil
                        )
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: .seconds(3))
                            guard let self else { return }
                            self.sendIdentity(to: peerID)
                            try? await Task.sleep(for: .seconds(3))
                            self.phase = .mlKemExchanged(payload)
                            try? await Task.sleep(for: .seconds(3))
                            guard case .mlKemExchanged(let p) = self.phase else { return }
                            self.phase = .confirming(p)
                        }
                    }
                }
                return
            }

            // MARK: Phase 3 — Ciphertext (ML-KEM ciphertext for decapsulation)

            if decoded.isCiphertext {
                let ours: QuantumPayload
                if case .waitingForPeerQuantum(let o) = self.exchangeStatus {
                    ours = o
                } else if case .sendingMyQuantum(let o, nil) = self.exchangeStatus {
                    // Backward compat: old peer sent ciphertext before our send Task fired.
                    ours = o
                } else {
                    #if DEBUG
                    debugPrint("[KE] Ciphertext received but not waiting — ignoring")
                    #endif
                    return
                }
                guard let ciphertext = decoded.ciphertext,
                      let handle = self.privateKeyHandle,
                      let provider = self.pqProvider else { return }

                #if DEBUG
                debugPrint("[KE] Peer's ciphertext received from \(peerID.displayName)")
                #endif

                guard let secret = provider.decapsulate(ciphertext: ciphertext, privateKeyHandle: handle) else {
                    #if DEBUG
                    debugPrint("[KE] Decapsulation failed")
                    #endif
                    return
                }

                // ⚠️ Release SE private key — its only purpose is fulfilled.
                self.privateKeyHandle = nil
                let theirs = QuantumPayload(secret: secret, ciphertext: ciphertext)

                #if DEBUG
                debugPrint("[KE] Decapsulation succeeded")
                #endif

                if self.isInitiator {
                    if case .sendingMyQuantum = self.exchangeStatus {
                        // Backward compat: arrived before our send Task fired.
                        // Store theirs now; the Task will assemble after sending.
                        self.exchangeStatus = .sendingMyQuantum(ours: ours, theirs: theirs)
                    } else {
                        self.exchangeStatus = .complete(ours: ours, theirs: theirs)
                        self.assembleHybridResult(ours: ours, theirs: theirs)
                    }
                } else {
                    // Received initiator's ciphertext → send ours.
                    self.exchangeStatus = .sendingMyQuantum(ours: ours, theirs: theirs)
                    Task { @MainActor [weak self] in
                        try? await Task.sleep(for: .seconds(3))
                        guard let self,
                              case .sendingMyQuantum(let ours, let theirs?) = self.exchangeStatus else { return }
                        self.sendCiphertext(ours.ciphertext, to: peerID)
                        self.exchangeStatus = .complete(ours: ours, theirs: theirs)
                        self.assembleHybridResult(ours: ours, theirs: theirs)
                    }
                }
                return
            }
        } catch {
            #if DEBUG
            debugPrint("[KE] Exchange decode failed: \(error)")
            #endif
        }
    }

    private func handleNearbyObjectsUpdate(_ nearbyObjects: [NINearbyObject]) {
        // Any NI update proves the subsystem is alive — reset watchdog before distance filter.
        self.scheduleWatchdog()

        for object in nearbyObjects {
            if let d = object.distance { self.distance = d }
            if let dir = object.direction { self.direction = dir }

            guard let distance = object.distance, distance.isLessThanOrEqualTo(0.25) else { continue }

            if self.phase == .found || self.phase == .searching { self.phase = .connected }

            #if DEBUG
            debugPrint("[KE] Object in range")
            #endif

            let token = object.discoveryToken
            guard let peer = self.receivedDiscoveryTokens[token] else { continue }

            #if DEBUG
            debugPrint("[KE] Discovery token matches peer: \(peer.displayName)")
            #endif

            // Protocol starts exactly once.
            guard self.exchangeStatus == nil else { continue }

            if self.isInitiator {
                self.exchangeStatus = .sendingMyIdentity(ours: nil)
                #if DEBUG
                debugPrint("[KE] Initiator — sending identity in 3s")
                #endif
                Task { @MainActor [weak self] in
                    try? await Task.sleep(for: .seconds(3))
                    guard let self, case .sendingMyIdentity(let ours) = self.exchangeStatus else { return }
                    self.sendIdentity(to: peer)
                    if let ours {
                        // Backward compat: old peer sent identity in parallel, quantum already computed.
                        // Chain ciphertext send directly — skip waitingForPeerIdentity.
                        self.exchangeStatus = .sendingMyQuantum(ours: ours, theirs: nil)
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: .seconds(3))
                            guard let self,
                                  case .sendingMyQuantum(let ours, let theirs) = self.exchangeStatus else { return }
                            self.sendCiphertext(ours.ciphertext, to: peer)
                            if let theirs {
                                // Peer's ciphertext arrived before we sent ours — assemble now.
                                self.exchangeStatus = .complete(ours: ours, theirs: theirs)
                                self.assembleHybridResult(ours: ours, theirs: theirs)
                            } else {
                                self.exchangeStatus = .waitingForPeerQuantum(ours: ours)
                            }
                        }
                    } else if let peerIdentity = self.peerIdentity {
                        // Backward compat: classical path, old peer sent identity in parallel.
                        self.exchangeStatus = .done
                        let payload = ExchangePhase.Payload(
                            fingerprint: peerIdentity.sha256,
                            classicalKey: peerIdentity,
                            hybridResult: nil
                        )
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(for: .seconds(3))
                            guard let self else { return }
                            self.phase = .mlKemExchanged(payload)
                            try? await Task.sleep(for: .seconds(3))
                            guard case .mlKemExchanged(let p) = self.phase else { return }
                            self.phase = .confirming(p)
                        }
                    } else {
                        self.exchangeStatus = .waitingForPeerIdentity
                    }
                }
            } else {
                self.exchangeStatus = .waitingForPeerIdentity
                #if DEBUG
                debugPrint("[KE] Responder — waiting for initiator's identity")
                #endif
            }

            // Replay identity that arrived before NI confirmed proximity.
            if let buffered = self.bufferedIdentityMessage {
                self.bufferedIdentityMessage = nil
                self.handleReceivedData(buffered.data, from: buffered.peerID)
            }
        }
    }
}

// MARK: - MCSessionDelegate
// ⚠️ All delegate callbacks dispatch to the main queue before mutating state.

extension ExchangeManager: MCSessionDelegate {
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        DispatchQueue.main.async { [weak self] in
            #if DEBUG
            debugPrint("[KE] Session state changed: \(state.rawValue) for \(peerID.displayName)")
            #endif
            self?.handleSessionStateChange(peerID: peerID, state: state)
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        DispatchQueue.main.async { [weak self] in
            #if DEBUG
            debugPrint("[KE] Received data from \(peerID.displayName)")
            #endif
            self?.handleReceivedData(data, from: peerID)
        }
    }

    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) { }
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) { }
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: (any Error)?) { }
}

// MARK: - MCNearbyServiceBrowserDelegate

extension ExchangeManager: MCNearbyServiceBrowserDelegate {
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        #if DEBUG
        debugPrint("[KE] Browser found peer: \(peerID.displayName)")
        #endif
        guard let session = self.multipeerSession else { return }
        guard peerID.displayName != session.myPeerID.displayName,
              !session.connectedPeers.contains(peerID) else { return }
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) { }
}

// MARK: - MCNearbyServiceAdvertiserDelegate

extension ExchangeManager: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        #if DEBUG
        debugPrint("[KE] Advertiser received invitation from: \(peerID.displayName)")
        #endif
        invitationHandler(true, self.multipeerSession)
    }
}

// MARK: - NISessionDelegate
// ⚠️ NI delegate callbacks dispatch to the main queue before mutating state.

extension ExchangeManager: NISessionDelegate {
    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        DispatchQueue.main.async { [weak self] in
            #if DEBUG
            let distances = nearbyObjects.map { $0.distance.map { String(format: "%.2f", $0) } ?? "nil" }
            debugPrint("[KE] NI didUpdate: distances: \(distances)")
            #endif
            self?.handleNearbyObjectsUpdate(nearbyObjects)
        }
    }

    func session(_ session: NISession, didInvalidateWith error: Error) {
        #if DEBUG
        debugPrint("[KE] NI didInvalidateWith error: \(error)")
        if let niError = error as? NIError {
            debugPrint("[KE] NIError code: \(niError.code.rawValue)")
        }
        #endif
    }

    func session(_ session: NISession, didRemove nearbyObjects: [NINearbyObject], reason: NINearbyObject.RemovalReason) {
        #if DEBUG
        debugPrint("[KE] NI didRemove \(nearbyObjects.count) objects, reason: \(reason.rawValue)")
        #endif
    }

    func sessionWasSuspended(_ session: NISession) {
        #if DEBUG
        debugPrint("[KE] NI sessionWasSuspended")
        #endif
    }

    func sessionSuspensionEnded(_ session: NISession) {
        #if DEBUG
        debugPrint("[KE] NI sessionSuspensionEnded — re-running configuration")
        #endif
        if let config = self.lastNIConfiguration {
            session.run(config)
        }
    }

    func sessionDidStartRunning(_ session: NISession) {
        #if DEBUG
        debugPrint("[KE] NISession started running")
        #endif
    }
}
