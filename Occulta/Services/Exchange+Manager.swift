//
//  Exchange+Manager.swift
//  Occulta
//
//  Hybrid post-quantum key exchange with full v1 backward compatibility.
//  ML-KEM operations are delegated to PQProvider — no ML-KEM types appear in this file.
//
//  ⚠️ Backward compatibility contract:
//  - All messages use `version: .v1` on the wire.
//  - `receivedIdentity` preserved for v1 classical exchanges.
//  - `completedExchange` added for hybrid PQ exchanges.
//  - If PQProvider is nil (iOS < 26), exchange is classical-only.
//  - If peer sends identity without `encapsulationKey`, exchange is classical-only.
//

import Foundation
import NearbyInteraction
import MultipeerConnectivity
import Combine
import os

@Observable
class ExchangeManager: NSObject {
    private var nearbySession: NISession?
    private var multipeerSession: MCSession?
    private var receivedDiscoveryTokens: [NIDiscoveryToken: MCPeerID] = [:]

    private let serviceType = "peer-data-ex"
    private let log = Logger(subsystem: "com.occulta.multipeer", category: "multipeer")

    private var peerReceivingOurIdentity: MCPeerID?

    /// Classical exchange result — peer's P-256 public key only.
    /// ⚠️ Preserved for backward compatibility with KeyExchange.swift.
    let receivedIdentity: CurrentValueSubject<Data?, Never> = .init(nil)

    /// Hybrid PQ exchange result — P-256 + ML-KEM secrets + nonces.
    let completedExchange: CurrentValueSubject<HybridExchangeResult?, Never> = .init(nil)

    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?

    var inProgress: Bool = false

    var isExchangePossible: Bool {
        NISession.deviceCapabilities.supportsPreciseDistanceMeasurement
    }

    // MARK: - PQ exchange state

    /// PQ provider — nil on iOS < 26.
    private let pqProvider: PQProvider? = PQProviderFactory.create()
    /// Our 16-byte nonce, generated at session start and committed in discovery.
    private var ourNonce: Data?
    /// Peer's nonce from their discovery message. Nil if peer is v1.
    private var peerNonce: Data?
    /// Opaque handle to our SE-backed ML-KEM-1024 private key.
    /// Type is `Any` to avoid ML-KEM type references in this file.
    private var privateKeyHandle: Any?
    /// Shared secret from OUR encapsulation of peer's ML-KEM key.
    private var encapsulatedSecret: Data?
    /// Shared secret from DECAPSULATING peer's ciphertext.
    private var decapsulatedSecret: Data?
    /// Peer's P-256 identity, stored temporarily until ML-KEM completes.
    private var peerIdentity: Data?
    /// ML-KEM ciphertext we produced (for contact record storage).
    private var ourCiphertext: Data?
    /// ML-KEM ciphertext peer produced (for contact record storage).
    private var peerCiphertext: Data?
    /// Guards: prevent duplicate sends on repeated NI distance callbacks.
    private var identitySent: Bool = false
    private var ciphertextSent: Bool = false

    // MARK: - Result type

    struct HybridExchangeResult {
        let peerP256PublicKey: Data
        let mlkemSecret1: Data
        let mlkemSecret2: Data
        let ourNonce: Data
        let peerNonce: Data
        let ourCiphertext: Data
        let peerCiphertext: Data
    }

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
        self.nearbySession = NISession()
        self.nearbySession?.delegate = self

        self.setupMC()

        let keyManager = Manager.Key()
        self.ourNonce = keyManager.generateExchangeNonce()

        self.advertiser?.startAdvertisingPeer()
        self.browser?.startBrowsingForPeers()

        self.inProgress = true
        #if DEBUG
        debugPrint("Starting exchange...")
        #endif
    }

    func finish() {
        self.nearbySession?.pause()

        self.advertiser?.stopAdvertisingPeer()
        self.browser?.stopBrowsingForPeers()

        // ⚠️ Release SE-backed ML-KEM private key handle.
        // For SecureEnclave.MLKEM1024, releasing the reference means the SE key
        // can no longer be used. No explicit SE delete needed — CryptoKit SE keys
        // are accessed via their object reference, not a keychain tag.
        self.privateKeyHandle = nil

        self.ourNonce = nil
        self.peerNonce = nil
        self.encapsulatedSecret = nil
        self.decapsulatedSecret = nil
        self.peerIdentity = nil
        self.ourCiphertext = nil
        self.peerCiphertext = nil
        self.identitySent = false
        self.ciphertextSent = false
        self.peerReceivingOurIdentity = nil

        self.inProgress = false
        #if DEBUG
        debugPrint("Exchange finished")
        #endif
    }

    // MARK: - Completion check

    private func tryCompleteHybridExchange() {
        guard
            let peerIdentity,
            let encapsulatedSecret,
            let decapsulatedSecret,
            let ourNonce,
            let peerNonce,
            let ourCiphertext,
            let peerCiphertext
        else { return }

        let result = HybridExchangeResult(
            peerP256PublicKey: peerIdentity,
            mlkemSecret1: encapsulatedSecret,
            mlkemSecret2: decapsulatedSecret,
            ourNonce: ourNonce,
            peerNonce: peerNonce,
            ourCiphertext: ourCiphertext,
            peerCiphertext: peerCiphertext
        )

        Task { @MainActor in
            self.completedExchange.send(result)
        }
    }
}

// MARK: - MCSessionDelegate

extension ExchangeManager: MCSessionDelegate {

    /// Phase 1: MC connected → send discovery token + nonce.
    /// ⚠️ Version .v1 on wire. Nonce is optional — v1 peers ignore it.
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        guard state == .connected else { return }

        #if DEBUG
        debugPrint("Connected to peer: \(peerID)")
        #endif

        guard let discoveryToken = self.nearbySession?.discoveryToken else { return }

        do {
            let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: discoveryToken, requiringSecureCoding: true)

            let exchange = Exchange(
                id: UUID().uuidString,
                token: archivedToken,
                version: .v1,
                nonce: self.ourNonce
            )

            let encoded = try JSONEncoder().encode(exchange)
            try session.send(encoded, toPeers: [peerID], with: .reliable)
        } catch {
            #if DEBUG
            debugPrint("Discovery send failed")
            #endif
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        do {
            let decoded = try JSONDecoder().decode(Exchange.self, from: data)

            // MARK: Phase 1 — Discovery (token + optional nonce)

            if decoded.isDiscovery {
                guard
                    let token = try NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: decoded.token)
                else { return }

                if let nonce = decoded.nonce, nonce.count == 16 {
                    self.peerNonce = nonce
                }

                self.receivedDiscoveryTokens[token] = peerID

                let configuration = NINearbyPeerConfiguration(peerToken: token)
                self.nearbySession?.run(configuration)
                
                return
            }

            // MARK: Phase 2 — Identity (P-256 + optional ML-KEM encapsulation key)

            if decoded.isIdentity {
                guard peerID == self.peerReceivingOurIdentity else {
                    #if DEBUG
                    debugPrint("MITM guard: identity from unexpected peer")
                    #endif
                    return
                }

                guard
                    let peersP256Key = decoded.identity, peersP256Key.count == 65
                else { return }

                // ── PQ path: peer sent encapsulation key AND we have a provider ──
                if let peerEncapsulationKey = decoded.encapsulationKey, let provider = self.pqProvider, self.privateKeyHandle != nil {
                    self.peerIdentity = peersP256Key

                    guard let encapsulationResult = provider.encapsulate(peerPublicKeyData: peerEncapsulationKey) else { return }
                    
                    self.encapsulatedSecret = encapsulationResult.sharedSecret
                    self.ourCiphertext = encapsulationResult.ciphertext

                    guard !self.ciphertextSent else { return }
                    
                    self.ciphertextSent = true

                    let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: self.nearbySession?.discoveryToken as Any, requiringSecureCoding: true)

                    let ciphertextExchange = Exchange(
                        id: UUID().uuidString,
                        token: archivedToken,
                        version: .v1,
                        ciphertext: encapsulationResult.ciphertext
                    )

                    let encoded = try JSONEncoder().encode(ciphertextExchange)
                    try session.send(encoded, toPeers: [peerID], with: .reliable)
                } else {
                    // ── Classical fallback: peer is v1 or we have no PQ provider ──
                    Task { @MainActor in
                        self.receivedIdentity.send(peersP256Key)
                    }
                }
                return
            }

            // MARK: Phase 3 — Ciphertext (ML-KEM ciphertext for decapsulation)

            if decoded.isCiphertext {
                guard
                    let ciphertext = decoded.ciphertext,
                    let handle = self.privateKeyHandle,
                    let provider = self.pqProvider
                else { return }

                guard let sharedSecret = provider.decapsulate(ciphertext: ciphertext, privateKeyHandle: handle) else { return }

                self.decapsulatedSecret = sharedSecret
                self.peerCiphertext = ciphertext

                // ⚠️ Release SE private key — its only purpose is fulfilled.
                self.privateKeyHandle = nil

                self.tryCompleteHybridExchange()
                return
            }
        } catch {
            #if DEBUG
            debugPrint("Exchange decode failed")
            #endif
        }
    }

    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) { }
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) { }
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: (any Error)?) { }
}

// MARK: - MCNearbyServiceBrowserDelegate

extension ExchangeManager: MCNearbyServiceBrowserDelegate {
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        if self.multipeerSession?.connectedPeers.contains(peerID) == false, let session = self.multipeerSession {
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
        }
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) { }
}

// MARK: - MCNearbyServiceAdvertiserDelegate

extension ExchangeManager: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        invitationHandler(true, self.multipeerSession)
    }
}

// MARK: - NISessionDelegate

extension ExchangeManager: NISessionDelegate {

    /// Phase 2: UWB ≤ 25cm → send identity + optional ML-KEM encapsulation key.
    /// If PQ provider is nil (iOS < 26), encapsulationKey is nil — v1 peers and us both work fine.
    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        for object in nearbyObjects {
            guard
                let distance = object.distance,
                distance.isLessThanOrEqualTo(0.25)
            else { continue }

            let token = object.discoveryToken
            guard let peer = self.receivedDiscoveryTokens[token] else { continue }

            guard !self.identitySent else { continue }
            self.identitySent = true

            do {
                let keyManager = Manager.Key()

                #if targetEnvironment(simulator)
                let keyingMaterial = keyManager.fixedX963
                #else
                let keyingMaterial = try keyManager.retrieveIdentity()
                #endif

                // Generate SE-backed ML-KEM-1024 key pair if available.
                // On iOS < 26, pqProvider is nil → mlkemPair is nil → encapsulationKey is nil.
                // V1 peers ignore the field. Our side falls back to classical on receive.
                var encapsulationKeyData: Data?
                
                if let keyPair = self.pqProvider?.generateKeyPair() {
                    self.privateKeyHandle = keyPair.privateKeyHandle
                    encapsulationKeyData = keyPair.publicKeyData
                }

                let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)

                let exchange = Exchange(
                    id: UUID().uuidString,
                    token: archivedToken,
                    version: .v1,
                    identity: keyingMaterial,
                    encapsulationKey: encapsulationKeyData
                )

                let encoded = try JSONEncoder().encode(exchange)
                self.peerReceivingOurIdentity = peer
                try self.multipeerSession?.send(encoded, toPeers: [peer], with: .reliable)
            } catch {
                #if DEBUG
                debugPrint("Identity send failed")
                #endif
            }
        }
    }
}
