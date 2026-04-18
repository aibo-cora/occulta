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
//  ⚠️ Thread safety:
//  MC and NI delegate callbacks arrive on arbitrary background threads.
//  All state mutations are dispatched to the main queue via `DispatchQueue.main.async`.
//  Main queue is serial + FIFO, preserving MC's per-peer ordering guarantee.
//  This also ensures @Observable property changes are UI-safe.
//

import Foundation
import NearbyInteraction
import MultipeerConnectivity
import Combine
import os

@Observable
class ExchangeManager: NSObject {
    private var nearbySession: NISession?
    private var lastNIConfiguration: NINearbyPeerConfiguration?
    
    private var multipeerSession: MCSession?
    private var receivedDiscoveryTokens: [NIDiscoveryToken: MCPeerID] = [:]

    private let serviceType = "peer-data-ex"
    private let log = Logger(subsystem: "com.occulta.multipeer", category: "multipeer")

    /// The peer whose proximity was confirmed by UWB.
    /// ⚠️ Set the moment NI confirms distance ≤ 25cm, BEFORE key generation begins.
    /// This closes the race window where a peer's identity could arrive before our
    /// NI delegate fires and get silently dropped by the MITM guard.
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
    // Generate SE-backed ML-KEM-1024 key pair if available.
    // On iOS < 26, pqProvider is nil → keyPair is nil → encapsulationKeyData is nil.
    // V1 peers ignore the field. Our side falls back to classical on receive.
    var encapsulationKeyData: Data?

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
        self.finish()
        self.nearbySession = NISession()
        self.nearbySession?.delegate = self

        self.setupMC()

        let keyManager = Manager.Key()
        self.ourNonce = keyManager.generateExchangeNonce()

        // ── NEW: generate ML-KEM keypair immediately (both sides)
        if let provider = self.pqProvider {
            if let keyPair = provider.generateKeyPair() {
                self.privateKeyHandle = keyPair.privateKeyHandle
                self.encapsulationKeyData = keyPair.publicKeyData
                
                #if DEBUG
                debugPrint("ML-KEM keypair generated at start (public key \(self.encapsulationKeyData?.count ?? 0) bytes)")
                #endif
            }
        }

        self.advertiser?.startAdvertisingPeer()
        self.browser?.startBrowsingForPeers()

        self.inProgress = true
        #if DEBUG
        debugPrint("Starting exchange...")
        #endif
    }

    func finish() {
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
        
        /// The session was already invalidated.
        self.receivedIdentity.send(nil)
        self.completedExchange.send(nil)

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
        
        #if DEBUG
        debugPrint("Hybrid exchange complete")
        #endif

        self.completedExchange.send(result)
    }

    // MARK: - Phase handlers (always called on main queue)

    private func handleSessionStateChange(peerID: MCPeerID, state: MCSessionState) {
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
            try self.multipeerSession?.send(encoded, toPeers: [peerID], with: .reliable)
        } catch {
            #if DEBUG
            debugPrint("Discovery send failed")
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
                    guard let unarchived = try NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: decoded.token) else {
                        #if DEBUG
                        debugPrint("Discovery: NIDiscoveryToken unarchive returned nil (from peer \(peerID.displayName))")
                        #endif
                        return
                    }
                    token = unarchived
                } catch {
                    #if DEBUG
                    debugPrint("Discovery: NIDiscoveryToken unarchive threw: \(error)")
                    #endif
                    return
                }

                if let nonce = decoded.nonce, nonce.count == 16 {
                    self.peerNonce = nonce
                }

                self.receivedDiscoveryTokens[token] = peerID
                
                #if DEBUG
                debugPrint("Discovery: token received from \(peerID.displayName), running NI config")
                #endif

                let configuration = NINearbyPeerConfiguration(peerToken: token)
                
                self.lastNIConfiguration = configuration
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
                
                self.peerIdentity = peersP256Key

                // ── PQ path: peer sent encapsulation key, we have a provider, AND
                //    we successfully generated our own ML-KEM key pair (privateKeyHandle != nil).
                //    Without our own private key, we cannot decapsulate the peer's ciphertext
                //    in Phase 3, so entering the PQ path would leave the exchange stuck.
                if let peerEncapsulationKey = decoded.encapsulationKey, let provider = self.pqProvider, self.privateKeyHandle != nil {
                    guard let encapsulationResult = provider.encapsulate(peerPublicKeyData: peerEncapsulationKey) else { return }
                    
                    self.encapsulatedSecret = encapsulationResult.sharedSecret
                    self.ourCiphertext = encapsulationResult.ciphertext

                    guard self.ciphertextSent == false else { return }

                    // ⚠️ Guard against nil discovery token. If the NI session was invalidated
                    //    between the NI delegate firing and now, the token is nil.
                    guard let discoveryToken = self.nearbySession?.discoveryToken else { return }
                    let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: discoveryToken, requiringSecureCoding: true)

                    let ciphertextExchange = Exchange(
                        id: UUID().uuidString,
                        token: archivedToken,
                        version: .v1,
                        ciphertext: encapsulationResult.ciphertext
                    )

                    let encoded = try JSONEncoder().encode(ciphertextExchange)
                    try self.multipeerSession?.send(encoded, toPeers: [peerID], with: .reliable)
                    
                    self.ciphertextSent = true
                    
                    #if DEBUG
                    debugPrint("Ciphertext sent to peer: \(peerID.displayName)")
                    #endif
                    
                    /// We are trying to complete exchange. Identity & Ciphertext could arrive in different order. MC does not guarantee order.
                    self.tryCompleteHybridExchange()
                } else {
                    // ── Classical fallback: peer is v1, we have no PQ provider,
                    //    or our SE ML-KEM key generation failed.
                    self.receivedIdentity.send(peersP256Key)
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
                
                #if DEBUG
                debugPrint("Ciphertext received from peer: \(peerID.displayName)")
                #endif

                guard let sharedSecret = provider.decapsulate(ciphertext: ciphertext, privateKeyHandle: handle) else { return }

                self.decapsulatedSecret = sharedSecret
                self.peerCiphertext = ciphertext
                
                #if DEBUG
                debugPrint("Peer's secret decapsulated: \(peerID.displayName)")
                #endif

                // ⚠️ Release SE private key — its only purpose is fulfilled.
                self.privateKeyHandle = nil
                /// We are trying to complete exchange. Identity & Ciphertext could arrive in different order. MC does not guarantee order.
                self.tryCompleteHybridExchange()
                
                return
            }
        } catch {
            #if DEBUG
            debugPrint("Exchange decode failed")
            #endif
        }
    }

    private func handleNearbyObjectsUpdate(_ nearbyObjects: [NINearbyObject]) {
        for object in nearbyObjects {
            guard
                let distance = object.distance,
                distance.isLessThanOrEqualTo(0.25)
            else { continue }
            
            #if DEBUG
            debugPrint("Object in range...")
            #endif

            let token = object.discoveryToken
            guard let peer = self.receivedDiscoveryTokens[token] else { continue }
            
            #if DEBUG
            debugPrint("Discovery token matches peer: \(peer.displayName)")
            #endif

            guard
                self.identitySent == false
            else { continue }

            // ⚠️ Set peerReceivingOurIdentity BEFORE key generation.
            // This closes the race where the peer's identity arrives before we finish
            // generating keys and sending ours. The MITM guard checks this value —
            // if it's nil when the peer's identity arrives, the identity is silently dropped
            // and the exchange hangs because identitySent prevents a resend.
            self.peerReceivingOurIdentity = peer

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
                try self.multipeerSession?.send(encoded, toPeers: [peer], with: .reliable)
                
                self.identitySent = true
                
                #if DEBUG
                debugPrint("Identity sent to peer: \(peer.displayName)")
                #endif
            } catch {
                #if DEBUG
                debugPrint("Identity send failed")
                #endif
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
                debugPrint("session state changed: \(state)")
            #endif
            
            self?.handleSessionStateChange(peerID: peerID, state: state)
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        DispatchQueue.main.async { [weak self] in
            #if DEBUG
                debugPrint("Received data from peer: \(peerID)")
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
            debugPrint("Browser found peer: \(peerID)")
        #endif
        
        guard let session = self.multipeerSession else { return }
        
        guard
            peerID.displayName != session.myPeerID.displayName,
            !session.connectedPeers.contains(peerID)
        else {
            return
        }
        
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) { }
}

// MARK: - MCNearbyServiceAdvertiserDelegate

extension ExchangeManager: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        #if DEBUG
            debugPrint("Advertiser received invitation from peer: \(peerID)")
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
            debugPrint("NI didUpdate: \(distances.count) objects, distances: \(distances)")
            #endif
            self?.handleNearbyObjectsUpdate(nearbyObjects)
        }
    }
    
    func session(_ session: NISession, didInvalidateWith error: Error) {
        #if DEBUG
        debugPrint("NI didInvalidateWith error: \(error)")
        if let niError = error as? NIError {
            debugPrint("NIError code: \(niError.code.rawValue)")
        }
        #endif
    }
    
    func session(_ session: NISession, didRemove nearbyObjects: [NINearbyObject], reason: NINearbyObject.RemovalReason) {
        #if DEBUG
        debugPrint("NI didRemove \(nearbyObjects.count) objects, reason: \(reason.rawValue)")
        #endif
    }
    
    func sessionWasSuspended(_ session: NISession) {
        #if DEBUG
        debugPrint("NI sessionWasSuspended")
        #endif
    }
    
    func sessionSuspensionEnded(_ session: NISession) {
        #if DEBUG
        debugPrint("NI sessionSuspensionEnded — re-running configuration")
        #endif
        
        if let config = self.lastNIConfiguration {
            session.run(config)
        }
    }
    
    func sessionDidStartRunning(_ session: NISession) {
        print("✅ NISession started running successfully")
    }
}
