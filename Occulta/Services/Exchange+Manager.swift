//
//  ExchangeManager.swift
//  Occulta
//
//  Created by Yura on 11/12/25.
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
    private let log = Logger(subsystem: "com.maverick.multipeer", category: "multipeer")
    
    /// This ID will be matched with the incoming data to make sure that we get a public key from a peer that got our identity - public key.
    ///
    /// This will be the peer that we verified through nearby interaction.
    private var peerReceivingOurIdentity: MCPeerID?
    /// Passing received identity from a contact that got within range.
    let receivedIdentity: CurrentValueSubject<Data?, Never> = .init(nil)
    
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    
    /// Key exchange is in progress?
    var inProgress: Bool = false
    
    var isExchangePossible: Bool {
        NISession.deviceCapabilities.supportsPreciseDistanceMeasurement
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
    
    /// Start Nearby Interaction and Multipeer Connectivity to find a peer and exchange keys.
    func start() {
        /// 1. Create a session and a discovery token.
        self.nearbySession = NISession()
        self.nearbySession?.delegate = self
        
        self.setupMC()
        
        self.advertiser?.startAdvertisingPeer()
        self.browser?.startBrowsingForPeers()
        
        self.inProgress = true
        debugPrint("Starting exchange...")
    }
    
    func finish() {
        self.nearbySession?.pause()
        
        self.advertiser?.stopAdvertisingPeer()
        self.browser?.stopBrowsingForPeers()
        
        self.inProgress = false
        debugPrint("Exchange finished")
    }
}

extension ExchangeManager: MCSessionDelegate {
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        debugPrint("Changed state for peer \(peerID): \(state.rawValue)")
        guard
            state == .connected
        else {
            return
        }
        
        debugPrint("Connected to a peer, id = \(peerID)")
        
        guard
            let discoveryToken = self.nearbySession?.discoveryToken
        else {
            // TODO: Handle the no token event
            return
        }
        
        debugPrint("My discovery token, \(discoveryToken)")
        
        do {
            let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: discoveryToken, requiringSecureCoding: true)
            
            let exchange = Exchange(id: UUID().uuidString, token: archivedToken, version: .v1)
            let encodedExchange = try JSONEncoder().encode(exchange)
            
            /// 2. Send the discovery token to ALL the peers in the vicinity.
            try session.send(encodedExchange, toPeers: [peerID], with: .reliable)
            
            debugPrint("Exchange sent")
        } catch {
            // TODO: Handle the archiving, encoding and sending exceptions
            debugPrint("Archiving or sending failed")
        }
    }
    /// 3. Receive discovery token.
    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        do {
            let decoded = try JSONDecoder().decode(Exchange.self, from: data)
            let archivedToken = decoded.token
            let token = try NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: archivedToken)
            
            // TODO: - Multiple peers
            
            debugPrint("Received data from peer, \(peerID): \(decoded)")
            
            guard
                let token
            else {
                // TODO: Handle missing token
                debugPrint("No token found")
                return
            }
            
            if let peersIdentity = decoded.identity {
                if peerID == self.peerReceivingOurIdentity {
                    Task { @MainActor in
                        /// The exchange contains an identity key and we verified that we got it from the same peer that got our own identity.
                        self.receivedIdentity.send(peersIdentity)
                    }
                } else {
                    debugPrint("MITM attack?")
                    // TODO: MITM? attack
                    return
                }
            } else {
                debugPrint("No identity key found in the received data")
            }
            
            /// There could be multiple contacts in the vicinity willing to exchange keys. Need to create as many `NISession()` objects as there are tokens received. For simplicity, I am creating only one for now.
            ///
            self.receivedDiscoveryTokens[token] = peerID
            /// 4. Run `NearbyInteraction` session.
            ///
            
            /// Nearby configuratuio
            let configuration = NINearbyPeerConfiguration(peerToken: token)
            debugPrint("Running nearby session")
            self.nearbySession?.run(configuration)
        } catch {
            // TODO: Handle decoding error
        }
    }
    
    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {
        
    }
    
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {
        
    }
    
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: (any Error)?) {
        
    }
}

extension ExchangeManager: MCNearbyServiceBrowserDelegate {
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String : String]?) {
        self.log.info("Found peer: \(peerID.displayName)")
        
        if self.multipeerSession?.connectedPeers.contains(peerID) == false, let session = self.multipeerSession {
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 30)
        }
    }
    
    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        self.log.info("Lost peer: \(peerID.displayName)")
    }
}

extension ExchangeManager: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        self.log.info("Received invitation from \(peerID.displayName) - Auto-accepting")
        
        invitationHandler(true, self.multipeerSession)
    }
}

extension ExchangeManager: NISessionDelegate {
    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        debugPrint("Detected nearby objects")
        for object in nearbyObjects {
            debugPrint("Object distance: \(object.distance ?? 0.0), token: \(object.discoveryToken.debugDescription)")
            
            if let distance = object.distance, distance.isLessThanOrEqualTo(0.25) {
                let token = object.discoveryToken
                
                if let peer = self.receivedDiscoveryTokens[token] {
                    do {
                        let keyManager = Manager.Key()
                        
                        #if targetEnvironment(simulator)
                        let keyingMaterial = keyManager.fixedX963
                        #else
                        let keyingMaterial = try keyManager.retrieveIdentity()
                        #endif
                        
                        let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
                        let exchange = Exchange(id: UUID().uuidString, token: archivedToken, version: .v1, identity: keyingMaterial)
                        let encodedExchange = try JSONEncoder().encode(exchange)
                        /// Peer ID to be matched on receive.
                        self.peerReceivingOurIdentity = peer
                        /// Send public key to the peer that got close to us.
                        try self.multipeerSession?.send(encodedExchange, toPeers: [peer], with: .reliable)
                        /// Stop the session
                        session.invalidate()
                    } catch {
                        // TODO: Handle errors
                    }
                }
            }
        }
    }
    
    func session(_ session: NISession, didRemove nearbyObjects: [NINearbyObject], reason: NINearbyObject.RemovalReason) {
        debugPrint("Did remove objects, \(nearbyObjects), reason - \(reason)")
    }
    
    func session(_ session: NISession, didInvalidateWith error: any Error) {
        debugPrint("Did invalidate with error = \(error)")
    }
}
