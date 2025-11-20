//
//  ExchangeManager.swift
//  Maverick
//
//  Created by Yura on 11/12/25.
//

import Foundation
import NearbyInteraction
import MultipeerConnectivity
import Combine

@Observable
class ExchangeManager: NSObject {
    private var nearbySession: NISession?
    private var multipeerSession: MCSession?
    private var receivedDiscoveryTokens: [NIDiscoveryToken: MCPeerID] = [:]
    
    private let serviceType = "secure-peer-discovery-data-exchange"
    
    /// This ID will be matched with the incoming data to make sure that we get a public key from a peer that got our identity - public key.
    ///
    /// This will be the peer that we verified through nearby interaction.
    private var peerReceivingOurIdentity: MCPeerID?
    /// Passing received identity from a contact that got within range.
    let receivedIdentity: CurrentValueSubject<Data?, Never> = .init(nil)
    
    override init() {
        super.init()
        /// 1. Create a session and a discovery token.
        self.nearbySession = NISession()
        
        self.setupMC()
    }
    
    private func setupMC() {
        let peerID = MCPeerID(displayName: UIDevice.current.name)
        
        self.multipeerSession = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
        self.multipeerSession?.delegate = self

        let advertiser = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: nil, serviceType: self.serviceType)
        let browser = MCNearbyServiceBrowser(peer: peerID, serviceType: self.serviceType)

        advertiser.delegate = self
        browser.delegate = self

        advertiser.startAdvertisingPeer()
        browser.startBrowsingForPeers()
    }
}

extension ExchangeManager: MCSessionDelegate {
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        guard
            state == .connected
        else {
            return
        }
        
        guard
            let discoveryToken = self.nearbySession?.discoveryToken
        else {
            // TODO: Handle the no token event
            return
        }
        
        do {
            let archivedToken = try NSKeyedArchiver.archivedData(withRootObject: discoveryToken, requiringSecureCoding: true)
            
            let exchange = Exchange(id: UUID().uuidString, token: archivedToken, version: .v1)
            let encodedExchange = try JSONEncoder().encode(exchange)
            
            /// 2. Send the discovery token to ALL the peers in the vicinity.
            try session.send(encodedExchange, toPeers: [peerID], with: .reliable)
        } catch {
            // TODO: Handle the archiving, encoding and sending exceptions
        }
    }
    /// 3. Receive discovery token.
    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        do {
            let decoded = try JSONDecoder().decode(Exchange.self, from: data)
            let archivedToken = decoded.token
            let token = try NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: archivedToken)
            
            // TODO: - Multiple peers
            
            guard
                let token
            else {
                // TODO: Handle missing token
                return
            }
            
            if let peersIdentity = decoded.identity {
                if peerID == self.peerReceivingOurIdentity {
                    /// The exchange contains an identity key and we verified that we got it from the same peer that got our own identity.
                    self.receivedIdentity.send(peersIdentity)
                } else {
                    // TODO: MITM? attack
                    return
                }
            }
            
            /// There could be multiple contacts in the vicinity willing to exchange keys. Need to create as many `NISession()` objects as there are tokens received. For simplicity, I am creating only one for now.
            ///
            self.receivedDiscoveryTokens[token] = peerID
            /// 4. Run `NearbyInteraction` session.
            ///
            
            /// Nearby configuratuio
            let configuration = NINearbyPeerConfiguration(peerToken: token)
            
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
        
    }
    
    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        
    }
}

extension ExchangeManager: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        
    }
}

extension ExchangeManager: NISessionDelegate {
    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        for object in nearbyObjects {
            if let distance = object.distance, distance.isLessThanOrEqualTo(0.25) {
                let token = object.discoveryToken
                
                if let peer = self.receivedDiscoveryTokens[token] {
                    do {
                        let keyManager = KeyManager()
                        let keyingMaterial = try keyManager.retrieveIdentity()
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
        
    }
    
    func session(_ session: NISession, didInvalidateWith error: any Error) {
        
    }
}
