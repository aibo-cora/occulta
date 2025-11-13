//
//  ExchangeManager.swift
//  Maverick
//
//  Created by Yura on 11/12/25.
//

import Foundation
import NearbyInteraction
import MultipeerConnectivity

@Observable
class ExchangeManager: NSObject {
    var nearbySession: NISession?
    var multipeerSession: MCSession?
    var receivedDiscoveryTokens: [NIDiscoveryToken: MCPeerID] = [:]
    
    private let serviceType = "secure-peer-discovery"
    
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
            state == .connected,
            let discoveryToken = self.nearbySession?.discoveryToken,
            let encodedData = try? NSKeyedArchiver.archivedData(withRootObject: discoveryToken, requiringSecureCoding: true)
        else {
            return
        }
        
        /// 2. Send the discovery token to ALL the peers in the vicinity.
        try? session.send(encodedData, toPeers: [peerID], with: .reliable)
    }
    
    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        /// 3. Receive discovery token.
        guard
            let token = try? NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: data)
        else {
            return
        }
        
        // TODO: -
        
        /// There could be multiple contacts in the vicinity willing to exchange keys. Need to create as many `NISession()` objects as there are tokens received. For simplicity, I am creating only one for now.
        ///
        self.receivedDiscoveryTokens[token] = peerID
        /// 4. Run `NearbyInteraction` session.
        ///
        
        /// Nearby configuratuio
        let configuration = NINearbyPeerConfiguration(peerToken: token)
        
        self.nearbySession?.run(configuration)
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
                    /// Send public key to the peer that got close to us.
                    
                    try? self.multipeerSession?.send(Data(), toPeers: [peer], with: .reliable)
                }
            }
        }
    }
    
    func session(_ session: NISession, didRemove nearbyObjects: [NINearbyObject], reason: NINearbyObject.RemovalReason) {
        
    }
    
    func session(_ session: NISession, didInvalidateWith error: any Error) {
        
    }
}
