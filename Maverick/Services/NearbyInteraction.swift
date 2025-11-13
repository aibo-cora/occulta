//
//  NearbyInteraction.swift
//  Maverick
//
//  Created by Yura on 11/10/25.
//

import Foundation
import NearbyInteraction
import CoreHaptics
import UIKit

@available(iOS 17.0, *)
@Observable
final class NearbyInteractionViewModel: NSObject {
    
    // MARK: - Observable Properties
    
    var status: NIStatus = .idle
    var distance: Float?
    var direction: SIMD3<Float>?
    var isConnected = false
    var receivedMessage: String?
    var showPermissionAlert = false
    var useFallbackQR = false

    // MARK: - Private
    
    private var session: NISession?
    private var myDiscoveryToken: NIDiscoveryToken?
    private let haptic = UINotificationFeedbackGenerator()

    // MARK: - Public API
    
    func startSession() async {
        // 1. Check UWB support
        guard
            NISession.deviceCapabilities.supportsPreciseDistanceMeasurement
        else {
            self.status = .error("UWB not supported")
            self.useFallbackQR = true
            
            return
        }

        await self.setupAndRunSession()
    }

    func stopSession() {
        self.session?.invalidate()
        self.reset()
    }

    func sendHello() async throws {
        guard
            let session = self.session, let token = self.myDiscoveryToken
        else { return }

        let payload = "Hello from @yummyface! (UWB)".data(using: .utf8)!
        let accessory = try NINearbyAccessoryConfiguration(data: payload)

        self.status = .sending

        try? await Task.sleep(for: .milliseconds(600))
        
        self.status = .connected
    }

    // MARK: - Private
    
    private func setupAndRunSession() async {
        self.session = NISession()
        self.session?.delegate = self

//        let config = NINearbyPeerConfiguration(peerToken: <#T##NIDiscoveryToken#>)
//        
//        self.session?.run(config)
        self.status = .searching
    }

    private func reset() {
        self.session = nil
        self.myDiscoveryToken = nil
        self.distance = nil
        self.direction = nil
        self.isConnected = false
        self.receivedMessage = nil
        self.status = .idle
        self.useFallbackQR = false
    }
}

// MARK: - NISessionDelegate

@available(iOS 17.0, *)
extension NearbyInteractionViewModel: NISessionDelegate {

    func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        Task { @MainActor in
            guard
                let closest = nearbyObjects.first
            else {
                self.isConnected = false
                self.distance = nil
                self.direction = nil
                
                return
            }

            self.distance = closest.distance
            self.direction = closest.direction
            self.isConnected = true

            if let distance = closest.distance, distance < 0.1 {
                self.status = .connected
                self.haptic.notificationOccurred(.success)

                // First contact: auto-send
                if self.myDiscoveryToken == nil {
                    self.myDiscoveryToken = session.discoveryToken
                    
                    try? await self.sendHello()
                }
            } else {
                self.status = .nearby
            }

            // Receive message
        }
    }

    func session(_ session: NISession, didInvalidateWith error: Error) {
        Task { @MainActor in
            self.status = .error(error.localizedDescription)
            self.haptic.notificationOccurred(.error)
            
            self.session = nil
        }
    }

    func sessionWasSuspended(_ session: NISession) {
        Task { @MainActor in
            self.status = .suspended }
    }
}

// MARK: - Status

enum NIStatus: Equatable {
    case idle, searching, nearby, connected, sending, suspended, error(String)

    var description: String {
        switch self {
        case .idle: 
            "Ready"
        case .searching: 
            "Hold phones close..."
        case .nearby: 
            "Getting closer..."
        case .connected: 
            "Connected!"
        case .sending: 
            "Sending..."
        case .suspended: 
            "Paused"
        case .error(let msg): 
            "Error: \(msg)"
        }
    }
}
