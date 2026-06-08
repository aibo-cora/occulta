//
//  SecureModeDeactivateFlow.swift
//  Occulta
//
//  PIN confirmation + deactivation progress overlay.
//  Presented as a sheet from Settings → Security → "Deactivate Protection".
//

import SwiftUI

struct SecureModeDeactivateFlow: View {

    @Environment(\.dismiss)             private var dismiss
    @Environment(Manager.Security.self) private var security
    @Environment(ContactManager.self)   private var contactManager
    @Environment(VaultManager.self)     private var vaultManager

    @State private var isDeactivating     = false
    @State private var deactivationFailed = false

    var body: some View {
        PINEntry(mode: .verifyCurrentLayer, onAuthenticated: { pin in
            self.isDeactivating = true
            let cm = self.contactManager
            let vm = self.vaultManager
            Task {
                try? await Task.sleep(for: .milliseconds(50)) // let the overlay render
                do {
                    try await self.security.deactivateSecureMode(
                        confirmingEntryPIN: pin,
                        contactManager:     cm,
                        vaultManager:       vm
                    )
                    self.isDeactivating = false
                    self.dismiss()
                } catch {
                    self.isDeactivating     = false
                    self.deactivationFailed = true
                }
            }
        })
        .overlay {
            if self.isDeactivating {
                DeactivatingOverlay()
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: self.isDeactivating)
        .interactiveDismissDisabled(self.isDeactivating)
        .alert("Deactivation Failed", isPresented: self.$deactivationFailed) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Protection could not be removed. Your data is unchanged. Please try again.")
        }
    }
}

// MARK: - Overlay

private struct DeactivatingOverlay: View {
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 16) {
                ProgressView()
                    .progressViewStyle(.circular)
                    .tint(.white)
                    .scaleEffect(1.2)
                Text("Removing protection…")
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(.white.opacity(0.8))
            }
        }
        .allowsHitTesting(true)
    }
}
