//
//  SecureModeDeactivateFlow.swift
//  Occulta
//
//  PIN confirmation + deactivation progress screen.
//  Presented as a sheet from Settings → Security → "Deactivate Protection".
//

import SwiftUI

struct SecureModeDeactivateFlow: View {

    @Environment(\.dismiss)             private var dismiss
    @Environment(Manager.Security.self) private var security

    /// `.deactivating` is never left on success, so the PIN screen doesn't come back during the
    /// slide-out (Bug 240). Only a failure returns to the PIN screen, with its alert.
    private enum Phase { case enterPIN, deactivating, failed }

    @State private var phase: Phase = .enterPIN

    var body: some View {
        switch self.phase {
        case .deactivating:
            SecureModeProgressScreen(message: "Removing protection…")
        case .enterPIN, .failed:
            self.pinEntry
        }
    }

    private var pinEntry: some View {
        PINEntry(mode: .verifyCurrentLayer, onAuthenticated: { pin in
            self.phase = .deactivating
            Task {
                // Lets the progress screen commit a frame before deactivation blocks the main thread.
                try? await Task.sleep(for: .milliseconds(50))
                do {
                    try self.security.deactivateSecureMode(confirmingEntryPIN: pin)
                    self.dismiss()
                } catch {
                    self.phase = .failed
                }
            }
        })
        .alert("Deactivation Failed", isPresented: Binding(
            get: { self.phase == .failed },
            set: { if !$0 { self.phase = .enterPIN } }
        )) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Protection could not be removed. Your data is unchanged. Please try again.")
        }
    }
}
