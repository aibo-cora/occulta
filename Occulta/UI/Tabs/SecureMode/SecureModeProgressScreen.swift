//
//  SecureModeProgressScreen.swift
//  Occulta
//
//  The black progress screen activation and deactivation show while they run.
//

import SwiftUI

/// Shown in place of the screen it belongs to, never over it (Bug 240).
///
/// Activation and deactivation run on the main thread, so no animation can progress while they
/// do. An overlay that faded in froze at its first frames and left the message drawn over a
/// screen that was still visible. Shown as a phase of its own and without a transition, its first
/// frame is fully opaque; the caller waits one short sleep for that frame before the blocking call.
struct SecureModeProgressScreen: View {
    let message: LocalizedStringKey

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 16) {
                ProgressView()
                    .progressViewStyle(.circular)
                    .tint(.white)
                    .scaleEffect(1.2)
                Text(self.message)
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(.white.opacity(0.8))
            }
        }
        .allowsHitTesting(true) // absorbs all taps
        .interactiveDismissDisabled()
    }
}
