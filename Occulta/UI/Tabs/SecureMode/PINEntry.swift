//
//  PINEntry.swift
//  Occulta
//

import SwiftUI
import SwiftData
import Combine

// MARK: - View

struct PINEntry: View {

    // MARK: Mode

    enum Mode {
        case verify
        /// Single-entry verification against the current layer's verifier — no counter
        /// mutation. In `.duress` checks the duress verifier; all other states check
        /// the normal verifier. Use for Settings-level confirmations where wrong
        /// attempts must not increment the wipe counter.
        case verifyCurrentLayer
        /// Two-phase entry: first entry sets `pendingPINEntry`, second entry must match it.
        /// On match, calls `onAuthenticated(pin)` with the confirmed PIN and does **not** call
        /// any security method internally — the caller's `onAuthenticated` closure is responsible
        /// for the actual security operation (e.g. `configurePIN`, `disablePIN(at:confirmingPIN:)`,
        /// `reEnablePIN`). This keeps the view decoupled from which operation is being confirmed.
        case setup
        /// Phase 1: verify existing layer PIN. Phase 2: enter + confirm new duress PIN.
        /// Delivers (authenticatedLayerPIN, newDuressPIN) to onComplete.
        case confirmThenSet(onComplete: (String, String) -> Void)
    }

    // MARK: Callbacks

    var mode: Mode = .verify
    /// Called with the authenticated PIN when the entry matches the normal/current-layer verifier,
    /// or with the confirmed new PIN in `.setup` mode. The caller is responsible for any
    /// subsequent security operation.
    var onAuthenticated: (String) -> Void = { _ in }
    /// Called when the entry matches the duress verifier. No PIN is delivered — the duress
    /// path must not expose the duress PIN to callers.
    var onDuress: () -> Void = {}

    // MARK: Dependencies

    @Environment(Manager.Security.self) private var security

    // MARK: State

    /// Raw digit input, stored as individual UInt8 values. Zeroed and cleared on every submit.
    @State private var digits:                Data    = Data()
    /// Horizontal offset driving the shake animation on a wrong entry.
    @State private var shakeOffset:           CGFloat = 0
    /// True while a submission is being processed (SE operation + timing pad). Disables the
    /// keypad to prevent queued entries during the artificial response window.
    @State private var isProcessing:          Bool    = false
    /// First-pass entry for two-pass confirmation modes (.setup, .confirmThenSet phase 2).
    /// Stored as UTF-8 Data so it can be zeroed via memset before clearing, unlike String.
    @State private var pendingPINEntry:       Data?   = nil
    /// The current-layer PIN authenticated in .confirmThenSet phase 1. Stored as UTF-8 Data
    /// so it can be zeroed before clearing. Converted to String only at the comparison boundary.
    @State private var authenticatedLayerPIN: Data?   = nil
    /// Non-nil while a lockout is active; the Date at which the lockout expires.
    @State private var lockoutUntil:          Date?   = nil
    /// Human-readable countdown string shown in place of the prompt title during lockout.
    @State private var lockoutRemaining:      String  = ""

    /// Number of digits required to complete a PIN entry.
    private let pinLength:         Int          = 6
    /// Minimum wall-clock duration for any PIN response. Each verification path waits at least
    /// this long before delivering a result, so correct and incorrect entries take identical
    /// time — timing side-channel resistance.
    private let timingPadDuration: TimeInterval = 0.5
    /// Fires every second to update the lockout countdown display.
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    /// True when a lockout expiry is set and has not yet elapsed.
    private var isLockedOut: Bool { self.lockoutUntil != nil }

    // MARK: Derived

    private var title: String {
        switch self.mode {
        case .verify, .verifyCurrentLayer:
            return "Passcode"
        case .setup:
            return self.pendingPINEntry != nil ? "Confirm Passcode" : "Passcode"
        case .confirmThenSet:
            guard self.authenticatedLayerPIN != nil else { return "Current Passcode" }
            return self.pendingPINEntry != nil ? "Confirm Passcode" : "New Passcode"
        }
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer()

                Group {
                    if self.isLockedOut {
                        Text(self.lockoutRemaining)
                    } else {
                        Text(self.title)
                    }
                }
                .font(.title3)
                .fontWeight(.semibold)
                .foregroundStyle(.white)

                Spacer().frame(height: 36)

                HStack(spacing: 18) {
                    ForEach(0..<self.pinLength, id: \.self) { index in
                        Circle()
                            .fill(index < self.digits.count ? Color.white : Color.white.opacity(0.25))
                            .frame(width: 14, height: 14)
                    }
                }
                .offset(x: self.shakeOffset)

                Spacer().frame(height: 56)

                VStack(spacing: 16) {
                    ForEach([[1,2,3],[4,5,6],[7,8,9]], id: \.self) { row in
                        HStack(spacing: 20) {
                            ForEach(row, id: \.self) { digit in
                                KeypadButton(label: "\(digit)", disabled: self.isProcessing || self.isLockedOut) {
                                    self.append(digit)
                                }
                            }
                        }
                    }
                    HStack(spacing: 20) {
                        Color.clear.frame(width: 88, height: 88)
                        KeypadButton(label: "0", disabled: self.isProcessing || self.isLockedOut) {
                            self.append(0)
                        }
                        KeypadButton(label: "⌫", isSymbol: true, disabled: self.isProcessing || self.isLockedOut) {
                            self.deleteLast()
                        }
                    }
                }

                Spacer()
            }
            .padding(.horizontal, 32)
        }
        .onAppear {
            if let expiry = self.security.lockoutExpiry() {
                self.lockoutUntil     = expiry
                self.lockoutRemaining = Self.countdownText(until: expiry, from: Date.now)
            }
        }
        .onReceive(self.timer) { now in
            guard let until = self.lockoutUntil else { return }
            if now >= until {
                self.lockoutUntil     = nil
                self.lockoutRemaining = ""
            } else {
                self.lockoutRemaining = Self.countdownText(until: until, from: now)
            }
        }
    }

    // MARK: Input

    private func append(_ digit: Int) {
        guard !self.isProcessing, !self.isLockedOut, self.digits.count < self.pinLength else { return }
        self.hapticSelection()
        self.digits.append(UInt8(digit))
        if self.digits.count == self.pinLength { self.submit() }
    }

    private func deleteLast() {
        guard !self.digits.isEmpty else { return }
        self.hapticSelection()
        self.digits[self.digits.count - 1] = 0
        self.digits.removeLast()
    }

    private func clearDigits() {
        _ = self.digits.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
        self.digits.removeAll()
    }

    private func clearPending() {
        guard self.pendingPINEntry != nil else { return }
        _ = self.pendingPINEntry!.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
        self.pendingPINEntry = nil
    }

    private func clearAuthPIN() {
        guard self.authenticatedLayerPIN != nil else { return }
        _ = self.authenticatedLayerPIN!.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
        self.authenticatedLayerPIN = nil
    }

    // MARK: Submit

    private func submit() {
        self.isProcessing = true
        let pin = self.digits.map { String($0) }.joined()

        switch self.mode {
        case .setup:
            self.submitSetup(pin: pin)
        case .verify:
            self.submitVerify(pin: pin)
        case .verifyCurrentLayer:
            self.submitVerifyCurrentLayer(pin: pin)
        case .confirmThenSet(let onComplete):
            if self.authenticatedLayerPIN == nil {
                self.submitConfirmPhase(pin: pin, onComplete: onComplete)
            } else {
                self.submitSetPhase(pin: pin, onComplete: onComplete)
            }
        }
    }

    // .setup — enter + confirm → deliver to onAuthenticated (caller handles security)

    private func submitSetup(pin: String) {
        if let firstData = self.pendingPINEntry {
            if Data(pin.utf8) == firstData {
                self.hapticResult(.success)
                self.clearPending()
                self.onAuthenticated(pin)
            } else {
                self.clearPending()
                self.clearDigits()
                self.isProcessing    = false
                self.shake()
            }
        } else {
            self.pendingPINEntry = Data(pin.utf8)
            self.clearDigits()
            self.isProcessing    = false
        }
    }

    // .verify — single entry → route on PINVerifyResult

    private func submitVerify(pin: String) {
        let start     = Date()
        let result    = (try? self.security.verify(pin)) ?? .wrong
        let elapsed   = Date().timeIntervalSince(start)
        let remaining = max(0, self.timingPadDuration - elapsed)

        DispatchQueue.main.asyncAfter(deadline: .now() + remaining) {
            self.security.applyVerifyState(for: result)
            self.route(result, pin: pin)
        }
    }

    // .verifyCurrentLayer — checkCurrentLayerPIN; no counter mutation; no duress/wipe routing.
    // In .duress, matches the duress verifier. In all other states, matches the normal verifier.

    private func submitVerifyCurrentLayer(pin: String) {
        let start     = Date()
        let matched   = self.security.checkCurrentLayerPIN(pin)
        let elapsed   = Date().timeIntervalSince(start)
        let remaining = max(0, self.timingPadDuration - elapsed)

        DispatchQueue.main.asyncAfter(deadline: .now() + remaining) {
            if matched {
                self.hapticResult(.success)
                self.onAuthenticated(pin)
            } else {
                self.clearDigits()
                self.isProcessing = false
                self.shake()
            }
        }
    }

    // .confirmThenSet phase 1 — verify current-layer PIN (no counter mutation)
    // Uses checkCurrentLayerPIN so the duress PIN is accepted in .duress state,
    // matching the PIN the coercer observed at unlock. When no duress verifier exists
    // (Secure Mode not active) the behaviour is identical to checkNormalPIN.

    private func submitConfirmPhase(pin: String, onComplete: @escaping (String, String) -> Void) {
        let start     = Date()
        let matched   = self.security.checkCurrentLayerPIN(pin)
        let elapsed   = Date().timeIntervalSince(start)
        let remaining = max(0, self.timingPadDuration - elapsed)

        DispatchQueue.main.asyncAfter(deadline: .now() + remaining) {
            if matched {
                self.hapticResult(.success)
                self.authenticatedLayerPIN = Data(pin.utf8)
                self.clearDigits()
                self.isProcessing          = false
            } else {
                self.clearDigits()
                self.isProcessing = false
                self.shake()
            }
        }
    }

    // .confirmThenSet phase 2 — enter + confirm new duress PIN → onComplete(layerAuthenticationPIN, duressPIN)

    private func submitSetPhase(pin currentEntryPIN: String, onComplete: @escaping (String, String) -> Void) {
        guard let layerAuthData = self.authenticatedLayerPIN else { return }
        let layerAuthPIN = String(bytes: layerAuthData, encoding: .utf8) ?? ""

        if let duressPINData = self.pendingPINEntry {
            let duressPIN = String(bytes: duressPINData, encoding: .utf8) ?? ""
            if currentEntryPIN == duressPIN && currentEntryPIN != layerAuthPIN {
                self.hapticResult(.success)
                self.clearPending()
                self.clearAuthPIN()
                onComplete(layerAuthPIN, currentEntryPIN)
            } else {
                self.clearPending()
                self.clearDigits()
                self.isProcessing    = false
                self.shake()
            }
        } else {
            self.pendingPINEntry = Data(currentEntryPIN.utf8)
            self.clearDigits()
            self.isProcessing    = false
        }
    }

    // MARK: Route

    private func route(_ result: PINVerifyResult, pin: String) {
        switch result {
        case .normal(depth: _):
            self.hapticResult(.success)
            self.clearDigits()
            self.onAuthenticated(pin)   // depth carried by applyVerifyState; not needed here
        case .duress:
            self.hapticResult(.success)  // identical to normal — deniability requires same feedback
            self.clearDigits()
            self.onDuress()
        case .wrong:
            self.clearDigits()
            self.isProcessing = false
            self.shake()   // shake() fires .error internally
        case .locked(let until):
            self.hapticResult(.warning)
            self.clearDigits()
            self.isProcessing     = false
            self.lockoutUntil     = until
            self.lockoutRemaining = Self.countdownText(until: until, from: Date.now)
        }
    }

    private static func countdownText(until: Date, from now: Date) -> String {
        let seconds = max(0, Int(until.timeIntervalSince(now)))
        if seconds >= 3600 {
            return String(format: "Try again in %d:%02d:%02d",
                          seconds / 3600, (seconds % 3600) / 60, seconds % 60)
        } else {
            return String(format: "Try again in %d:%02d", seconds / 60, seconds % 60)
        }
    }

    // MARK: Shake

    private func shake() {
        self.hapticResult(.error)
        let a       = Animation.easeOut(duration: 0.06)
        let offsets: [CGFloat] = [14, -14, 8, -8, 0]
        for (i, offset) in offsets.enumerated() {
            DispatchQueue.main.asyncAfter(deadline: .now() + Double(i) * 0.06) {
                withAnimation(a) { self.shakeOffset = offset }
            }
        }
    }

    // MARK: Haptics

    private func hapticSelection() {
        UISelectionFeedbackGenerator().selectionChanged()
    }

    private func hapticResult(_ type: UINotificationFeedbackGenerator.FeedbackType) {
        UINotificationFeedbackGenerator().notificationOccurred(type)
    }
}

// MARK: - Keypad Button

private struct KeypadButton: View {

    let label:    String
    var isSymbol: Bool = false
    var disabled: Bool = false
    let action:   () -> Void

    @State private var pressed = false

    var body: some View {
        Button(action: self.action) {
            ZStack {
                Circle()
                    .fill(self.pressed ? Color.white.opacity(0.35) : Color.white.opacity(0.12))
                    .frame(width: 88, height: 88)

                Text(self.label)
                    .font(self.isSymbol ? .title2 : .title)
                    .fontWeight(self.isSymbol ? .regular : .light)
                    .foregroundStyle(self.disabled ? Color.white.opacity(0.3) : .white)
            }
        }
        .buttonStyle(.plain)
        .disabled(self.disabled)
        ._onButtonGesture(pressing: { isPressing in
            withAnimation(.easeInOut(duration: 0.08)) { self.pressed = isPressing }
        }, perform: {})
    }
}

// MARK: - Preview

#Preview {
    let container = try! ModelContainer(
        for: Schema([AppLayerConfig.self]),
        configurations: [ModelConfiguration(isStoredInMemoryOnly: true)]
    )
    PINEntry()
        .modelContainer(container)
        .environment(Manager.Security(modelContainer: container))
}
