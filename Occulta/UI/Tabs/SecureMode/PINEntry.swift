//
//  PINEntry.swift
//  Occulta
//

import SwiftUI
import SwiftData

// MARK: - View

struct PINEntry: View {

    // MARK: Mode

    enum Mode {
        case verify
        /// Like .verify but routes through checkNormalPIN — no counter mutation.
        /// Use for Settings-level confirmations where wrong attempts must not
        /// increment the wipe counter.
        case verifyNormal
        /// Two-phase entry: first entry sets `firstPIN`, second entry must match it.
        /// On match, calls `onNormal(pin)` with the confirmed PIN and does **not** call
        /// any security method internally — the caller's `onNormal` closure is responsible
        /// for the actual security operation (e.g. `configurePIN`, `disablePINFromCurrentDepth`,
        /// `reEnablePIN`). This keeps the view decoupled from which operation is being confirmed.
        case setup
        /// Phase 1: verify existing normal PIN. Phase 2: enter + confirm new PIN.
        /// Delivers (confirmedNormalPIN, newPIN) to onComplete.
        case confirmThenSet(onComplete: (String, String) -> Void)
    }

    // MARK: Callbacks

    var mode:     Mode             = .verify
    var onNormal: (String) -> Void = { _ in }
    var onDuress: () -> Void       = {}
    var onWipe:   () -> Void       = {}

    // MARK: Dependencies

    @Environment(Manager.Security.self) private var security

    // MARK: State

    @State private var digits:       Data    = Data()
    @State private var shakeOffset:  CGFloat = 0
    @State private var isVerifying:  Bool    = false
    @State private var firstPIN:     String? = nil
    @State private var confirmedPIN: String? = nil  // phase-1 result for .confirmThenSet

    private let pinLength:    Int          = 6
    private let gateDuration: TimeInterval = 0.5

    // MARK: Derived

    private var title: String {
        switch self.mode {
        case .verify, .verifyNormal:
            return "Passcode"
        case .setup:
            return self.firstPIN != nil ? "Confirm Passcode" : "Passcode"
        case .confirmThenSet:
            guard self.confirmedPIN != nil else { return "Passcode" }
            return self.firstPIN != nil ? "Confirm Passcode" : "New Passcode"
        }
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer()

                Text(self.title)
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
                                KeypadButton(label: "\(digit)", disabled: self.isVerifying) {
                                    self.append(digit)
                                }
                            }
                        }
                    }
                    HStack(spacing: 20) {
                        Color.clear.frame(width: 88, height: 88)
                        KeypadButton(label: "0", disabled: self.isVerifying) {
                            self.append(0)
                        }
                        KeypadButton(label: "⌫", isSymbol: true, disabled: self.isVerifying) {
                            self.deleteLast()
                        }
                    }
                }

                Spacer()
            }
            .padding(.horizontal, 32)
        }
    }

    // MARK: Input

    private func append(_ digit: Int) {
        guard !self.isVerifying, self.digits.count < self.pinLength else { return }
        self.digits.append(UInt8(digit))
        if self.digits.count == self.pinLength { self.submit() }
    }

    private func deleteLast() {
        guard !self.digits.isEmpty else { return }
        self.digits[self.digits.count - 1] = 0
        self.digits.removeLast()
    }

    private func clearDigits() {
        _ = self.digits.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
        self.digits.removeAll()
    }

    // MARK: Submit

    private func submit() {
        self.isVerifying = true
        let pin = self.digits.map { String($0) }.joined()

        switch self.mode {
        case .setup:
            self.submitSetup(pin: pin)
        case .verify:
            self.submitVerify(pin: pin)
        case .verifyNormal:
            self.submitVerifyNormal(pin: pin)
        case .confirmThenSet(let onComplete):
            if self.confirmedPIN == nil {
                self.submitConfirmPhase(pin: pin, onComplete: onComplete)
            } else {
                self.submitSetPhase(pin: pin, onComplete: onComplete)
            }
        }
    }

    // .setup — enter + confirm → deliver to onNormal (caller handles security)

    private func submitSetup(pin: String) {
        if let first = self.firstPIN {
            if pin == first {
                self.onNormal(pin)
            } else {
                self.firstPIN    = nil
                self.clearDigits()
                self.isVerifying = false
                self.shake()
            }
        } else {
            self.firstPIN    = pin
            self.clearDigits()
            self.isVerifying = false
        }
    }

    // .verify — single entry → route on PINVerifyResult

    private func submitVerify(pin: String) {
        let start     = Date()
        let result    = (try? self.security.verify(pin)) ?? .wrong
        let elapsed   = Date().timeIntervalSince(start)
        let remaining = max(0, self.gateDuration - elapsed)

        DispatchQueue.main.asyncAfter(deadline: .now() + remaining) {
            self.route(result, pin: pin)
        }
    }

    // .verifyNormal — checkNormalPIN only; no counter mutation; no duress/wipe routing

    private func submitVerifyNormal(pin: String) {
        let start     = Date()
        let matched   = self.security.checkNormalPIN(pin)
        let elapsed   = Date().timeIntervalSince(start)
        let remaining = max(0, self.gateDuration - elapsed)

        DispatchQueue.main.asyncAfter(deadline: .now() + remaining) {
            if matched {
                self.onNormal(pin)
            } else {
                self.clearDigits()
                self.isVerifying = false
                self.shake()
            }
        }
    }

    // .confirmThenSet phase 1 — verify current-layer PIN (no counter mutation)
    // Uses checkCurrentLayerPIN so the duress PIN is accepted in .duress state,
    // matching the PIN the coercer observed at unlock. From .pinOnly the behaviour
    // is identical to checkNormalPIN (only one verifier exists).

    private func submitConfirmPhase(pin: String, onComplete: @escaping (String, String) -> Void) {
        let start     = Date()
        let matched   = self.security.checkCurrentLayerPIN(pin)
        let elapsed   = Date().timeIntervalSince(start)
        let remaining = max(0, self.gateDuration - elapsed)

        DispatchQueue.main.asyncAfter(deadline: .now() + remaining) {
            if matched {
                self.confirmedPIN = pin
                self.clearDigits()
                self.isVerifying  = false
            } else {
                self.clearDigits()
                self.isVerifying = false
                self.shake()
            }
        }
    }

    // .confirmThenSet phase 2 — enter + confirm new PIN → onComplete(normalPIN, newPIN)

    private func submitSetPhase(pin: String, onComplete: @escaping (String, String) -> Void) {
        guard let normalPIN = self.confirmedPIN else { return }

        if let first = self.firstPIN {
            if pin == first {
                onComplete(normalPIN, pin)
            } else {
                self.firstPIN    = nil
                self.clearDigits()
                self.isVerifying = false
                self.shake()
            }
        } else {
            self.firstPIN    = pin
            self.clearDigits()
            self.isVerifying = false
        }
    }

    // MARK: Route

    private func route(_ result: PINVerifyResult, pin: String) {
        switch result {
        case .normal: self.onNormal(pin)
        case .duress: self.onDuress()
        case .wrong:
            self.clearDigits()
            self.isVerifying = false
            self.shake()
        case .wipe:   self.onWipe()
        }
    }

    // MARK: Shake

    private func shake() {
        let a       = Animation.easeOut(duration: 0.06)
        let offsets: [CGFloat] = [14, -14, 8, -8, 0]
        for (i, offset) in offsets.enumerated() {
            DispatchQueue.main.asyncAfter(deadline: .now() + Double(i) * 0.06) {
                withAnimation(a) { self.shakeOffset = offset }
            }
        }
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
