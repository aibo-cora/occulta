//
//  PINEntry.swift
//  Occulta
//

import SwiftUI
import SwiftData

// MARK: - View

struct PINEntry: View {

    // MARK: Callbacks

    var onNormal: () -> Void = {}
    var onDuress: () -> Void = {}
    var onWipe:   () -> Void = {}

    // MARK: Dependencies

    @Environment(Manager.Security.self) private var security

    // MARK: State

    @State private var digits:      [Int]   = []
    @State private var shakeOffset: CGFloat = 0
    @State private var isVerifying: Bool    = false

    private let pinLength:    Int           = 6
    private let gateDuration: TimeInterval  = 0.5

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer()

                Text("Passcode")
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
        self.digits.append(digit)
        if self.digits.count == self.pinLength { self.submit() }
    }

    private func deleteLast() {
        guard !self.digits.isEmpty else { return }
        self.digits.removeLast()
    }

    // MARK: Verification

    private func submit() {
        self.isVerifying = true
        let pin   = self.digits.map { String($0) }.joined()
        let start = Date()

        // verify() always attempts both sentinel checks regardless of outcome,
        // so all paths do equivalent crypto work. The gate pads any remaining gap.
        let result = (try? self.security.verify(pin)) ?? .wrong

        let elapsed   = Date().timeIntervalSince(start)
        let remaining = max(0, self.gateDuration - elapsed)

        DispatchQueue.main.asyncAfter(deadline: .now() + remaining) {
            self.route(result)
        }
    }

    private func route(_ result: PINVerifyResult) {
        switch result {
        case .normal:
            self.onNormal()
        case .duress:
            self.onDuress()
        case .wrong:
            self.digits      = []
            self.isVerifying = false
            self.shake()
        case .wipe:
            self.onWipe()
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
        for: Schema([SecureModeConfig.self]),
        configurations: [ModelConfiguration(isStoredInMemoryOnly: true)]
    )
    PINEntry()
        .modelContainer(container)
        .environment(Manager.Security(modelContainer: container))
}
