//
//  KeyExchangeLiveView.swift
//  Occulta
//

import SwiftUI

struct KeyExchangeLiveView: View {
    let manager: ExchangeManager

    @Environment(\.scenePhase) private var scenePhase
    @State private var ringPulse: Bool = false
    @State private var displayPhaseIndex: Int = 0

    private enum DisplayPhase: Int {
        case searching = 0, found, connected, identityExchanged, mlKemExchanged, complete
    }

    private var displayStep: DisplayPhase {
        DisplayPhase(rawValue: self.displayPhaseIndex) ?? .complete
    }

    private var targetPhaseIndex: Int {
        switch self.manager.phase {
        case .resting, .searching:
            return 0
        case .found:
            return 1
        case .connected:
            return 2
        case .identityExchanged:
            return 3
        case .mlKemExchanged:
            return 4
        case .confirming, .complete:
            return 5
        case .timedOut, .failed:
            return self.displayPhaseIndex
        }
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            ParticleFieldView(
                phase: self.displayPhaseIndex,
                directionXY: self.manager.direction.map { CGPoint(x: CGFloat($0.x), y: CGFloat(-$0.y)) },
                distance: self.manager.distance
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer().frame(height: 24)

                Text(self.phaseLabel)
                    .font(.system(size: 10, design: .monospaced).weight(.semibold))
                    .kerning(2)
                    .foregroundStyle(.white.opacity(0.4))
                    .animation(.easeInOut(duration: 0.4), value: self.phaseLabel)

                Spacer().frame(height: 6)

                Text(self.statusText)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.9))
                    .multilineTextAlignment(.center)
                    .animation(.easeInOut(duration: 0.4), value: self.statusText)

                Spacer().frame(height: 20)

                self.proximityRing

                Spacer().frame(height: 16)

                if self.displayPhaseIndex >= 3 {
                    self.fingerprintGrid
                        .transition(.opacity.animation(.easeInOut(duration: 0.4)))
                }

                Spacer()

                self.stepPills
            }
            .animation(.easeInOut(duration: 0.3), value: self.displayPhaseIndex)
        }
        .onChange(of: self.targetPhaseIndex) { _, new in
            self.displayPhaseIndex = new
        }
        .onChange(of: self.scenePhase) { _, newPhase in
            if newPhase == .background { self.manager.finish() }
        }
    }

    // MARK: - Subviews

    private var proximityRing: some View {
        let dist = self.manager.distance
        let accentColor = self.accentColor

        return ZStack {
            Canvas { ctx, size in
                let cx = size.width / 2, cy = size.height / 2
                let r: CGFloat = 60, lw: CGFloat = 8

                var track = Path()
                track.addArc(center: CGPoint(x: cx, y: cy), radius: r,
                             startAngle: .degrees(0), endAngle: .degrees(360), clockwise: false)
                ctx.stroke(track, with: .color(.white.opacity(0.07)), style: StrokeStyle(lineWidth: lw))

                let ratio = Double(max(0, min(1, 1 - (dist ?? 1.0) / 0.85)))
                if ratio > 0 {
                    var arc = Path()
                    arc.addArc(center: CGPoint(x: cx, y: cy), radius: r,
                               startAngle: .degrees(-90), endAngle: .degrees(-90 + 360 * ratio), clockwise: false)
                    ctx.stroke(arc, with: .color(accentColor), style: StrokeStyle(lineWidth: lw, lineCap: .round))
                }
            }
            .frame(width: 140, height: 140)

            Circle()
                .stroke(accentColor.opacity(0.25), lineWidth: 2)
                .frame(width: 152, height: 152)
                .scaleEffect(self.ringPulse ? 1.12 : 1.0)
                .opacity(self.ringPulse ? 0.0 : 1.0)
                .animation(.easeInOut(duration: 1.2).repeatForever(autoreverses: false), value: self.ringPulse)

            VStack(spacing: 2) {
                let distCm = dist.map { Int(($0 * 100).rounded()) }
                
                Text(distCm.map { "\($0)" } ?? "—")
                    .font(.system(size: 28, design: .monospaced).weight(.bold))
                    .foregroundStyle(distCm.map { $0 <= 25 } == true ? Color.occultaVerified : .white)
                    .privacySensitive()
                Text("cm")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.5))
            }
        }
        .opacity(self.displayPhaseIndex > 0 ? 1 : 0)
        .animation(.easeInOut(duration: 0.6), value: self.displayPhaseIndex > 0)
        .onAppear { self.ringPulse = true }
    }

    private var fingerprintGrid: some View {
        let cellColor: Color = self.displayStep == .mlKemExchanged
            ? Color(red: 90/255, green: 74/255, blue: 176/255)
            : .occultaVerified

        return LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 4), spacing: 4) {
            ForEach(Array(self.fingerprintCells().enumerated()), id: \.offset) { _, cell in
                Text(cell)
                    .font(.system(size: 9, design: .monospaced).weight(.bold))
                    .foregroundStyle(cellColor)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 4)
                    .overlay(
                        RoundedRectangle(cornerRadius: 3)
                            .stroke(cellColor.opacity(0.3), lineWidth: 0.5)
                    )
            }
        }
        .padding(.horizontal, 24)
        .animation(.easeInOut(duration: 0.3), value: cellColor)
        .privacySensitive()
    }

    private var stepPills: some View {
        HStack(spacing: 6) {
            ForEach(0..<6) { i in
                RoundedRectangle(cornerRadius: 2)
                    .fill(self.pillColor(for: i))
                    .frame(width: i == self.displayPhaseIndex ? 40 : 24, height: 4)
                    .animation(.easeInOut(duration: 0.3), value: self.displayPhaseIndex)
            }
        }
        .padding(.bottom, 12)
    }

    // MARK: - Derived state

    private var phaseLabel: String {
        switch self.displayStep {
        case .searching:         
            return "01 · SEARCHING"
        case .found:             
            return "02 · FOUND"
        case .connected:         
            return "03 · CONNECTED"
        case .identityExchanged: 
            return "04 · IDENTITY KEY"
        case .mlKemExchanged:    
            return "05 · ML-KEM"
        case .complete:          
            return "06 · COMPLETE"
        }
    }

    private var statusText: String {
        switch self.displayStep {
        case .searching:         
            return "Looking for a peer..."
        case .found:             
            return "Peer found, move closer"
        case .connected:         
            return "Proximity confirmed, sending identity key..."
        case .identityExchanged:
            return "Identity key received, sending quantum key..."
        case .mlKemExchanged:
            return "Post-quantum layer received"
        case .complete:          
            return "Verified · stored"
        }
    }

    private var accentColor: Color {
        switch self.displayStep {
        case .searching:
            return .occultaAccent
        case .found:
            return .occultaWarn
        case .connected, .complete:
            return .occultaVerified
        case .identityExchanged:
            return Color(red: 58/255, green: 92/255, blue: 191/255)
        case .mlKemExchanged:
            return Color(red: 90/255, green: 74/255, blue: 176/255)
        }
    }

    private func fingerprintCells() -> [String] {
        let fingerprint: Data?
        switch self.manager.phase {
        case .identityExchanged(let fp):
            fingerprint = fp
        case .mlKemExchanged(let p), .confirming(let p):
            fingerprint = p.fingerprint
        default:
            fingerprint = nil
        }
        guard let fp = fingerprint else { return Array(repeating: "••••", count: 12) }
        return (0..<12).map { i in
            let idx = i * 2
            guard idx + 1 < fp.count else { return "••••" }
            return String(format: "%02X%02X", fp[idx], fp[idx + 1])
        }
    }

    private func pillColor(for i: Int) -> Color {
        if i < self.displayPhaseIndex { return .occultaVerified }
        if i == self.displayPhaseIndex { return .occultaAccent }
        return .white.opacity(0.12)
    }
}

#Preview {
    KeyExchangeLiveView(manager: ExchangeManager())
}
