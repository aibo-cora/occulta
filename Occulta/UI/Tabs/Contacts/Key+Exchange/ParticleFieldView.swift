//
//  ParticleFieldView.swift
//  Occulta
//

import SwiftUI
import UIKit

final class ParticleCanvas: UIView {
    var animationPhase: Int = 0 {
        didSet { if oldValue != animationPhase { self.beginPhaseTransition() } }
    }

    /// Normalized peer direction in screen space: x in [-1,1] (left/right), y in [-1,1] (up/down).
    /// Nil when NI direction data is unavailable — no ring is shown.
    var peerDirectionXY: CGPoint? = nil
    var peerDistance: Float? = nil

    private struct Particle {
        var x, y, vx, vy, radius, angle, orbitR, orbitSpeed, col, row: Float
        var ring: Int
    }

    private var particles: [Particle] = []
    private var displayLink: CADisplayLink?
    private var tick: Float = 0

    /// Smoothly lerped ring center. Nil when direction is unavailable.
    private var ringCenter: CGPoint? = nil
    private let ringRadius: Float = 70

    private var currentR: Float = 211/255, currentG: Float =  79/255, currentB: Float =  44/255
    private var targetR:  Float = 211/255, targetG:  Float =  79/255, targetB:  Float =  44/255
    private var accentT: Float = 1.0

    private let accents: [(r: Float, g: Float, b: Float)] = [
        (211/255,  79/255,  44/255),
        (192/255, 138/255,  43/255),
        ( 46/255, 125/255,  91/255),
        ( 58/255,  92/255, 191/255),
        ( 90/255,  74/255, 176/255),
        ( 46/255, 125/255,  91/255),
    ]

    private let thresholds: [Float] = [90, 70, 45, 55, 35, 25]
    private let modes = ["brownian", "converge", "orbit", "lattice", "crystal", "settle"]

    override init(frame: CGRect) {
        super.init(frame: frame)
        self.isOpaque = false
        self.backgroundColor = .clear
        self.clearsContextBeforeDrawing = true
        self.initParticles()
        let dl = CADisplayLink(target: self, selector: #selector(self.step))
        dl.preferredFrameRateRange = CAFrameRateRange(minimum: 30, maximum: 60, preferred: 60)
        dl.add(to: .main, forMode: .common)
        self.displayLink = dl
    }

    required init?(coder: NSCoder) { fatalError() }

    deinit { self.displayLink?.invalidate() }

    private func initParticles() {
        let w = Float(max(self.bounds.width, 390))
        let h = Float(max(self.bounds.height, 700))
        self.particles = (0..<80).map { i in
            Particle(
                x: Float.random(in: 0...w),
                y: Float.random(in: 0...h),
                vx: Float.random(in: -0.6...0.6),
                vy: Float.random(in: -0.6...0.6),
                radius: Float.random(in: 1.5...3.0),
                angle: Float.random(in: 0...(2 * .pi)),
                orbitR: Float.random(in: 30...90),
                orbitSpeed: Float.random(in: 0.008...0.018) * (Bool.random() ? 1 : -1),
                col: Float(i % 10) / 9.0 * w * 0.8 + w * 0.1,
                row: Float(i / 10) / 7.0 * h * 0.8 + h * 0.1,
                ring: i % 4
            )
        }
    }

    private func beginPhaseTransition() {
        let a = self.accents[min(self.animationPhase, self.accents.count - 1)]
        self.targetR = a.r; self.targetG = a.g; self.targetB = a.b
        self.accentT = 0
    }

    @objc private func step() {
        self.tick += 1
        if self.accentT < 1 {
            self.accentT = min(1, self.accentT + 0.02)
            let t = self.accentT
            self.currentR += (self.targetR - self.currentR) * t
            self.currentG += (self.targetG - self.currentG) * t
            self.currentB += (self.targetB - self.currentB) * t
        }
        self.updateRingCenter()
        self.updateParticles()
        self.setNeedsDisplay()
    }

    // MARK: - Ring center

    private func updateRingCenter() {
        guard let dir = self.peerDirectionXY, let dist = self.peerDistance else {
            self.ringCenter = nil
            return
        }
        let w = Float(self.bounds.width), h = Float(self.bounds.height)
        guard w > 0, h > 0 else { return }
        let cx = CGFloat(w / 2), cy = CGFloat(h / 2)
        // Ring sits at the peer's direction, scaled by how far away they are.
        // factor → 1 when far (≥ 1m), → 0 when close (≤ 0.25m, ring centered).
        let factor = CGFloat(max(0, min(1, (dist - 0.25) / 0.75)))
        let maxOffset = CGFloat(min(w, h)) * 0.28
        let target = CGPoint(
            x: cx + dir.x * maxOffset * factor,
            y: cy + dir.y * maxOffset * factor
        )
        if let current = self.ringCenter {
            let speed: CGFloat = 0.025
            self.ringCenter = CGPoint(
                x: current.x + (target.x - current.x) * speed,
                y: current.y + (target.y - current.y) * speed
            )
        } else {
            // First appearance: start from screen center and drift to target.
            self.ringCenter = CGPoint(x: cx, y: cy)
        }
    }

    private var isDirected: Bool {
        self.ringCenter != nil && self.animationPhase <= 2
    }

    // MARK: - Particle update

    private func updateParticles() {
        let w = Float(self.bounds.width)
        let h = Float(self.bounds.height)
        guard w > 0, h > 0 else { return }
        let cx = w / 2, cy = h / 2
        let mode = self.isDirected
            ? "directed"
            : self.modes[min(self.animationPhase, self.modes.count - 1)]

        for i in self.particles.indices {
            switch mode {
            case "brownian":
                self.particles[i].vx += Float.random(in: -0.1...0.1)
                self.particles[i].vy += Float.random(in: -0.1...0.1)
                self.particles[i].vx *= 0.98
                self.particles[i].vy *= 0.98
                let spd = (self.particles[i].vx * self.particles[i].vx + self.particles[i].vy * self.particles[i].vy).squareRoot()
                if spd > 1.2 { self.particles[i].vx *= 1.2/spd; self.particles[i].vy *= 1.2/spd }

            case "converge":
                self.particles[i].vx += (cx - self.particles[i].x) * 0.003
                self.particles[i].vy += (cy - self.particles[i].y) * 0.003
                self.particles[i].vx += Float.random(in: -0.04...0.04)
                self.particles[i].vy += Float.random(in: -0.04...0.04)
                self.particles[i].vx *= 0.97
                self.particles[i].vy *= 0.97

            case "orbit":
                self.particles[i].angle += self.particles[i].orbitSpeed
                let r = self.particles[i].orbitR * 0.6
                self.particles[i].x += (cx + cos(self.particles[i].angle) * r - self.particles[i].x) * 0.04
                self.particles[i].y += (cy + sin(self.particles[i].angle) * r - self.particles[i].y) * 0.04
                continue

            case "lattice":
                let ripple = sin(self.tick * 0.05 - Float(i) * 0.3) * 8
                self.particles[i].x += (self.particles[i].col - self.particles[i].x) * 0.06
                self.particles[i].y += (self.particles[i].row + ripple - self.particles[i].y) * 0.06
                continue

            case "crystal":
                let dir: Float = self.particles[i].ring % 2 == 0 ? 1 : -1
                self.particles[i].angle += self.particles[i].orbitSpeed * 1.6 * dir
                let rings: [Float] = [25, 50, 75, 100]
                let r = rings[self.particles[i].ring]
                self.particles[i].x += (cx + cos(self.particles[i].angle) * r - self.particles[i].x) * 0.07
                self.particles[i].y += (cy + sin(self.particles[i].angle) * r - self.particles[i].y) * 0.07
                continue

            case "settle":
                self.particles[i].vx *= 0.96
                self.particles[i].vy *= 0.96
                self.particles[i].vx += Float.random(in: -0.02...0.02)
                self.particles[i].vy += Float.random(in: -0.02...0.02)

            case "directed":
                // Particles orbit the ring center, which itself drifts toward the peer's direction.
                let rc = self.ringCenter!
                self.particles[i].angle += self.particles[i].orbitSpeed
                let targetX = Float(rc.x) + cos(self.particles[i].angle) * self.ringRadius
                let targetY = Float(rc.y) + sin(self.particles[i].angle) * self.ringRadius
                self.particles[i].x += (targetX - self.particles[i].x) * 0.04
                self.particles[i].y += (targetY - self.particles[i].y) * 0.04
                continue

            default: break
            }

            self.particles[i].x = (self.particles[i].x + self.particles[i].vx).clamped(to: 0...w)
            self.particles[i].y = (self.particles[i].y + self.particles[i].vy).clamped(to: 0...h)
            if self.particles[i].x == 0 || self.particles[i].x == w { self.particles[i].vx *= -1 }
            if self.particles[i].y == 0 || self.particles[i].y == h { self.particles[i].vy *= -1 }
        }
    }

    override func draw(_ rect: CGRect) {
        guard let ctx = UIGraphicsGetCurrentContext() else { return }
        // Tighter connection threshold in directed mode keeps the ring outline clean.
        let thresh = self.isDirected
            ? Float(28)
            : self.thresholds[min(self.animationPhase, self.thresholds.count - 1)]
        let threshSq = thresh * thresh
        let r = CGFloat(self.currentR), g = CGFloat(self.currentG), b = CGFloat(self.currentB)

        ctx.setLineWidth(0.5)
        ctx.setStrokeColor(UIColor(red: r, green: g, blue: b, alpha: 0.18).cgColor)
        ctx.beginPath()
        var lineCount = 0
        outer: for i in 0..<self.particles.count {
            for j in (i+1)..<self.particles.count {
                let dx = self.particles[i].x - self.particles[j].x
                let dy = self.particles[i].y - self.particles[j].y
                if dx*dx + dy*dy < threshSq {
                    ctx.move(to: CGPoint(x: CGFloat(self.particles[i].x), y: CGFloat(self.particles[i].y)))
                    ctx.addLine(to: CGPoint(x: CGFloat(self.particles[j].x), y: CGFloat(self.particles[j].y)))
                    lineCount += 1
                    if lineCount == 200 { break outer }
                }
            }
        }
        ctx.strokePath()

        ctx.setFillColor(UIColor(red: r, green: g, blue: b, alpha: 0.9).cgColor)
        ctx.beginPath()
        for p in self.particles {
            let pr = CGFloat(p.radius)
            ctx.addEllipse(in: CGRect(x: CGFloat(p.x) - pr, y: CGFloat(p.y) - pr, width: pr*2, height: pr*2))
        }
        ctx.fillPath()
    }
}

private extension Float {
    func clamped(to range: ClosedRange<Float>) -> Float {
        Swift.min(Swift.max(self, range.lowerBound), range.upperBound)
    }
}

struct ParticleFieldView: UIViewRepresentable {
    let phase: Int
    let directionXY: CGPoint?  // normalized screen-space direction, x/y in [-1, 1]
    let distance: Float?

    func makeUIView(context: Context) -> ParticleCanvas { ParticleCanvas() }

    func updateUIView(_ view: ParticleCanvas, context: Context) {
        view.animationPhase = self.phase
        view.peerDirectionXY = self.directionXY
        view.peerDistance = self.distance
    }
}
