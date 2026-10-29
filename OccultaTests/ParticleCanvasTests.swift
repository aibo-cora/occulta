//
//  ParticleCanvasTests.swift
//  OccultaTests
//
//  `ParticleCanvas` steps itself with a `CADisplayLink`, and a display link retains its target. A
//  link invalidated only in `deinit` therefore keeps its canvas from ever reaching `deinit`, and
//  the 60 Hz step outlives the screen that showed it. The key exchange and onboarding both show a
//  canvas; these pin that one is released once it is off screen.
//

import Testing
import UIKit
@testable import Occulta

@Suite("Particle canvas — released once off screen")
@MainActor
struct ParticleCanvasTests {

    @Test("A canvas removed from its window is released")
    func releasedAfterLeavingWindow() {
        weak var released: ParticleCanvas?

        autoreleasepool {
            let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 390, height: 844))
            let canvas = ParticleCanvas()
            released = canvas

            window.addSubview(canvas)
            canvas.removeFromSuperview()
        }

        #expect(released == nil)
    }

    @Test("A canvas never put in a window is released")
    func releasedWithoutWindow() {
        weak var released: ParticleCanvas?

        autoreleasepool {
            let canvas = ParticleCanvas()
            released = canvas
        }

        #expect(released == nil)
    }
}
