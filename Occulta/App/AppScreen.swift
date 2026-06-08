//
//  AppScreen.swift
//  Occulta
//

import UIKit
import Combine

// MARK: - Phase

/// Single source of truth for what the user sees.
///
/// Phases advance in one direction per foreground cycle:
///   .covered → .pinRequired   (PIN required: grace expired or cold launch)
///   .covered → .unlocked      (no PIN, or within grace period)
///   .pinRequired → .unlocked  (via pinDidSucceed())
///
/// Once in .pinRequired the phase never regresses — a brief background and
/// return keeps .pinRequired until the correct PIN is entered.
enum ScreenPhase: Equatable {
    /// UIKit snapshot cover is on screen. Security evaluation pending.
    case covered
    /// Cover stays up; removed by pinViewAppeared() once PINEntry is visible.
    case pinRequired
    /// Content visible at security.currentDepth.
    case unlocked
}

// MARK: - AppScreen

/// Replaces SceneDelegate. Owns the UIKit snapshot cover, grace-period
/// evaluation, and the `phase` observable that drives the SwiftUI hierarchy.
///
/// Security cryptographic operations remain in Manager.Security.
/// Screen-state lifecycle — what the user sees — lives entirely here.
@MainActor
final class AppScreen: NSObject, UIWindowSceneDelegate, ObservableObject {

    // MARK: - Published

    @Published private(set) var phase: ScreenPhase = .covered

    // MARK: - Private

    private var security: Manager.Security?
    private var coverView: UIView?
    private weak var windowScene: UIWindowScene?

    private static let gracePeriod: TimeInterval = 5 * 60

    /// Set in sceneDidEnterBackground; cleared on every foreground return.
    /// nil means cold launch or brief inactive-only interruption (Face ID,
    /// share sheet) — counted as zero background duration, no re-lock.
    private var backgroundEntryDate: Date?

    // MARK: - UIWindowSceneDelegate

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options: UIScene.ConnectionOptions) {
        self.windowScene = scene as? UIWindowScene
        // Cover installed in sceneWillEnterForeground once the window exists.
    }

    /// Fires on cold launch and on every warm-from-background return.
    /// On warm returns the cover is already up from sceneWillResignActive;
    /// the guard inside installCover() prevents double-installation.
    func sceneWillEnterForeground(_ scene: UIScene) {
        guard let ws = scene as? UIWindowScene else { return }
        self.installCover(for: ws)
    }

    /// Synchronous cover install — must complete before this method returns
    /// so iOS captures the cover (not live content) in the app-switcher snapshot.
    func sceneWillResignActive(_ scene: UIScene) {
        guard let ws = scene as? UIWindowScene else { return }
        self.installCover(for: ws)
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        self.backgroundEntryDate = Date()
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        // Skip evaluation on cold launch: security isn't wired yet.
        // wire() drives evaluation after the first SwiftUI render.
        guard self.security != nil else { return }

        if self.phase == .pinRequired {
            // PINEntry is already on screen. Remove the transient cover installed
            // by sceneWillResignActive (app-switcher visit, Face ID, banner pull-down)
            // and clear the background date so the post-PIN grace period isn't
            // poisoned by this stale measurement.
            self.backgroundEntryDate = nil
            self.removeCover()
            return
        }

        self.evaluate(coldLaunch: false)
    }

    // MARK: - Wiring (called once from RootView .task)

    func wire(security: Manager.Security) {
        // Guard prevents a SwiftUI .task re-fire from re-evaluating as a cold
        // launch and incorrectly presenting PINEntry mid-session.
        guard self.security == nil else { return }
        self.security = security
        self.evaluate(coldLaunch: true)
    }

    // MARK: - PIN gate callbacks (called from RootView)

    /// PINEntry.onAppear — PIN view is on screen, safe to drop the UIKit cover.
    func pinViewAppeared() {
        self.removeCover()
    }

    /// Called from onNormal/onDuress after successful authentication.
    func pinDidSucceed() {
        self.phase = .unlocked
    }

    // MARK: - Evaluation

    private func evaluate(coldLaunch: Bool) {
        guard let security = self.security else { return }

        guard security.requiresPIN, security.pinEnabled else {
            self.removeCover()
            self.phase = .unlocked
            return
        }

        if coldLaunch {
            // Cold launch always requires PIN regardless of background duration.
            self.phase = .pinRequired
            return
        }

        let elapsed = self.backgroundEntryDate.map { Date().timeIntervalSince($0) } ?? 0
        self.backgroundEntryDate = nil

        if elapsed > Self.gracePeriod {
            self.phase = .pinRequired
        } else {
            // Brief inactive or within grace period — no PIN needed.
            self.removeCover()
            self.phase = .unlocked
        }
    }

    // MARK: - Cover

    private func installCover(for scene: UIWindowScene) {
        guard let window = scene.windows.first(where: { !$0.isHidden }) else { return }
        guard self.coverView == nil else { return }  // already installed

        let cover = UIView(frame: window.bounds)
        cover.backgroundColor = .systemBackground
        cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]

        let spinner = UIActivityIndicatorView(style: .medium)
        spinner.startAnimating()
        spinner.center = CGPoint(x: cover.bounds.midX, y: cover.bounds.midY)
        spinner.autoresizingMask = [.flexibleTopMargin, .flexibleBottomMargin,
                                    .flexibleLeftMargin, .flexibleRightMargin]
        cover.addSubview(spinner)

        CATransaction.begin()
        CATransaction.setDisableActions(true)
        window.addSubview(cover)
        CATransaction.commit()

        self.coverView = cover
    }

    private func removeCover() {
        self.coverView?.removeFromSuperview()
        self.coverView = nil
    }
}
