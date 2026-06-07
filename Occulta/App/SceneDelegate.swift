import UIKit
import Combine

class SceneDelegate: NSObject, UIWindowSceneDelegate, ObservableObject {
    weak var security: Manager.Security?
    private var coverView: UIView?

    func sceneDidBecomeActive(_ scene: UIScene) {
        self.removeCover()
        self.security?.handleActive()
    }

    func sceneWillResignActive(_ scene: UIScene) {
        self.installCover(for: scene)
        self.security?.handleInactive()
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        self.security?.handleBackground()
    }

    // MARK: - Snapshot cover

    private func installCover(for scene: UIScene) {
        guard let window = (scene as? UIWindowScene)?.windows.first(where: { !$0.isHidden }) else { return }

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
