//
//  AppDelegate.swift
//  Occulta
//

import UIKit
import Combine

class AppDelegate: NSObject, UIApplicationDelegate, ObservableObject {

    /// Programmatically injects AppScreen into every scene session.
    ///
    /// SwiftUI's build-time scene manifest overrides UISceneDelegateClassName in Info.plist,
    /// so the Info.plist entry is never read. This method is the Apple-documented path for
    /// connecting a scene delegate from a SwiftUI app — UIKit calls it when creating each
    /// scene session, and setting delegateClass causes AppScreen to be instantiated and
    /// wired for every scene.
    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let config = UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
        config.delegateClass = AppScreen.self
        return config
    }
}
