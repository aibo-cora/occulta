import UIKit
import Combine


class SceneDelegate: NSObject, UIWindowSceneDelegate, ObservableObject {
    weak var security: Manager.Security?
    
    func sceneDidBecomeActive(_ scene: UIScene) {
        #if DEBUG
        debugPrint("Handing active...")
        #endif
        
        self.security?.handleActive()
    }
    
    func sceneWillResignActive(_ scene: UIScene) {
        #if DEBUG
        debugPrint("Handing inactive...")
        #endif
        
        self.security?.handleInactive()
    }
    
    func sceneDidEnterBackground(_ scene: UIScene) {
        #if DEBUG
        debugPrint("Handing background...")
        #endif
        
        self.security?.handleBackground()
    }
}
