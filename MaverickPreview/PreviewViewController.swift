import QuickLook
import UIKit

class PreviewViewController: UIViewController, QLPreviewingController {
    
    func preparePreviewOfFile(at url: URL, completionHandler handler: @escaping (Error?) -> Void) {
        let accessing = url.startAccessingSecurityScopedResource()
        
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        
        let label = UILabel(frame: view.bounds)
        
        label.text = "Maverick Encrypted File\n\n\nTap \"Share\" and choose the Maverick app to import data.\n\n\nNote: Do NOT open files that came from an untrusted source."
        label.textAlignment = .center
        label.numberOfLines = 0
        
        self.view.addSubview(label)
        
        handler(nil)
    }
}
