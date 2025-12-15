import QuickLook
import UIKit

class PreviewViewController: UIViewController, QLPreviewingController {
    
    func preparePreviewOfFile(at url: URL, completionHandler handler: @escaping (Error?) -> Void) {
        let accessing = url.startAccessingSecurityScopedResource()
        
        defer {
            if accessing {
                url.stopAccessingSecurityScopedResource()
            }
        }
        
        // Clear any existing subviews
        view.subviews.forEach { $0.removeFromSuperview() }
        
        // Create the three labels
        let titleLabel = UILabel()
        titleLabel.text = "Maverick Encrypted File"
        titleLabel.font = UIFont.boldSystemFont(ofSize: 24)
        titleLabel.textAlignment = .center
        titleLabel.textColor = .label
        
        let instructionLabel = UILabel()
        instructionLabel.text = "Tap \"Share\" and choose the Maverick app to import data."
        instructionLabel.font = UIFont.systemFont(ofSize: 18)
        instructionLabel.textAlignment = .center
        instructionLabel.numberOfLines = 0
        instructionLabel.textColor = .secondaryLabel
        
        let warningLabel = UILabel()
        warningLabel.text = "Note: Do NOT open files that came from an untrusted source."
        warningLabel.font = UIFont.systemFont(ofSize: 16)
        warningLabel.textAlignment = .center
        warningLabel.numberOfLines = 0
        warningLabel.textColor = .systemRed
        
        // Create a vertical stack view to arrange them neatly
        let stackView = UIStackView(arrangedSubviews: [titleLabel, instructionLabel, warningLabel])
        stackView.axis = .vertical
        stackView.alignment = .center
        stackView.spacing = 32
        stackView.distribution = .fill
        
        // Add stack view to the main view
        view.addSubview(stackView)
        
        // Constrain stack view to safe area with comfortable margins
        stackView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            stackView.leadingAnchor.constraint(greaterThanOrEqualTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 20),
            stackView.trailingAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -20),
            stackView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stackView.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
        
        // Optional: Add some padding around the text
        titleLabel.setContentHuggingPriority(.required, for: .vertical)
        instructionLabel.setContentHuggingPriority(.defaultHigh, for: .vertical)
        warningLabel.setContentHuggingPriority(.defaultHigh, for: .vertical)
        
        handler(nil)
    }
}
