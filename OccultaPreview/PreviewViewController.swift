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
        
        // Clear previous content
        view.subviews.forEach { $0.removeFromSuperview() }
        view.backgroundColor = .systemBackground // Good practice for light/dark mode
        
        // Title label
        let titleLabel = UILabel()
        titleLabel.text = "Occulta Encrypted File"
        titleLabel.font = UIFont.boldSystemFont(ofSize: 26)
        titleLabel.textAlignment = .center
        titleLabel.textColor = .label
        
        // Instruction row: Share icon + text
        let shareIcon = UIImageView(image: UIImage(systemName: "square.and.arrow.up.circle"))
        shareIcon.tintColor = .systemGray
        shareIcon.contentMode = .scaleAspectFit
        shareIcon.preferredSymbolConfiguration = UIImage.SymbolConfiguration(pointSize: 48, weight: .medium)
        
        let instructionLabel = UILabel()
        instructionLabel.text = "Tap the Share button on screen and choose the Occulta app to import data."
        instructionLabel.font = UIFont.systemFont(ofSize: 18)
        instructionLabel.textAlignment = .center
        instructionLabel.numberOfLines = 0
        instructionLabel.textColor = .secondaryLabel
        
        // Horizontal stack for icon + instruction text
        let instructionStack = UIStackView(arrangedSubviews: [shareIcon, instructionLabel])
        instructionStack.axis = .horizontal
        instructionStack.alignment = .center
        instructionStack.spacing = 20
        
        // Warning label
        let warningLabel = UILabel()
        warningLabel.text = "Note: Do NOT open files that came from an untrusted source."
        warningLabel.font = UIFont.systemFont(ofSize: 16)
        warningLabel.textAlignment = .center
        warningLabel.numberOfLines = 0
        warningLabel.textColor = .systemRed
        
        // Main vertical stack
        let mainStack = UIStackView(arrangedSubviews: [titleLabel, instructionStack, warningLabel])
        mainStack.axis = .vertical
        mainStack.alignment = .center
        mainStack.spacing = 40
        mainStack.distribution = .fill
        
        view.addSubview(mainStack)
        mainStack.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            mainStack.leadingAnchor.constraint(greaterThanOrEqualTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 30),
            mainStack.trailingAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -30),
            mainStack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            mainStack.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
        
        // Ensure the share icon doesn't stretch
        shareIcon.setContentHuggingPriority(.required, for: .horizontal)
        shareIcon.setContentCompressionResistancePriority(.required, for: .horizontal)
        
        handler(nil)
    }
}
