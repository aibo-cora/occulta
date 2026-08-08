//
//  ActivityView.swift
//  Occulta
//
//  Created by Yura on 3/31/26.
//

import SwiftUI
import Foundation

struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]
    var applicationActivities: [UIActivity]? = nil
    /// Called when the activity sheet closes — both on completion and cancellation.
    /// `completed` is true only when the user picked an activity and it finished successfully.
    var onComplete: ((Bool) -> Void)? = nil

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let vc = UIActivityViewController(activityItems: self.activityItems, applicationActivities: self.applicationActivities)
        vc.completionWithItemsHandler = { _, completed, _, _ in
            self.onComplete?(completed)
        }
        return vc
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) { }
}
