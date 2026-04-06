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

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: self.activityItems, applicationActivities: self.applicationActivities)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) { }
}
