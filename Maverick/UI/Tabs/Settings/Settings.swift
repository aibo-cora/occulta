//
//  Settings.swift
//  Maverick
//
//  Created by Yura on 12/9/25.
//

import SwiftUI

struct Settings: View {
    var body: some View {
        NavigationStack {
            Text("Information")
                .navigationTitle("Settings")
        }
    }
}

#Preview {
    Settings()
        .environment(ContactManager.preview)
}
