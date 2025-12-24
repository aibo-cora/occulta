//
//  Verify.swift
//  Maverick
//
//  Created by Yura on 12/23/25.
//

import SwiftUI

struct Verify: View {
    var body: some View {
        NavigationStack {
            VStack {
                VStack(spacing: 20) {
                    Text("Copy the message containing a signature to the clipboard and press **Verify**.")
                }
                .padding()
                
                Spacer()
                
                Button("Verify", systemImage: "checkmark.bubble", role: .cancel) {
                    
                }
                .prominentButtonStyle()
            }
            .navigationTitle(MaverickApp.Tabs.verify.rawValue.capitalized)
        }
    }
}

#Preview {
    Verify()
}
