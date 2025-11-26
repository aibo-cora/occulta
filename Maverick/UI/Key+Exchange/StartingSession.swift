//
//  StartingSession.swift
//  Maverick
//
//  Created by Yura on 11/9/25.
//

import SwiftUI
import SwiftData
import Combine

struct StartingSession: View {
    @State private var isAnimating: Bool = false
    
    private var timer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()
    private let contactIdentifier: String
    
    /// Start an exchange session.
    /// - Parameter identifier: Identifier of our contact which is exchanging identities with us.
    init(withContact identifier: String) {
        self.contactIdentifier = identifier
    }
    
    /// <#Description#>
    var body: some View {
        VStack {
            Text("Bring your phones together with your contact to exchange identities.")
                .padding()
            
            HStack(spacing: 30) {
                Image(systemName: "iphone.radiowaves.left.and.right")
                    .font(.system(size: 100))
                    .symbolEffect(.variableColor.reversing.iterative, value: self.isAnimating)
                    .foregroundStyle(.blue)
            }
        }
        .onReceive(self.timer) { _ in
            self.isAnimating.toggle()
        }
    }
}

#Preview {
    StartingSession(withContact: UUID().uuidString)
}
