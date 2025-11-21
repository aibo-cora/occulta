//
//  StartingSession.swift
//  Maverick
//
//  Created by Yura on 11/9/25.
//

import SwiftUI
import SwiftData

struct StartingSession: View {
    @State private var exchangeManager: ExchangeManager = .init()
    
    
    var body: some View {
        Text(/*@START_MENU_TOKEN@*/"Hello, World!"/*@END_MENU_TOKEN@*/)
            .onReceive(self.exchangeManager.receivedIdentity) { identity in
                if let identity {
                    print("Received identity: \(identity)")
                }
            }
    }
}

#Preview {
    StartingSession()
}
