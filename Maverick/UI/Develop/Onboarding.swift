//
//  Onboarding.swift
//  Maverick
//
//  Created by Yura on 11/25/25.
//

import SwiftUI
import Combine

struct Onboarding: View {
    @State private var selection: Int = 0
    private var timer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()
    @State private var isAnimating: Bool = false
    
    var body: some View {
        TabView {
            Text("Do you ever feel that you are not the owner of your own data? That is being analyzed and sold without your knowledge or consent?")
                .padding()
                .tag(0)
            
            VStack {
                Text("Bring your phones together to create a life long link.")
                    .padding()
                
                HStack(spacing: 30) {
                    Image(systemName: "iphone.radiowaves.left.and.right")
                        .font(.system(size: 75))
                        .symbolEffect(.variableColor.reversing.iterative, value: self.isAnimating)
                    
                    Image(systemName: "iphone.radiowaves.left.and.right")
                        .font(.system(size: 75))
                        .symbolEffect(.variableColor.reversing.iterative, value: self.isAnimating)
                }
            }
            .tag(1)
            
            VStack(spacing: 40) {
                Text("Now you can encrypt anything for them —\ntoday, tomorrow, or in 20 years.\n\nNo servers. No accounts. Just keys.")
                    .multilineTextAlignment(.center)
                
                Button("Get Started") {
                    UserDefaults.standard.set(true, forKey: "hasSeenOnboarding")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
        }
        .tabViewStyle(.page)
        .indexViewStyle(PageIndexViewStyle(backgroundDisplayMode: .always))
        .onReceive(self.timer) { date in
            self.isAnimating.toggle()
        }
    }
}

#Preview {
    Onboarding()
}
