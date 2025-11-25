//
//  MinimalOnboardingView.swift
//  Maverick
//
//  Created by Yura on 11/25/25.
//


import SwiftUI

struct MinimalOnboardingView: View {
    @State private var page = 0
    
    var body: some View {
        TabView(selection: $page) {
            // Screen 1
            OnboardingPage(
                title: "Your secure contacts shouldn’t be trapped\ninside someone else’s app.",
                systemImage: "lock.fill",
                backgroundColor: Color(.systemBackground)
            )
            .tag(0)
            
            // Screen 2
            OnboardingPage(
                title: "Hold phones together for one second\n→ permanently linked forever.",
                systemImage: "wave.3.forward",
                backgroundColor: Color(.systemBackground),
                showRipple: true
            )
            .tag(1)
            
            // Screen 3
            VStack(spacing: 40) {
                Text("Now you can encrypt anything for them —\ntoday, tomorrow, or in 20 years.\n\nNo servers. No accounts. Just keys.")
                    .multilineTextAlignment(.center)
                    .font(.title2)
                    .foregroundStyle(.primary)
                
                Button("Get Started") {
                    // Dismiss onboarding, go to main app
                    UserDefaults.standard.set(true, forKey: "hasSeenOnboarding")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
            .padding(40)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(.systemBackground))
            .tag(2)
        }
        .tabViewStyle(PageTabViewStyle())
        .indexViewStyle(PageIndexViewStyle(backgroundDisplayMode: .always))
    }
}

struct OnboardingPage: View {
    let title: String
    let systemImage: String
    var backgroundColor: Color = Color(.systemBackground)
    var foregroundColor: Color = .primary
    var showRipple: Bool = false
    
    var body: some View {
        VStack(spacing: 30) {
            if showRipple {
                RippleAnimation()
                    .frame(width: 200, height: 200)
            } else {
                Image(systemName: systemImage)
                    .font(.system(size: 90))
                    .foregroundStyle(foregroundColor)
            }
            
            Text(title)
                .multilineTextAlignment(.center)
                .font(.title2)
                .fontWeight(.medium)
                .foregroundStyle(foregroundColor)
                .padding(.horizontal, 40)
            
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(backgroundColor)
    }
}

// Tiny ripple animation used in Screen 2
struct RippleAnimation: View {
    @State private var animate = false
    
    var body: some View {
        ZStack {
            ForEach(0..<4) { i in
                Circle()
                    .stroke(Color.gray.opacity(0.3), lineWidth: 4)
                    .scaleEffect(animate ? 2 : 0.5)
                    .opacity(animate ? 0 : 1)
                    .animation(
                        Animation.easeOut(duration: 1.5)
                            .repeatForever(autoreverses: false)
                            .delay(Double(i) * 0.3),
                        value: animate
                    )
            }
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 80))
                .foregroundColor(.green)
                .opacity(animate ? 1 : 0)
                .scaleEffect(animate ? 1 : 0.5)
                .animation(.easeOut(duration: 0.6).delay(0.9), value: animate)
        }
        .onAppear { animate = true }
    }
}

#Preview {
    MinimalOnboardingView()
}
