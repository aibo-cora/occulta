import SwiftUI

struct ForeverOnboardingView: View {
    @State private var pageIndex = 0
    @AppStorage("hasCompletedOnboarding") private var hasCompleted = false
    
    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            
            TabView(selection: self.$pageIndex) {
                // MARK: Screen 1 – The fear
                OnboardingPage1()
                    .tag(0)
                
                // MARK: Screen 2 – The promise
                OnboardingPage2()
                    .tag(1)
                
                // MARK: Screen 3 – Lifelong moments
                OnboardingPage3()
                    .tag(2)
                
                // MARK: Screen 4 – Unbreakable truth
                OnboardingPage4()
                    .tag(3)
                
                // MARK: Screen 5 – Invitation
                OnboardingPage5 {
                    withAnimation {
                        self.hasCompleted = true
                    }
                }
                .tag(4)
            }
            .tabViewStyle(PageTabViewStyle(indexDisplayMode: .never))
            .animation(.easeInOut, value: self.pageIndex)
            
            // Custom dots + skip button
            VStack {
                HStack {
                    Spacer()
                    Button("Skip") {
                        withAnimation {
                            self.hasCompleted = true
                        }
                    }
                    .foregroundColor(.secondary)
                    .padding()
                    .opacity(self.pageIndex < 4 ? 1 : 0)
                }
                
                Spacer()
                
                HStack(spacing: 8) {
                    ForEach(0..<5) { i in
                        Circle()
                            .frame(width: 8, height: 8)
                            .foregroundColor(self.pageIndex == i ? .primary : .secondary)
                            .scaleEffect(self.pageIndex == i ? 1.2 : 1)
                            .animation(.spring(response: 0.3), value: self.pageIndex)
                    }
                }
                .padding(.bottom, 50)
            }
        }
    }
}

// MARK: - Individual Pages

struct OnboardingPage1: View {
    @State private var showText = false
    
    var body: some View {
        VStack(spacing: 40) {
            Spacer()
            
            ZStack {
                Image(systemName: "person.3.fill")
                    .font(.system(size: 110))
                    .foregroundColor(.secondary.opacity(0.6))
            }
            
            VStack(spacing: 20) {
                Text("Build a cryptographic address book that only you can access.")
                    .font(.largeTitle)
                    .fontWeight(.semibold)
                    .multilineTextAlignment(.center)
                    .opacity(self.showText ? 1 : 0)
                    .offset(y: self.showText ? 0 : 20)
                
                HStack(alignment: .firstTextBaseline) {
                    Image(systemName: "arrow.right.circle")
                        .font(.title3)
                        .foregroundStyle(Color.accentColor)
                    Text("Let's see how to secure your data.")
                        .padding(.top, 20)
                        .font(.title3)
                        .multilineTextAlignment(.center)
                }
            }
            .padding(.horizontal, 40)
            
            Spacer()
        }
        .onAppear {
            withAnimation(.easeOut.delay(0.4)) {
                self.showText = true
            }
        }
    }
}

struct OnboardingPage2: View {
    @State private var glow = false
    
    private struct PhoneShape: Shape {
        func path(in rect: CGRect) -> Path {
            var path = Path()
            let corner: CGFloat = 30
            path.move(to: CGPoint(x: rect.minX + corner, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - corner, y: rect.minY))
            path.addArc(center: CGPoint(x: rect.maxX - corner, y: rect.minY + corner), radius: corner, startAngle: .degrees(270), endAngle: .degrees(0), clockwise: false)
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - corner))
            path.addArc(center: CGPoint(x: rect.maxX - corner, y: rect.maxY - corner), radius: corner, startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX + corner, y: rect.maxY))
            path.addArc(center: CGPoint(x: rect.minX + corner, y: rect.maxY - corner), radius: corner, startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + corner))
            path.addArc(center: CGPoint(x: rect.minX + corner, y: rect.minY + corner), radius: corner, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
            return path
        }
    }
    
    private struct PhonesTouching: View {
        var body: some View {
            HStack(spacing: 30) {
                VStack {
                    PhoneShape()
                        .frame(width: 140, height: 280)
                        .foregroundColor(.secondary.opacity(0.2))
                    
                    Text("Your Phone")
                }
                
                VStack {
                    PhoneShape()
                        .frame(width: 140, height: 280)
                        .foregroundColor(.secondary.opacity(0.2))
                        .rotationEffect(.degrees(180))
                    
                    Text("Anna's Phone")
                }
            }
        }
    }
    
    private struct PulsingRing: View {
        @State private var scale: CGFloat = 0.8
        
        var body: some View {
            Circle()
                .stroke(Color.white, lineWidth: 6)
                .scaleEffect(self.scale)
                .opacity(1 - self.scale)
                .animation(
                    Animation.easeOut(duration: 2)
                        .repeatForever(autoreverses: false),
                    value: self.scale
                )
                .onAppear {
                    self.scale = 2.0
                }
        }
    }
    
    var body: some View {
        VStack(spacing: 40) {
            ZStack {
                PhonesTouching()
                    .hueRotation(.degrees(self.glow ? 20 : 0))
                    .brightness(self.glow ? 0.2 : 0)
                
                PulsingRing()
                    .opacity(self.glow ? 1 : 0)
            }
            .frame(height: 300)
            
            VStack(spacing: 20) {
                Text("One second together.")
                    .font(.largeTitle)
                    .fontWeight(.semibold)
                
                Text("Secure forever.")
                    .font(.title)
                    .fontWeight(.medium)
                    .foregroundColor(.secondary)
                
                Text("After exchanging keys with someone, nothing can take this person away from you — not time, not companies, not broken phones.")
                    .font(.title3)
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 40)
            }
        }
        .onAppear {
            withAnimation(.easeInOut.repeatForever(autoreverses: true).delay(0.3)) {
                self.glow = true
            }
        }
    }
}

struct OnboardingPage3: View {
    let moments = [
        ("lock.shield.fill", "Confidentiality - Encrypted database of your contacts"),
        // ("signature", "Sign posts, documents, contracts, and more. Phishing is no longer a threat."),
        ("square.and.arrow.up.fill", "Share encrypted messages, photos, documents, and more."),
        ("hand.raised.fill", "Data Integrity, Source Authenticity - No data loss or theft"),
        ("box.truck.fill", "Use a varierty of delivery methods - SMS, email, and more"),
        ("infinity.circle.fill", "Apps come and go, your contacts stay trusted and secure"),
    ]
    
    @State private var currentMoment = -1
    
    private struct MomentRow: View {
        let icon: String
        let text: String
        let isVisible: Bool
        
        var body: some View {
            HStack(spacing: 20) {
                Image(systemName: self.icon)
                    .foregroundStyle(Color.accentColor)
                
                Text(self.text)
                
                Spacer()
            }
            .padding(.horizontal, 40)
            .offset(x: self.isVisible ? 0 : 300)
            .opacity(self.isVisible ? 1 : 0)
        }
    }
    
    var body: some View {
        VStack(spacing: 50) {
            Text("Features")
                .font(.title)
                .fontWeight(.bold)
            
            VStack(alignment: .listRowSeparatorLeading, spacing: 32) {
                ForEach(self.moments.indices, id: \.self) { index in
                    MomentRow(
                        icon: self.moments[index].0,
                        text: self.moments[index].1,
                        isVisible: index <= self.currentMoment
                    )
                    .animation(
                        .spring(response: 0.6, dampingFraction: 0.78, blendDuration: 0.5)
                        .delay(Double(index) * 1), value: self.currentMoment)
                }
            }
        }
        .onAppear {
            self.currentMoment = self.moments.count - 1
        }
    }
}

struct OnboardingPage4: View {
    @State private var ringRotation = 0.0
    
    private struct TitaniumRing: View {
        var body: some View {
            ZStack {
                Circle()
                    .stroke(AngularGradient(
                        gradient: Gradient(colors: [.clear, .primary.opacity(0.3), .clear]),
                        center: .center
                    ), lineWidth: 4)
                    .blur(radius: 3)
                
                Circle()
                    .stroke(Color.primary.opacity(0.15), lineWidth: 2)
            }
            .frame(width: 180, height: 180)
        }
    }
    
    var body: some View {
        VStack(spacing: 40) {
            ZStack {
                TitaniumRing()
                    .rotationEffect(.degrees(self.ringRotation))
                    .onAppear {
                        withAnimation(.linear(duration: 20).repeatForever(autoreverses: false)) {
                            self.ringRotation = 360
                        }
                    }
                
                Image(systemName: "cpu.fill")
                    .font(.system(size: 100))
                    .foregroundColor(.accentColor)
            }
            .frame(height: 250)
            
            VStack(spacing: 16) {
                Text("Your keys live in the same vault Apple uses for Face ID.")
                    .font(.title2)
                    .multilineTextAlignment(.center)
                
                VStack(alignment: .leading, spacing: 12) {
                    Label("Never leave your device", systemImage: "lock.shield")
                        .foregroundStyle(Color.accentColor)
                    Label("Never touch the internet", systemImage: "network.slash")
                        .foregroundStyle(Color.accentColor)
                    Label("Belong only to you — for life", systemImage: "person.crop.circle")
                        .foregroundStyle(Color.accentColor)
                }
                .font(.title3)
                .foregroundColor(.secondary)
                .padding(.horizontal, 50)
            }
        }
    }
}

struct OnboardingPage5: View {
    let onComplete: () -> Void
    
    var body: some View {
        VStack(spacing: 50) {
            Spacer()
            
            Image(systemName: "infinity.circle.fill")
                .font(.system(size: 90))
                .foregroundColor(.accentColor)
                .symbolEffect(.pulse, options: .repeating)
            
            VStack(spacing: 20) {
                Text("Let’s make your connections truly permanent.")
                    .font(.largeTitle)
                    .fontWeight(.semibold)
                    .multilineTextAlignment(.center)
                
                Text("One second today — secure for life.")
                    .font(.title3)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 40)
            
            Spacer()
            
            VStack(spacing: 16) {
                Button("I’m ready") {
                    self.onComplete()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
            .padding(.bottom, 100)
        }
    }
}

// MARK: - Preview
#Preview {
    ForeverOnboardingView()
}
