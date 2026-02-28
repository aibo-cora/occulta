import SwiftUI

// MARK: - Message Model
struct Message: Identifiable, Equatable {
    let id = UUID()
    let text: String
    let timestamp: Date
    let isOutgoing: Bool
}

// MARK: - Main Chat View
struct UnidirectionalChatView: View {
    
    @State private var messages: [Message] = []
    @State private var messageText: String = ""
    
    var body: some View {
        VStack {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 24) {
                        ForEach(Array(messages.enumerated()), id: \.element.id) { index, message in
                            VStack(spacing: 6) {
                                if index == 0 ||
                                   !Calendar.current.isDate(messages[index - 1].timestamp, inSameDayAs: message.timestamp) {
                                    DateHeader(date: message.timestamp)
                                }
                                MessageBubble(message: message)
                            }
                            .id(message.id)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 20)
                }
                .onChange(of: messages) { _, _ in
                    withAnimation(.easeOut(duration: 0.3)) {
                        if let last = messages.last {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
            
            // MARK: - Prettier Input Bar
            
            HStack(alignment: .center, spacing: 10) {
                // Attachment Button (ready for photos/files later)
                Button {
                    // TODO: Implement attachment picker
                } label: {
                    Image(systemName: "plus.circle.fill")
                        .font(.system(size: 30))
                        .foregroundStyle(.blue)
                }
                
                // Prettier TextField – modern pill shape
                TextField("Type a message...", text: $messageText, axis: .vertical)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 11)
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: 24))
                    .lineLimit(1...6)
                
                Button(action: sendMessage) {
                    Image(systemName: "paperplane.fill")
                        .padding(13)
                }
                .disabled(messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(Color(.systemBackground))
            .overlay(alignment: .top) {
                Rectangle()
                    .frame(height: 0.5)
                    .foregroundStyle(.gray.opacity(0.2))
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .background(Color(.systemGroupedBackground))
    }
    
    private func sendMessage() {
        let trimmed = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        
        let newMessage = Message(
            text: trimmed,
            timestamp: Date(),
            isOutgoing: true
        )
        
        messages.append(newMessage)
        messageText = ""
    }
}

// MARK: - Date Header
struct DateHeader: View {
    let date: Date
    
    var body: some View {
        Text(relativeDateString(for: date))
            .font(.caption.bold())
            .foregroundStyle(.secondary)
            .padding(.vertical, 6)
            .padding(.horizontal, 16)
            .background(Color(.systemGray5))
            .clipShape(Capsule())
            .frame(maxWidth: .infinity)
    }
    
    private func relativeDateString(for date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return "Today" }
        if calendar.isDateInYesterday(date) { return "Yesterday" }
        
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        return formatter.string(from: date)
    }
}

struct MessageBubble: View {
    let message: Message
    
    var body: some View {
        Text(message.text)
            .padding(.horizontal, 15)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 18)
                    .fill(message.isOutgoing ? Color.blue : Color(.systemGray6))
            )
            .foregroundStyle(message.isOutgoing ? .white : .primary)
            .frame(maxWidth: 270, alignment: message.isOutgoing ? .trailing : .leading)
    }
}

// MARK: - Preview

#Preview {
    NavigationStack {
        UnidirectionalChatView()
    }
}
