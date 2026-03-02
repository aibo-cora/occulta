import SwiftUI
import SwiftData
import UniformTypeIdentifiers
import PhotosUI

struct ComposableMessage: View {
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    let identifier: String
    let filename = "message.occ"
    
    @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
    
    init(identifier: String) {
        self.identifier = identifier
        
        let predicate = #Predicate<Contact.Profile> {
            $0.identifier == identifier
        }
        
        self._contacts = Query(filter: predicate)
    }
    
    @State private var draftFiles: [Occulta.File] = []
    @State private var messageText: String = ""
    
    // Picker states
    @State private var showMediaPicker = false
    @State private var showFileImporter = false
    @State private var selectedMediaItems: [PhotosPickerItem] = []
    
    @State private var encryptedResult: EncryptedFile?
    
    // Error feedback
    @State private var showError = false
    @State private var errorMessage = ""
    
    var body: some View {
        VStack {
            if self.draftFiles.isEmpty {
                ContentUnavailableView {
                    Label("Add content", systemImage: "plus.circle")
                } description: {
                    Text("Type messages or attach photos, videos, or files. Everything will be encrypted together at the end.")
                        .multilineTextAlignment(.center)
                }
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .trailing, spacing: 24) {
                            ContactEncryptionDisclaimer()
                            
                            ForEach(Array(self.draftFiles.enumerated()), id: \.element.id) { index, file in
                                VStack(spacing: 6) {
                                    if index == 0 || self.shouldShowDateSeparator(before: self.draftFiles[index - 1], current: file) {
                                        DateHeader(date: file.date ?? Date())
                                    }
                                    
                                    DraftBubble(file: file)
                                }
                                .id(file.id)
                            }
                        }
                        .padding(.horizontal, 16)
                        .padding(.bottom, 20)
                    }
                    .scrollDismissesKeyboard(.interactively)
                    .onChange(of: self.draftFiles) { _, latest in
                        withAnimation(.easeOut(duration: 0.3)) {
                            if let last = latest.last {
                                proxy.scrollTo(last.id, anchor: .bottom)
                            }
                        }
                    }
                }
            }
            
            HStack(alignment: .center, spacing: 10) {
                Menu {
                    Button { self.showMediaPicker = true } label: {
                        Label("Photos & Videos", systemImage: "photo")
                    }
                    Button { self.showFileImporter = true } label: {
                        Label("Browse Files", systemImage: "folder")
                    }
                } label: {
                    Image(systemName: "plus.circle.fill")
                        .font(.system(size: 30))
                        .foregroundStyle(.blue)
                }
                
                TextField("Type a message...", text: self.$messageText, axis: .vertical)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 11)
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: 24))
                    .lineLimit(1...6)
                
                Button(action: self.addTextMessage) {
                    Image(systemName: "paperplane.fill")
                        .foregroundStyle(.white)
                        .padding(13)
                        .background(
                            Circle()
                                .fill(self.messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                      ? Color.gray.opacity(0.6)
                                      : Color.blue)
                        )
                }
                .disabled(self.messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.horizontal, 10)
            .padding()
            .background(Color(.systemBackground))
            
            if self.draftFiles.isEmpty == false {
                Button(action: self.encrypt) {
                    Label("Encrypt", systemImage: "lock.shield.fill")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                }
                .padding()
            }
        }
        .background(Color(.systemGroupedBackground))
        .photosPicker(isPresented: self.$showMediaPicker, selection: self.$selectedMediaItems, matching: .any(of: [.images, .videos]))
        .onChange(of: self.selectedMediaItems) { _, newValue in
            newValue.forEach { item in
                Task { await self.handleMedia(item) }
            }
        }
        .fileImporter(isPresented: self.$showFileImporter, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            self.handleFile(result)
        }
        .sheet(item: self.$encryptedResult) { encrypted in
            NavigationStack {
                VStack(spacing: 30) {
                    Image(systemName: "lock.doc.fill")
                        .font(.system(size: 80))
                        .foregroundStyle(.blue)
                    
                    Text("Your entire conversation is encrypted and ready to be shared")
                        .font(.title3)
                        .multilineTextAlignment(.center)
                    
                    ShareLink(item: encrypted, preview: SharePreview("Encrypted Conversation", image: Image(systemName: "lock.doc"))) {
                        Label("Share Encrypted File (.occ)", systemImage: "square.and.arrow.up")
                            .font(.headline)
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(Color.blue)
                            .foregroundStyle(.white)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                    }
                }
                .padding()
                .navigationTitle("Ready to Send")
                .navigationBarTitleDisplayMode(.inline)
            }
        }
        .alert("Error", isPresented: self.$showError) {
            Button("OK") { }
        } message: {
            Text(self.errorMessage)
        }
    }
    
    private struct ContactEncryptionDisclaimer: View {
        @State private var displayingInfo: Bool = false
        
        var body: some View {
            VStack {
                HStack(alignment: .firstTextBaseline) {
                    Button {
                        self.displayingInfo.toggle()
                    } label: {
                        Image(systemName: "info.bubble")
                    }
                    
                    Text("Data we encrypt here is only visible to you and this contact.")
                        .font(.footnote)
                        .multilineTextAlignment(.center)
                }
                .padding()
                
                if self.displayingInfo {
                    Text("We use **AES GCM 256** encryption, with a key derived from your private key and this contacts public key, to secure data. The key is **never** stored or transmitted anywhere.")
                        .font(.caption)
                        .padding()
                }
            }
        }
    }
    
    private func addTextMessage() {
        let trimmed = self.messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard !trimmed.isEmpty else { return }
        
        let newFile = Occulta.File(content: trimmed.data(using: .utf8), format: .text, date: Date())
        
        self.draftFiles.append(newFile)
        self.messageText = ""
    }
    
    private func handleMedia(_ item: PhotosPickerItem) async {
        do {
            guard
                let data = try await item.loadTransferable(type: Data.self)
            else { return }
            
            let contentType = item.supportedContentTypes.first ?? .data
            let ext = contentType.preferredFilenameExtension ?? "bin"
            let filename = "media_\(UUID().uuidString.prefix(8))"
            
            let metadata = Occulta.File.Metadata(name: filename, extension: ext)
            let newFile = Occulta.File(content: data, format: .file(metadata), date: Date())
            
            self.draftFiles.append(newFile)
        } catch {
            self.showErrorAlert(error.localizedDescription)
        }
    }
    
    private func handleFile(_ result: Result<[URL], Error>) {
        do {
            guard
                let url = try result.get().first,
                url.startAccessingSecurityScopedResource()
            else { return }
            
            defer { url.stopAccessingSecurityScopedResource() }
            
            let data = try Data(contentsOf: url)
            let filename = url.lastPathComponent
            
            let metadata = Occulta.File.Metadata(name: filename, extension: url.pathExtension)
            let newFile = Occulta.File(content: data, format: .file(metadata), date: Date())
            
            self.draftFiles.append(newFile)
        } catch {
            self.showErrorAlert(error.localizedDescription)
        }
    }
    
    private func encrypt() {
        Task {
            do {
                let basket = Basket(files: self.draftFiles)
                let encoded = try JSONEncoder().encode(basket)
                let encryptedData = try self.contactManager?.encrypt(data: encoded, for: identifier)
                
                guard
                    let encrypted = encryptedData, encrypted.isEmpty == false
                else {
                    self.showErrorAlert("There is nothing to encrypt, try again.")
                    
                    return
                }
                
                let result = EncryptedFile(content: encrypted)
                
                await MainActor.run {
                    self.encryptedResult = result
                }
            } catch {
                self.showErrorAlert(error.localizedDescription)
            }
        }
    }
    
    @MainActor
    private func showErrorAlert(_ message: String) {
        self.errorMessage = message
        self.showError = true
    }
    
    private func shouldShowDateSeparator(before: Occulta.File, current: Occulta.File) -> Bool {
        guard
            let d1 = before.date,
            let d2 = current.date
        else {
            return false
        }
        
        return !Calendar.current.isDate(d1, inSameDayAs: d2)
    }
}


struct DraftBubble: View {
    let file: Occulta.File
    
    var body: some View {
        HStack(alignment: .bottom) {
            Spacer()
            
            VStack(alignment: .trailing, spacing: 6) {
                self.contentPreview
                
                if let date = self.file.date {
                    Text(date, format: .dateTime.hour().minute())
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 16)
    }
    
    @ViewBuilder
    private var contentPreview: some View {
        switch self.file.format {
        case .text:
            if let data = self.file.content, let text = String(data: data, encoding: .utf8) {
                Text(text)
                    .padding(14)
                    .background(Color.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
            }
        case .file(let metadata):
            if let data = self.file.content, let uiImage = UIImage(data: data) {
                Image(uiImage: uiImage)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 260, maxHeight: 320)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
            } else {
                let name = metadata.name ?? "file"
                let isVideoFile = VideoExtensions().supported.contains(metadata.extension ?? "")
                
                if isVideoFile {
                    VStack(spacing: 8) {
                        Image(systemName: "play.circle.fill")
                            .font(.system(size: 60))
                            .foregroundStyle(.white)
                        Text(name)
                            .font(.caption)
                            .foregroundStyle(.white)
                    }
                    .padding(40)
                    .background(Color.blue)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
                } else {
                    HStack {
                        Image(systemName: "doc.fill")
                            .font(.title2)
                        Text(name)
                            .lineLimit(1)
                    }
                    .padding(14)
                    .background(Color.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
                }
            }
        default:
            Text("Unsupported content")
                .padding(14)
                .background(Color.blue)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 18))
        }
    }
}

struct VideoExtensions {
    let supported: [String] = ["mp4", "mov", "m4v"]
}

// MARK: - Date Header

struct DateHeader: View {
    let date: Date
    
    var body: some View {
        Text(self.decideHeader(for: self.date))
            .font(.caption.bold())
            .foregroundStyle(.secondary)
            .padding(.vertical, 6)
            .padding(.horizontal, 16)
            .background(Color(.systemGray5))
            .clipShape(Capsule())
            .frame(maxWidth: .infinity)
    }
    
    private func decideHeader(for date: Date) -> String {
        let calendar = Calendar.current
        let formatter = DateFormatter()
        
        if calendar.isDateInToday(date) { return "Today" }
        if calendar.isDateInYesterday(date) { return "Yesterday" }
        
        formatter.dateStyle = .medium
        
        return formatter.string(from: date)
    }
}

// MARK: - Preview

#Preview {
    NavigationStack {
        ComposableMessage(identifier: UUID().uuidString)
            .environment(ContactManager.preview)
    }
}
