import SwiftUI
import SwiftData
import UniformTypeIdentifiers
import PhotosUI
import AVKit

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
    
    @State private var messages: [Occulta.File] = []
    
    @State private var messageText: String = ""
    
    // Picker states
    @State private var showMediaPicker = false
    @State private var showFileImporter = false
    @State private var selectedMediaItems: [PhotosPickerItem] = []
    /// Encrypted conversation
    @State private var encryptedResult: EncryptedFile?
    
    // Error feedback
    @State private var showError = false
    @State private var errorMessage = ""
    
    var body: some View {
        VStack {
            if self.messages.isEmpty {
                ContentUnavailableView {
                    Label("Add content", systemImage: "plus.circle")
                } description: {
                    Text("Type messages or attach photos, videos, or files. Everything will be encrypted together at the end.")
                        .multilineTextAlignment(.center)
                }
            } else {
                Conversation(mode: .write, identifier: self.identifier, messages: self.$messages)
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
            
            if self.messages.isEmpty == false {
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
        .onDisappear {
            FileManager.default.clearTemporaryDirectory()
        }
    }
    
    struct Conversation: View {
        let mode: Modes
        let identifier: String
        
        @Binding var messages: [Occulta.File]
        
        enum Modes {
            case read, write
        }
        
        private struct Badges: View {
            @Query(sort: \Contact.Profile.familyName) var contacts: [Contact.Profile]
            
            init(identifier: String) {
                let predicate = #Predicate<Contact.Profile> {
                    $0.identifier == identifier
                }
                
                self._contacts = Query(filter: predicate)
            }
            
            var body: some View {
                EmptyView()
            }
        }
        
        var body: some View {
            switch self.mode {
            case .write:
                VStack {
                    ContactEncryptionDisclaimer()
                    
                    Badges(identifier: self.identifier)
                }
            case .read:
                Contact.Info(identifier: self.identifier)
            }
            
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .trailing, spacing: 24) {
                        ForEach(Array(self.messages.enumerated()), id: \.element.id) { index, file in
                            VStack(spacing: 6) {
                                if index == 0 || self.shouldShowDateSeparator(before: self.messages[index - 1], current: file) {
                                    DateHeader(date: file.date ?? Date())
                                }
                                
                                MessageBubble(file: file, mode: self.mode)
                            }
                            .id(file.id)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.bottom, 20)
                }
                .scrollIndicators(.hidden)
                .scrollDismissesKeyboard(.interactively)
                .onChange(of: self.messages) { _, latest in
                    withAnimation(.easeOut(duration: 0.3)) {
                        if let last = latest.last {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
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
        
        struct MessageBubble: View {
            let file: Occulta.File
            let mode: Conversation.Modes
            
            var body: some View {
                HStack(alignment: .center) {
                    Spacer()
                    
                    VStack(alignment: .trailing, spacing: 6) {
                        self.contentPreview
                        
                        if let date = self.file.date {
                            Text(date, format: .dateTime.hour().minute())
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    
                    switch self.mode {
                    case .read:
                        if let url = self.file.url {
                            switch self.file.format {
                            case .file(_):
                                ShareLink(item: url) {
                                    Image(systemName: "square.and.arrow.up")
                                }
                            default:
                                EmptyView()
                            }
                        }
                    case .write:
                        EmptyView()
                    }
                }
                .padding(.horizontal, 16)
            }
            
            @ViewBuilder
            private var contentPreview: some View {
                switch self.file.format {
                case .text:
                    if let data = self.file.content, let text = String(data: data, encoding: .utf8) {
                        Text(text.withDetectedLinks())
                            .padding(14)
                            .background(Color.green)
                            .foregroundStyle(.white)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                    }
                case .file(let metadata):
                    let name = metadata.name ?? "file"
                    /// Display image.
                    if let _ = FileExtensions.Image(rawValue: metadata.extension ?? "") {
                        VStack(spacing: 8) {
                            AsyncImage(url: self.file.url) { image in
                                image
                                    .resizable()
                                    .scaledToFill()
                            } placeholder: {
                                ProgressView()
                            }
                            .frame(maxWidth: 260, maxHeight: 320)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            
                            Text(name)
                                .font(.caption)
                                .foregroundStyle(.white)
                        }
                        .onAppear {
                            let resources = try? self.file.url?.resourceValues(forKeys: [.fileSizeKey])
                            let size = UInt64(resources?.fileSize ?? 0)
                            
                            debugPrint("Showing async image..., url=\(String(describing: self.file.url)), size=\(size), file=\(self.file)")
                        }
                    } else if let _ = FileExtensions.Video(rawValue: metadata.extension ?? ""), let url = self.file.url {
                        /// Display video
                        let player = AVPlayer(url: url)
                        
                        VStack(spacing: 8) {
                            VideoPlayer(player: player)
                                .frame(width: 260, height: 200)
                                .clipShape(RoundedRectangle(cornerRadius: 18))
                                .onDisappear {
                                    player.pause()
                                }
                            Text(name)
                                .font(.caption)
                                .foregroundStyle(.white)
                        }
                    } else {
                        /// The content is neither image or video, must be a document
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
                default:
                    Text("Unsupported content")
                        .padding(14)
                        .background(Color.blue)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 18))
                }
            }
        }
        
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
    
    private func addTextMessage() {
        let trimmed = self.messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard !trimmed.isEmpty else { return }
        
        let newFile = Occulta.File(content: trimmed.data(using: .utf8), format: .text, date: Date())
        
        self.messages.append(newFile)
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
            
            let tempDir = FileManager.default.temporaryDirectory
            let fileURL = tempDir.appendingPathComponent(filename + ".\(ext)")
            /// We are creating a temp file so that the file data does not stay in memory
            try data.write(to: fileURL)
            
            let metadata = Occulta.File.Metadata(name: filename, extension: ext)
            let newFile = Occulta.File(url: fileURL, format: .file(metadata), date: Date())
            
            self.messages.append(newFile)
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
            
            let filename = url.lastPathComponent
            let metadata = Occulta.File.Metadata(name: filename, extension: url.pathExtension)
            let newFile = Occulta.File(url: url, format: .file(metadata), date: Date())
            
            self.messages.append(newFile)
        } catch {
            self.showErrorAlert(error.localizedDescription)
        }
    }
    
    private func encrypt() {
        Task {
            do {
                // Process files to convert the ones that contain only urls to files to files with actual content
                
                var processed: [Occulta.File] = []
                
                for file in self.messages {
                    if let url = file.url {
                        /// Messages that only have URLs to the content user imported: photos, videos or other files
                        /// Using `URLSession` instead of `resourceBytes` because we might need it for brackground processing.
                        let (data, _) = try await URLSession.shared.data(from: url)
                        let newFile = Occulta.File(content: data, format: file.format, date: file.date)
                        
                        processed.append(newFile)
                    } else {
                        processed.append(file)
                    }
                }
                
                // Encode & Encrypt
                
                let basket = Basket(files: processed)
                let encoded = try JSONEncoder().encode(basket)
                let encryptedData = try self.contactManager?.encryptBundle(data: encoded, for: self.identifier)
                
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
}

struct FileExtensions {
    enum Video: String {
        case mov, mp4, m4v
    }
    
    enum Image: String {
        case jpg, jpeg, png, heic
    }
}

// MARK: - Preview

#Preview {
    NavigationStack {
        ComposableMessage(identifier: UUID().uuidString)
            .environment(ContactManager.preview)
    }
}

#Preview {
    NavigationStack {
        ComposableMessage.Conversation.MessageBubble(file: File(content: "Hi".data(using: .utf8), format: .text), mode: .write)
    }
}
