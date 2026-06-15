import SwiftUI
import SwiftData
import UniformTypeIdentifiers
import PhotosUI
import AVKit

extension URL: @retroactive Identifiable {
    public var id: String { absoluteString }
}

struct ComposableMessage: View {
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Environment(VaultManager.self) private var vaultManager: VaultManager?
    
    let identifier: String
    let filename = "message.occ"
    
    @Query(Contact.Profile.descriptor) var contacts: [Contact.Profile]

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
    @State private var encryptedResultURL: URL?
    
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
                Conversation(mode: .write, messages: self.$messages)
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
                .sheet(item: self.$encryptedResultURL) { url in
                    ActivityView(activityItems: [url], onComplete: { completed in
                        try? FileManager.default.removeItem(at: url)
                        if completed {
                            self.messages = []
                            self.selectedMediaItems = []
                        }
                    })
                }
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
        
        @Binding var messages: [Occulta.File]
        
        enum Modes {
            case read(messageOwner: String), write
        }
        
        var body: some View {
            VStack {
                Group {
                    switch self.mode {
                    case .write:
                        ContactEncryptionDisclaimer()
                    case .read(let owner):
                        Contact.Info(identifier: owner)
                    }
                }
                .padding(.top)
                
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

            @State private var showingFullScreen = false
            @Environment(\.colorScheme) private var colorScheme

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
                }
                .padding(.horizontal, 16)
                .fullScreenCover(isPresented: self.$showingFullScreen) {
                    self.fullScreenContent
                }
            }

            private var fileSize: String? {
                guard let url = self.file.url,
                      let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize,
                      size > 0
                else { return nil }
                return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
            }

            @ViewBuilder
            private var fullScreenContent: some View {
                switch self.file.format {
                case .file(let metadata):
                    if let _ = FileExtensions.Image(rawValue: metadata.extension ?? "") {
                        FullScreenImageViewer(url: self.file.url)
                    } else if let _ = FileExtensions.Video(rawValue: metadata.extension ?? ""), let url = self.file.url {
                        FullScreenVideoViewer(url: url)
                    }
                default:
                    EmptyView()
                }
            }

            @ViewBuilder
            private var contentPreview: some View {
                switch self.file.format {
                case .text:
                    if let data = self.file.content, let text = String(data: data, encoding: .utf8) {
                        Text(text.withDetectedLinks())
                            .padding(14)
                            .background(Color.green.opacity(0.2))
                            .foregroundStyle(self.colorScheme == .dark ? .white : .black)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .contextMenu {
                                Button {
                                    UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: text]], options: [.expirationDate: Date().addingTimeInterval(120)])
                                    UIPasteboard.general.string = text
                                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                                } label: {
                                    Label("Copy", systemImage: "doc.on.doc")
                                }
                            }
                    }
                case .file(let metadata):
                    let name = metadata.name ?? "file"
                    if let _ = FileExtensions.Image(rawValue: metadata.extension ?? "") {
                        VStack(spacing: 6) {
                            AsyncImage(url: self.file.url) { phase in
                                switch phase {
                                case .success(let image):
                                    image
                                        .resizable()
                                        .scaledToFill()
                                case .failure(let error):
                                    VStack(spacing: 4) {
                                        Image(systemName: "exclamationmark.triangle")
                                            .foregroundStyle(.secondary)
                                        Text(error.localizedDescription)
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                            .multilineTextAlignment(.center)
                                    }
                                case .empty:
                                    ProgressView()
                                @unknown default:
                                    ProgressView()
                                }
                            }
                            .frame(maxWidth: 260, maxHeight: 320)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .onTapGesture { self.showingFullScreen = true }
                            .contextMenu {
                                if case .read = self.mode, let url = self.file.url {
                                    ShareLink(item: url) {
                                        Label("Share", systemImage: "square.and.arrow.up")
                                    }
                                }
                            }

                            HStack(spacing: 4) {
                                Text(name)
                                    .font(.caption)
                                    .foregroundStyle(.white)
                                if let size = self.fileSize {
                                    Text("·")
                                        .font(.caption)
                                        .foregroundStyle(.white.opacity(0.5))
                                    Text(size)
                                        .font(.caption)
                                        .foregroundStyle(.white.opacity(0.5))
                                }
                            }
                        }
                    } else if let _ = FileExtensions.Video(rawValue: metadata.extension ?? ""), let url = self.file.url {
                        VStack(spacing: 6) {
                            ZStack {
                                Color.black
                                Image(systemName: "play.circle.fill")
                                    .font(.system(size: 44))
                                    .foregroundStyle(.white)
                            }
                            .frame(width: 260, height: 200)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .onTapGesture { self.showingFullScreen = true }
                            .contextMenu {
                                if case .read = self.mode {
                                    ShareLink(item: url) {
                                        Label("Share", systemImage: "square.and.arrow.up")
                                    }
                                }
                            }

                            HStack(spacing: 4) {
                                Text(name)
                                    .font(.caption)
                                    .foregroundStyle(.white)
                                if let size = self.fileSize {
                                    Text("·")
                                        .font(.caption)
                                        .foregroundStyle(.white.opacity(0.5))
                                    Text(size)
                                        .font(.caption)
                                        .foregroundStyle(.white.opacity(0.5))
                                }
                            }
                        }
                    } else {
                        HStack {
                            Image(systemName: "doc.fill")
                                .font(.title2)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(name).lineLimit(1)
                                if let size = self.fileSize {
                                    Text(size)
                                        .font(.caption2)
                                        .foregroundStyle(.white.opacity(0.7))
                                }
                            }
                        }
                        .padding(14)
                        .background(Color.blue)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 18))
                        .contextMenu {
                            if case .read = self.mode, let url = self.file.url {
                                ShareLink(item: url) {
                                    Label("Share", systemImage: "square.and.arrow.up")
                                }
                            }
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
        Task {
            do {
                guard
                    let url = try result.get().first,
                    url.startAccessingSecurityScopedResource()
                else { return }
                
                defer { url.stopAccessingSecurityScopedResource() }
                /// Extract data from file.
                let data = try await URLSession.shared.data(from: url).0
                /// Create a temp file.
                let filename = url.lastPathComponent.components(separatedBy: ".").first ?? ""
                let ext = url.lastPathComponent.components(separatedBy: ".").last ?? ""
                let tempDir = FileManager.default.temporaryDirectory
                let tempFileURL = tempDir.appendingPathComponent(filename + ".\(ext)")
                /// Write to temp file because the original URL is going to have its scope changed back to private.
                try data.write(to: tempFileURL)
                
                let metadata = Occulta.File.Metadata(name: filename, extension: ext)
                let newFile = Occulta.File(url: tempFileURL, format: .file(metadata), date: Date())
                
                self.messages.append(newFile)
            } catch {
                self.showErrorAlert(error.localizedDescription)
            }
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
                
                // Staging files have been read into `processed` — delete them now
                for file in self.messages {
                    if let url = file.url { try? FileManager.default.removeItem(at: url) }
                }

                // Encode & Encrypt

                let basket = Basket(files: processed)

                let contactPub = try? self.contactManager?.currentPublicKey(forIdentifier: self.identifier)
                let shardOps   = try self.shardCustodyManager?.buildShardOperations(for: self.identifier, currentContactPublicKey: contactPub) ?? []
                let manifest_  = try? self.shardCustodyManager?.buildCustodyManifest(for: self.identifier)
                let expected: [UUID]?
                if let custody = self.shardCustodyManager, let vm = self.vaultManager {
                    expected = try? custody.buildExpectedShards(for: self.identifier, vaultManager: vm)
                } else {
                    expected = nil
                }

                let encryptedData: Data?
                do {
                    encryptedData = try self.contactManager?.encryptBundle(
                        basket:          basket,
                        for:             identifier,
                        shardOperations: shardOps.isEmpty ? nil : shardOps,
                        custodyManifest: manifest_,
                        expectedShards:  expected
                    )
                } catch ContactManager.Errors.trusteeLacksQuantumMaterial {
                    // Quantum material corrupted or missing — fall back to classical,
                    // strip shard ops (they stay pending and will retry after re-exchange).
                    encryptedData = try self.contactManager?.encryptBundle(
                        basket: basket,
                        for:    identifier
                    )
                } catch {
                    debugPrint("Error: \(error)")
                    encryptedData = nil
                }
                
                guard
                    let encrypted = encryptedData, encrypted.isEmpty == false
                else {
                    self.showErrorAlert("There is nothing to encrypt, try again.")
                    
                    return
                }
                
                let id = UUID().uuidString.components(separatedBy: "-").last ?? "encrypted.file"
                let tempURL = FileManager.default.temporaryDirectory
                    .appendingPathComponent("\(id).occ")
                
                try encrypted.write(to: tempURL)
                
                await MainActor.run {
                    self.encryptedResultURL = tempURL
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

// MARK: - Full-screen viewers

private struct FullScreenImageViewer: View {
    let url: URL?
    @Environment(\.dismiss) private var dismiss

    @State private var scale: CGFloat = 1.0
    @State private var offset: CGSize = .zero
    @GestureState private var gestureScale: CGFloat = 1.0
    @GestureState private var gestureOffset: CGSize = .zero

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()

            AsyncImage(url: self.url) { phase in
                switch phase {
                case .success(let image):
                    image
                        .resizable()
                        .scaledToFit()
                        .scaleEffect(max(1, self.scale * self.gestureScale))
                        .offset(
                            x: self.offset.width + self.gestureOffset.width,
                            y: self.offset.height + self.gestureOffset.height
                        )
                        .gesture(
                            MagnificationGesture()
                                .updating(self.$gestureScale) { value, state, _ in state = value }
                                .onEnded { value in
                                    let newScale = max(1, self.scale * value)
                                    self.scale = newScale
                                    if newScale == 1 { self.offset = .zero }
                                }
                        )
                        .simultaneousGesture(
                            DragGesture()
                                .updating(self.$gestureOffset) { value, state, _ in
                                    guard self.scale > 1 else { return }
                                    state = value.translation
                                }
                                .onEnded { value in
                                    guard self.scale > 1 else { return }
                                    self.offset.width  += value.translation.width
                                    self.offset.height += value.translation.height
                                }
                        )
                        .onTapGesture(count: 2) {
                            withAnimation(.spring()) {
                                self.scale  = 1
                                self.offset = .zero
                            }
                        }
                default:
                    ProgressView().tint(.white)
                }
            }

            Button { self.dismiss() } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
                    .padding(10)
                    .background(Circle().fill(.black.opacity(0.5)))
            }
            .padding()
        }
    }
}

private struct FullScreenVideoViewer: View {
    let url: URL
    @Environment(\.dismiss) private var dismiss
    @State private var player: AVPlayer

    init(url: URL) {
        self.url = url
        self._player = State(initialValue: AVPlayer(url: url))
    }

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()
            VideoPlayer(player: self.player)
                .ignoresSafeArea()
            Button { self.dismiss() } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
                    .padding(10)
                    .background(Circle().fill(.black.opacity(0.5)))
            }
            .padding()
        }
        .onAppear    { self.player.play() }
        .onDisappear { self.player.pause() }
    }
}

// MARK: -

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
        ComposableMessage.Conversation(mode: .read(messageOwner: UUID().uuidString), messages: .constant([File(content: "https://www.apple.com".data(using: .utf8), format: .text), File(content: "Hi".data(using: .utf8), format: .text)]))
    }
}
