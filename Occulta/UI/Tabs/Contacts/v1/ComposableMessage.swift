import SwiftUI
import SwiftData
import UniformTypeIdentifiers
import PhotosUI
import Photos
import AVKit

extension URL: @retroactive Identifiable {
    public var id: String { absoluteString }
}

struct PendingImport: Identifiable {
    let id       = UUID()
    let filename: String
    let ext:      String
    var thumbnail: UIImage? = nil
    var progress:  Double   = 0
    var isLoading: Bool     = true
}

struct ComposableMessage: View {
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Environment(VaultManager.self) private var vaultManager: VaultManager?
    
    let identifier: String
    let filename = "message.occ"
    
    @Query(Contact.Profile.descriptor) var contacts: [Contact.Profile]

    @Binding var messages: [Occulta.File]
    @Binding var messageText: String

    // Local UI state
    @State private var showMediaPicker = false
    @State private var showFileImporter = false
    @State private var encryptedResultURL: URL?
    @State private var showError = false
    @State private var errorMessage = ""
    @State private var attachmentManager: AttachmentManager? = nil
    @State private var pendingImports: [PendingImport] = []

    init(
        identifier: String,
        messages: Binding<[Occulta.File]>,
        messageText: Binding<String>
    ) {
        self.identifier = identifier
        self._messages = messages
        self._messageText = messageText

        let predicate = #Predicate<Contact.Profile> { $0.identifier == identifier }
        self._contacts = Query(filter: predicate)
    }
    
    var body: some View {
        VStack {
            if self.messages.isEmpty && self.pendingImports.isEmpty {
                ContentUnavailableView {
                    Label("Add content", systemImage: "plus.circle")
                } description: {
                    Text("Type messages or attach photos, videos, or files. Everything will be encrypted together at the end.")
                        .multilineTextAlignment(.center)
                }
            } else {
                Conversation(mode: .write, messages: self.$messages, pendingImports: self.pendingImports, attachmentManager: self.attachmentManager, onDelete: self.deleteMessage)
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
                            for file in self.messages {
                                if let stagingURL = file.url { try? FileManager.default.removeItem(at: stagingURL) }
                            }
                            self.messages = []
                        }
                    })
                }
            }
        }
        .background(Color(.systemGroupedBackground))
        .sheet(isPresented: self.$showMediaPicker) {
            PHPickerRepresentable(isPresented: self.$showMediaPicker) { results in
                results.forEach { result in Task { await self.handleMedia(result) } }
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
        .task {
            guard let key = try? self.contactManager?.fileEncryptionKey(for: self.identifier) else { return }
            self.attachmentManager = AttachmentManager(contactKey: key)
        }
    }
    
    struct Conversation: View {
        let mode: Modes
        @Binding var messages: [Occulta.File]
        var pendingImports: [PendingImport] = []
        var attachmentManager: AttachmentManager? = nil
        var onDelete: ((Occulta.File) -> Void)? = nil

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

                                    MessageBubble(file: file, mode: self.mode, attachmentManager: self.attachmentManager, onDelete: self.onDelete.map { cb in { cb(file) } })
                                }
                                .id(file.id)
                            }
                            ForEach(self.pendingImports) { pending in
                                PendingImportBubble(pending: pending)
                                    .id("pending-\(pending.id.uuidString)")
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
                    .onChange(of: self.pendingImports.count) { _, _ in
                        withAnimation(.easeOut(duration: 0.3)) {
                            if let last = self.pendingImports.last {
                                proxy.scrollTo("pending-\(last.id.uuidString)", anchor: .bottom)
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
        
        private struct PendingImportBubble: View {
            let pending: PendingImport

            var body: some View {
                HStack(alignment: .center) {
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        ZStack {
                            if let thumb = self.pending.thumbnail {
                                Image(uiImage: thumb)
                                    .resizable()
                                    .scaledToFill()
                                Color.black.opacity(0.4)
                            } else {
                                Color.black
                            }
                            VStack(spacing: 6) {
                                ProgressView().tint(.white)
                                
                                Text("Loading…")
                                    .font(.caption2)
                                    .foregroundStyle(.white)
                            }
                        }
                        .frame(width: 260, height: 200)
                        .clipShape(RoundedRectangle(cornerRadius: 18))

                        ProgressView(value: self.pending.progress)
                            .tint(.blue)
                            .frame(width: 260)
                            .animation(.linear(duration: 0.1), value: self.pending.progress)

                        HStack(spacing: 4) {
                            Text(self.pending.filename)
                                .font(.caption)
                                .foregroundStyle(.primary)
                            Text("·")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(self.pending.isLoading ? "Loading…" : "Encrypting…")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .padding(.horizontal, 16)
            }
        }

        struct MessageBubble: View {
            let file: Occulta.File
            let mode: Conversation.Modes
            var attachmentManager: AttachmentManager? = nil
            var onDelete: (() -> Void)? = nil

            @State private var showingFullScreen = false
            @State private var videoPlayer: AVPlayer? = nil
            @State private var decryptedImage: UIImage? = nil
            @State private var showingShare = false
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
                        FullScreenImageViewer(image: self.decryptedImage)
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
                                if let onDelete = self.onDelete {
                                    Button(role: .destructive, action: onDelete) {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                            }
                    }
                case .file(let metadata):
                    let name = metadata.name ?? "file"
                    
                    if let _ = FileExtensions.Image(rawValue: metadata.extension ?? "") {
                        VStack(spacing: 6) {
                            Group {
                                if let img = self.decryptedImage {
                                    Image(uiImage: img).resizable().scaledToFill()
                                } else {
                                    ProgressView()
                                }
                            }
                            .frame(maxWidth: 260, maxHeight: 320)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .onTapGesture { guard self.decryptedImage != nil else { return }; self.showingFullScreen = true }
                            .task(id: self.file.url) {
                                guard let manager = self.attachmentManager, let url = self.file.url else { return }
                                self.decryptedImage = try? await manager.image(at: url)
                            }
                            .contextMenu {
                                if case .read = self.mode {
                                    Button { self.showingShare = true } label: {
                                        Label("Share", systemImage: "square.and.arrow.up")
                                    }
                                }
                                if let onDelete = self.onDelete {
                                    Button(role: .destructive, action: onDelete) {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                            }
                            .sheet(isPresented: self.$showingShare) {
                                if let manager = self.attachmentManager, let url = self.file.url {
                                    let ext  = metadata.extension ?? "jpg"
                                    let type = UTType(filenameExtension: ext) ?? .image
                                    ActivityView(activityItems: [manager.shareProvider(at: url, filename: metadata.name ?? "image", contentType: type)])
                                }
                            }

                            HStack(spacing: 4) {
                                Text(name)
                                    .font(.caption)
                                    .foregroundStyle(.primary)
                                if let size = self.fileSize {
                                    Text("·")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Text(size)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    } else if let _ = FileExtensions.Video(rawValue: metadata.extension ?? ""), let url = self.file.url {
                        VStack(spacing: 6) {
                            Group {
                                if let player = self.videoPlayer {
                                    VideoPlayer(player: player)
                                } else {
                                    Color.black
                                }
                            }
                            .frame(width: 260, height: 200)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .onAppear {
                                self.videoPlayer = self.attachmentManager?.player(for: url) ?? AVPlayer(url: url)
                            }
                            .onDisappear { self.videoPlayer = nil }
                            .contextMenu {
                                if case .read = self.mode {
                                    Button { self.showingShare = true } label: {
                                        Label("Share", systemImage: "square.and.arrow.up")
                                    }
                                }
                                if let onDelete = self.onDelete {
                                    Button(role: .destructive, action: onDelete) {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                            }
                            .sheet(isPresented: self.$showingShare) {
                                if let manager = self.attachmentManager {
                                    let ext  = metadata.extension ?? "mov"
                                    let type = UTType(filenameExtension: ext) ?? .movie
                                    ActivityView(activityItems: [manager.shareProvider(at: url, filename: name, contentType: type)])
                                }
                            }

                            HStack(spacing: 4) {
                                Text(name)
                                    .font(.caption)
                                    .foregroundStyle(.primary)
                                if let size = self.fileSize {
                                    Text("·")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Text(size)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
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
                            if case .read = self.mode, self.file.url != nil {
                                Button { self.showingShare = true } label: {
                                    Label("Share", systemImage: "square.and.arrow.up")
                                }
                            }
                            if let onDelete = self.onDelete {
                                Button(role: .destructive, action: onDelete) {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                        .sheet(isPresented: self.$showingShare) {
                            if let manager = self.attachmentManager, let url = self.file.url {
                                let ext  = metadata.extension ?? "bin"
                                let type = UTType(filenameExtension: ext) ?? .data
                                ActivityView(activityItems: [manager.shareProvider(at: url, filename: name, contentType: type)])
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
    
    private func deleteMessage(_ file: Occulta.File) {
        if let url = file.url { try? FileManager.default.removeItem(at: url) }
        self.messages.removeAll { $0.id == file.id }
    }

    private func addTextMessage() {
        let trimmed = self.messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard !trimmed.isEmpty else { return }
        
        let newFile = Occulta.File(content: trimmed.data(using: .utf8), format: .text, date: Date())
        
        self.messages.append(newFile)
        self.messageText = ""
    }
    
    private func handleMedia(_ result: PHPickerResult) async {
        let provider    = result.itemProvider
        let typeID      = provider.registeredTypeIdentifiers.first ?? UTType.data.identifier
        let contentType = UTType(typeID) ?? .data
        let ext         = contentType.preferredFilenameExtension ?? "bin"
        let filename    = "media_\(UUID().uuidString.prefix(8))"
        let url         = FileManager.default.temporaryDirectory.appendingPathComponent("\(filename).\(ext)")
        let isVideo     = FileExtensions.Video(rawValue: ext) != nil

        #if DEBUG
        print("[handleMedia] registeredTypeIdentifiers: \(provider.registeredTypeIdentifiers)")
        print("[handleMedia] typeID=\(typeID) ext=\(ext) isVideo=\(isVideo) assetID=\(result.assetIdentifier ?? "nil")")
        #endif

        guard let manager = self.attachmentManager else {
            #if DEBUG
            print("[handleMedia] no attachmentManager — unencrypted fallback")
            #endif
            do {
                let data = try await loadItemData(from: provider, typeID: typeID)
                try data.writeProtected(to: url)
                self.messages.append(Occulta.File(url: url, format: .file(.init(name: filename, extension: ext)), date: Date()))
            } catch { self.showErrorAlert(error.localizedDescription) }
            return
        }

        if isVideo {
            #if DEBUG
            print("[handleMedia] → streaming path")
            #endif
            let pending = PendingImport(filename: filename, ext: ext)
            let thumbTypeID = "com.apple.private.photos.thumbnail.standard"
            
            self.pendingImports.append(pending)
            
            if provider.hasItemConformingToTypeIdentifier(thumbTypeID) {
                Task { @MainActor in
                    if let data = try? await loadItemData(from: provider, typeID: thumbTypeID),
                       let image = UIImage(data: data),
                       let idx = self.pendingImports.firstIndex(where: { $0.id == pending.id }) {
                        self.pendingImports[idx].thumbnail = image
                    }
                }
            }
            do {
                try await self.streamVideo(provider: provider, typeID: typeID, pendingID: pending.id, ext: ext, filename: filename, url: url, manager: manager)
            } catch {
                self.pendingImports.removeAll { $0.id == pending.id }
                self.showErrorAlert(error.localizedDescription)
            }
        } else {
            #if DEBUG
            print("[handleMedia] → loadTransferable fallback (isVideo=\(isVideo) assetID=\(result.assetIdentifier ?? "nil"))")
            #endif
            do {
                let data = try await loadItemData(from: provider, typeID: typeID)
                #if DEBUG
                print("[handleMedia] loaded \(data.count) bytes via itemProvider")
                #endif
                try manager.encrypt(data, to: url)
                self.messages.append(Occulta.File(url: url, format: .file(.init(name: filename, extension: ext)), date: Date()))
            } catch { self.showErrorAlert(error.localizedDescription) }
        }
    }

    private func streamVideo(
        provider: NSItemProvider,
        typeID: String,
        pendingID: UUID,
        ext: String,
        filename: String,
        url: URL,
        manager: AttachmentManager
    ) async throws {
        if let idx = self.pendingImports.firstIndex(where: { $0.id == pendingID }) {
            self.pendingImports[idx].isLoading = false
        }

        let encryptor = try manager.streamingEncryptor(to: url)
        let pageSize  = Int(getpagesize())

        // NSItemProvider — no Photos authorization needed; picker grant is sufficient.
        // For large files the delivered Data is mmap-backed: iterating in 64 KB slices and
        // calling MADV_DONTNEED after each lets the kernel reclaim pages as we go,
        // keeping resident memory bounded to one slice regardless of file size.
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            provider.loadDataRepresentation(forTypeIdentifier: typeID) { data, providerError in
                do {
                    if let err = providerError { throw err }
                    guard let data else { throw ImportError.noVideoResource }
                    var encryptError: Error? = nil
                    data.withUnsafeBytes { rawPtr in
                        guard let base = rawPtr.baseAddress else { return }
                        var offset = 0
                        while offset < data.count, encryptError == nil {
                            let take = min(65_536, data.count - offset)
                            autoreleasepool {
                                do { try encryptor.append(Data(bytes: base.advanced(by: offset), count: take)) }
                                catch { encryptError = error }
                            }
                            let adviseLen = ((take + pageSize - 1) / pageSize) * pageSize
                            madvise(UnsafeMutableRawPointer(mutating: base.advanced(by: offset)), adviseLen, MADV_DONTNEED)
                            offset += take
                        }
                    }
                    if let err = encryptError { throw err }
                    try encryptor.finalize()
                    cont.resume()
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }

        self.pendingImports.removeAll { $0.id == pendingID }
        self.messages.append(Occulta.File(url: url, format: .file(.init(name: filename, extension: ext)), date: Date()))
    }

    private func phThumbnail(for asset: PHAsset) async -> UIImage? {
        await withCheckedContinuation { cont in
            let opts = PHImageRequestOptions()
            opts.deliveryMode = .fastFormat
            opts.isNetworkAccessAllowed = true
            PHImageManager.default().requestImage(
                for: asset,
                targetSize: CGSize(width: 600, height: 600),
                contentMode: .aspectFit,
                options: opts
            ) { image, _ in cont.resume(returning: image) }
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

                let filename = url.deletingPathExtension().lastPathComponent
                let ext      = url.pathExtension
                let tmp      = FileManager.default.temporaryDirectory.appendingPathComponent("\(filename).\(ext)")

                if let manager = self.attachmentManager {
                    let source    = try FileHandle(forReadingFrom: url)
                    let encryptor = try manager.streamingEncryptor(to: tmp)
                    defer { try? source.close() }
                    do {
                        while let chunk = try source.read(upToCount: 65_536), !chunk.isEmpty {
                            try encryptor.append(chunk)
                        }
                        try encryptor.finalize()
                    } catch {
                        try? FileManager.default.removeItem(at: tmp)
                        throw error
                    }
                } else {
                    let data = try Data(contentsOf: url, options: .mappedIfSafe)
                    try data.writeProtected(to: tmp)
                }

                let file = Occulta.File(url: tmp, format: .file(.init(name: filename, extension: ext)), date: Date())
                await MainActor.run { self.messages.append(file) }
            } catch {
                self.showErrorAlert(error.localizedDescription)
            }
        }
    }
    
    private func encrypt() {
        Task {
            do {
                // Process files to convert the ones that contain only urls to files to files with actual content
                
                let processed: [Occulta.File] = try await withThrowingTaskGroup(of: Occulta.File.self) { group in
                    for file in self.messages {
                        if let url = file.url {
                            let manager = self.attachmentManager
                            
                            group.addTask {
                                let data: Data
                                
                                if let manager {
                                    data = try await manager.data(at: url)
                                } else {
                                    let (d, _) = try await URLSession.shared.data(from: url)
                                    data = d
                                }
                                return Occulta.File(content: data, format: file.format, date: file.date)
                            }
                        } else {
                            let captured = file
                            group.addTask { captured }
                        }
                    }
                    var results: [Occulta.File] = []
                    for try await file in group { results.append(file) }
                    
                    return results.sorted { ($0.date ?? .distantPast) < ($1.date ?? .distantPast) }
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
                        for:             self.identifier,
                        shardOperations: shardOps.isEmpty ? nil : shardOps,
                        custodyManifest: manifest_,
                        expectedShards:  expected
                    )
                } catch ContactManager.Errors.trusteeLacksQuantumMaterial {
                    // Quantum material corrupted or missing — fall back to classical,
                    // strip shard ops (they stay pending and will retry after re-exchange).
                    encryptedData = try self.contactManager?.encryptBundle(
                        basket: basket,
                        for:    self.identifier
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
                
                try encrypted.writeProtected(to: tempURL)
                
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
    let image: UIImage?
    @Environment(\.dismiss) private var dismiss

    @State private var scale: CGFloat = 1.0
    @State private var offset: CGSize = .zero
    @GestureState private var gestureScale: CGFloat = 1.0
    @GestureState private var gestureOffset: CGSize = .zero

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()

            if let image = self.image {
                Image(uiImage: image)
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
            } else {
                ProgressView().tint(.white)
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

// MARK: -

enum ImportError: LocalizedError {
    case assetNotFound
    case noVideoResource

    var errorDescription: String? {
        switch self {
        case .assetNotFound:      return "Could not find the selected video."
        case .noVideoResource:    return "The selected item has no video resource."
        }
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

// MARK: - PHPickerRepresentable

struct PHPickerRepresentable: UIViewControllerRepresentable {
    @Binding var isPresented: Bool
    let onPick: ([PHPickerResult]) -> Void

    func makeUIViewController(context: Context) -> PHPickerViewController {
        var config            = PHPickerConfiguration(photoLibrary: .shared())
        config.filter         = .any(of: [.images, .videos])
        config.selectionLimit = 0
        let picker            = PHPickerViewController(configuration: config)
        picker.delegate       = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: PHPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    final class Coordinator: NSObject, PHPickerViewControllerDelegate {
        var parent: PHPickerRepresentable
        init(parent: PHPickerRepresentable) { self.parent = parent }

        func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
            self.parent.isPresented = false
            self.parent.onPick(results)
        }
    }
}

private func loadItemData(from provider: NSItemProvider, typeID: String) async throws -> Data {
    try await withCheckedThrowingContinuation { cont in
        provider.loadDataRepresentation(forTypeIdentifier: typeID) { data, error in
            if let data { cont.resume(returning: data) }
            else { cont.resume(throwing: error ?? ImportError.assetNotFound) }
        }
    }
}

// MARK: - Preview

#Preview {
    struct Preview: View {
        @State var messages: [Occulta.File] = []
        @State var text = ""
        var body: some View {
            NavigationStack {
                ComposableMessage(
                    identifier: UUID().uuidString,
                    messages: self.$messages,
                    messageText: self.$text
                )
                .environment(ContactManager.preview)
            }
        }
    }
    return Preview()
}

#Preview {
    NavigationStack {
        ComposableMessage.Conversation(mode: .read(messageOwner: UUID().uuidString), messages: .constant([File(content: "https://www.apple.com".data(using: .utf8), format: .text), File(content: "Hi".data(using: .utf8), format: .text)]))
    }
}
