import SwiftUI
import SwiftData
import UniformTypeIdentifiers
import PhotosUI
import AVKit

extension URL: @retroactive Identifiable {
    public var id: String { self.absoluteString }
}

// MARK: - ComposableMessage

struct ComposableMessage: View {
    @Bindable var vm: ComposeViewModel

    @Query private var contacts: [Contact.Profile]
    @Environment(ContactManager.self) private var contactManager
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Environment(VaultManager.self) private var vaultManager: VaultManager?

    @State private var showMediaPicker  = false
    @State private var showFileImporter = false

    init(vm: ComposeViewModel) {
        self.vm = vm
        let id = vm.identifier
        self._contacts = Query(filter: #Predicate { $0.identifier == id })
    }

    private var firstName: String {
        self.contacts.first?.givenName.decrypt() ?? ""
    }

    private var canEncrypt: Bool {
        !self.vm.messages.isEmpty
            || !self.vm.draftText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            if self.vm.messages.isEmpty && self.vm.pendingImports.isEmpty {
                ContentUnavailableView {
                    Label("Add content", systemImage: "plus.circle")
                } description: {
                    Text("Type messages or attach photos, videos, or files. Everything will be encrypted together at the end.")
                        .multilineTextAlignment(.center)
                }
            } else {
                Conversation(
                    mode: .write,
                    messages: self.$vm.messages,
                    pendingImports: self.vm.pendingImports,
                    attachmentManager: self.vm.attachmentManager,
                    onDelete: { self.vm.deleteMessage($0) }
                )
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
                    ZStack {
                        Circle()
                            .fill(Color(.tertiarySystemFill))
                            .overlay(Circle().strokeBorder(Color(.separator), lineWidth: 0.5))
                            .frame(width: 34, height: 34)
                        Image(systemName: "plus")
                            .font(.system(size: 15, weight: .medium))
                            .foregroundStyle(Color.occultaAccent)
                    }
                }
                .tint(.occultaAccent)

                TextField("Type a message...", text: self.$vm.draftText, axis: .vertical)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: 22))
                    .lineLimit(1...5)
                    .tint(.occultaAccent)

                let hasText = !self.vm.draftText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                Button { self.vm.addText() } label: {
                    ZStack {
                        Circle()
                            .fill(hasText ? Color.occultaAccent : Color(.tertiarySystemFill))
                            .frame(width: 34, height: 34)
                        Image(systemName: "paperplane.fill")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(hasText ? AnyShapeStyle(.white) : AnyShapeStyle(Color.secondary))
                    }
                }
                .disabled(!hasText)
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(Color(.systemBackground))
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle(self.firstName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: self.encryptAction) {
                    Text("Encrypt")
                        .font(.system(size: 13, weight: .semibold))
                }
                .disabled(!self.canEncrypt)
                .tint(.occultaAccent)
            }
        }
        .sheet(item: self.$vm.encryptedURL) { url in
            ActivityView(activityItems: [url], onComplete: { completed in
                try? FileManager.default.removeItem(at: url)
                if completed { self.vm.clearAfterEncrypt() }
            })
        }
        .alert("Error", isPresented: self.$vm.isShowingError) {
            Button("OK") { }
        } message: {
            Text(self.vm.errorMessage)
        }
        .sheet(isPresented: self.$showMediaPicker) {
            PHPickerRepresentable(isPresented: self.$showMediaPicker) { results in
                results.forEach { result in Task { await self.vm.handleMedia(result) } }
            }
        }
        .fileImporter(
            isPresented: self.$showFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            self.vm.handleFile(result)
        }
    }

    private func encryptAction() {
        let cm  = self.contactManager
        let scm = self.shardCustodyManager
        let vlt = self.vaultManager
        Task { await self.vm.encrypt(contactManager: cm, shardCustodyManager: scm, vaultManager: vlt) }
    }
}

// MARK: - Conversation

extension ComposableMessage {
    struct Conversation: View {
        let mode: Modes
        @Binding var messages: [Occulta.File]
        var pendingImports:    [PendingImport]       = []
        var attachmentManager: AttachmentManager?    = nil
        var onDelete:          ((Occulta.File) -> Void)? = nil

        enum Modes {
            case read(messageOwner: String), write
        }

        var body: some View {
            VStack {
                if case .read(let owner) = self.mode {
                    Contact.Info(identifier: owner).padding(.top)
                }

                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .trailing, spacing: 24) {
                            ForEach(Array(self.messages.enumerated()), id: \.element.id) { index, file in
                                VStack(spacing: 6) {
                                    if index == 0 || self.shouldShowDateSeparator(
                                        before: self.messages[index - 1], current: file
                                    ) {
                                        DateHeader(date: file.date ?? Date())
                                    }
                                    MessageBubble(
                                        file: file,
                                        mode: self.mode,
                                        attachmentManager: self.attachmentManager,
                                        onDelete: self.onDelete.map { cb in { cb(file) } }
                                    )
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
                            if let last = latest.last { proxy.scrollTo(last.id, anchor: .bottom) }
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

        private func shouldShowDateSeparator(before: Occulta.File, current: Occulta.File) -> Bool {
            guard let d1 = before.date, let d2 = current.date else { return false }
            return !Calendar.current.isDate(d1, inSameDayAs: d2)
        }
    }
}

// MARK: - MessageBubble

extension ComposableMessage {
    struct MessageBubble: View {
        let file:              Occulta.File
        let mode:              Conversation.Modes
        var attachmentManager: AttachmentManager? = nil
        var onDelete:          (() -> Void)?      = nil

        @State private var showingFullScreen = false
        @State private var videoPlayer:    AVPlayer? = nil
        @State private var decryptedImage: UIImage?  = nil
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
            guard let url  = self.file.url,
                  let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize,
                  size > 0
            else { return nil }
            return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
        }

        @ViewBuilder private var fullScreenContent: some View {
            if case .file(let meta) = self.file.format,
               FileExtensions.Image(rawValue: meta.extension ?? "") != nil {
                FullScreenImageViewer(image: self.decryptedImage)
            }
        }

        @ViewBuilder private var contentPreview: some View {
            switch self.file.format {
            case .text:
                if let data = self.file.content, let text = String(data: data, encoding: .utf8) {
                    Text(text.withDetectedLinks())
                        .padding(14)
                        .background(Color.occultaAccent.opacity(0.15))
                        .foregroundStyle(self.colorScheme == .dark ? .white : .black)
                        .clipShape(RoundedRectangle(cornerRadius: 18))
                        .contextMenu {
                            Button {
                                UIPasteboard.general.setItems(
                                    [[UIPasteboard.typeAutomatic: text]],
                                    options: [.expirationDate: Date().addingTimeInterval(120)]
                                )
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
                if FileExtensions.Image(rawValue: metadata.extension ?? "") != nil {
                    self.imageBubble(name: name, metadata: metadata)
                } else if FileExtensions.Video(rawValue: metadata.extension ?? "") != nil,
                          let url = self.file.url {
                    self.videoBubble(name: name, url: url, metadata: metadata)
                } else {
                    self.genericFileBubble(name: name, metadata: metadata)
                }

            default:
                Text("Unsupported content")
                    .padding(14)
                    .background(Color.occultaAccent)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
            }
        }

        @ViewBuilder private func imageBubble(name: String, metadata: Occulta.File.Metadata) -> some View {
            VStack(spacing: 6) {
                Group {
                    if let img = self.decryptedImage {
                        Image(uiImage: img).resizable().scaledToFill()
                    } else {
                        ProgressView().tint(.occultaAccent)
                    }
                }
                .frame(maxWidth: 260, maxHeight: 320)
                .clipShape(RoundedRectangle(cornerRadius: 18))
                .onTapGesture { guard self.decryptedImage != nil else { return }; self.showingFullScreen = true }
                .task(id: "\(self.file.url?.path ?? "")|\(self.attachmentManager != nil)") {
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
                        ActivityView(activityItems: [manager.shareProvider(at: url, filename: name, contentType: type)])
                    }
                }

                self.fileCaptionRow(name: name)
            }
        }

        @ViewBuilder private func videoBubble(name: String, url: URL, metadata: Occulta.File.Metadata) -> some View {
            VStack(spacing: 6) {
                Group {
                    if let player = self.videoPlayer { VideoPlayer(player: player) }
                    else { Color.black }
                }
                .frame(width: 260, height: 200)
                .clipShape(RoundedRectangle(cornerRadius: 18))
                .onAppear { self.videoPlayer = self.attachmentManager?.player(for: url) ?? AVPlayer(url: url) }
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

                self.fileCaptionRow(name: name)
            }
        }

        @ViewBuilder private func genericFileBubble(name: String, metadata: Occulta.File.Metadata) -> some View {
            HStack {
                Image(systemName: "doc.fill").font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).lineLimit(1)
                    if let size = self.fileSize {
                        Text(size).font(.caption2).foregroundStyle(.white.opacity(0.7))
                    }
                }
            }
            .padding(14)
            .background(Color.occultaAccent)
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

        @ViewBuilder private func fileCaptionRow(name: String) -> some View {
            HStack(spacing: 4) {
                Text(name).font(.caption).foregroundStyle(.primary)
                if let size = self.fileSize {
                    Text("·").font(.caption).foregroundStyle(.secondary)
                    Text(size).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - DateHeader

extension ComposableMessage {
    struct DateHeader: View {
        let date: Date

        var body: some View {
            Text(self.label)
                .font(.caption.bold())
                .foregroundStyle(.secondary)
                .padding(.vertical, 6)
                .padding(.horizontal, 16)
                .background(Color(.systemGray5))
                .clipShape(Capsule())
                .frame(maxWidth: .infinity)
        }

        private var label: String {
            let cal = Calendar.current
            if cal.isDateInToday(date)     { return "Today" }
            if cal.isDateInYesterday(date) { return "Yesterday" }
            let f = DateFormatter(); f.dateStyle = .medium
            return f.string(from: date)
        }
    }
}

// MARK: - PendingImportBubble

private struct PendingImportBubble: View {
    let pending: PendingImport

    var body: some View {
        HStack(alignment: .center) {
            Spacer()
            VStack(alignment: .trailing, spacing: 6) {
                ZStack {
                    if let thumb = self.pending.thumbnail {
                        Image(uiImage: thumb).resizable().scaledToFill()
                        Color.black.opacity(0.4)
                    } else {
                        Color.black
                    }
                    VStack(spacing: 6) {
                        ProgressView().tint(.white)
                        Text("Loading…").font(.caption2).foregroundStyle(.white)
                    }
                }
                .frame(width: 260, height: 200)
                .clipShape(RoundedRectangle(cornerRadius: 18))

                ProgressView(value: self.pending.progress)
                    .tint(.occultaAccent)
                    .frame(width: 260)
                    .animation(.linear(duration: 0.1), value: self.pending.progress)

                HStack(spacing: 4) {
                    Text(self.pending.filename).font(.caption).foregroundStyle(.primary)
                    Text("·").font(.caption).foregroundStyle(.secondary)
                    Text(self.pending.isLoading ? "Loading…" : "Encrypting…")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 16)
    }
}

// MARK: - FullScreenImageViewer

private struct FullScreenImageViewer: View {
    let image: UIImage?
    @Environment(\.dismiss) private var dismiss

    @State private var scale:         CGFloat  = 1.0
    @State private var offset:        CGSize   = .zero
    @GestureState private var gestureScale:  CGFloat  = 1.0
    @GestureState private var gestureOffset: CGSize   = .zero

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()

            if let image = self.image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .scaleEffect(max(1, self.scale * self.gestureScale))
                    .offset(
                        x: self.offset.width  + self.gestureOffset.width,
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
                        withAnimation(.spring()) { self.scale = 1; self.offset = .zero }
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

// MARK: - Preview

#Preview {
    NavigationStack {
        ComposableMessage(vm: ComposeViewModel(identifier: UUID().uuidString))
            .environment(ContactManager.preview)
    }
}

#Preview {
    NavigationStack {
        ComposableMessage.Conversation(
            mode: .read(messageOwner: UUID().uuidString),
            messages: .constant([
                Occulta.File(content: "https://www.apple.com".data(using: .utf8), format: .text),
                Occulta.File(content: "Hi".data(using: .utf8), format: .text)
            ])
        )
    }
}
