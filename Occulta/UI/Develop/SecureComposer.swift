//
//  SecureComposer.swift
//  Occulta
//
//  Ordered chat-style composer — final version per your request
//  Created by Yura
//

import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

struct SecureComposer: View {
    let identifier: String
    
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    @State private var blocks: [ContentBlock] = []
    @State private var currentText: String = ""
    
    @State private var selectedPhotos: [PhotosPickerItem] = []
    @State private var isImportingFiles = false
    
    @State private var isEncrypting = false
    @State private var encryptedFile: EncryptedFile?
    @State private var errorMessage: String?
    
    var body: some View {
        VStack(spacing: 0) {
            // Preview area — ordered blocks (top to bottom = final order)
            ScrollView {
                VStack(spacing: 20) {
                    if blocks.isEmpty {
                        Spacer()
                        ContentUnavailableView("Your secure message", systemImage: "lock.doc", description: Text("Add text, photos, or files below"))
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(blocks.indices, id: \.self) { index in
                            BlockPreview(block: blocks[index]) {
                                blocks.remove(at: index)
                            }
                        }
                    }
                }
                .padding(.vertical, 24)
            }
            
            Divider()
            
            // Bottom chat-style composer
            VStack(spacing: 8) {
                // Expandable text field + Add button
                HStack(alignment: .bottom, spacing: 12) {
                    TextEditor(text: $currentText)
                        .frame(minHeight: 40, maxHeight: 180)
                        .padding(10)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 18))
                        .overlay(alignment: .topLeading) {
                            if currentText.isEmpty {
                                Text("Type message...")
                                    .foregroundStyle(.secondary)
                                    .padding(14)
                                    .padding(.leading, 4)
                            }
                        }
                    
                    Button {
                        addCurrentText()
                    } label: {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.title2)
                    }
                    .disabled(currentText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(.horizontal)
                
                // Attachment buttons + Encrypt
                HStack(spacing: 20) {
                    // Photos / Videos
                    PhotosPicker(selection: $selectedPhotos,
                                 matching: .any(of: [.images, .videos]),
                                 photoLibrary: .shared()) {
                        Image(systemName: "photo.stack.fill")
                            .font(.title2)
                    }
                    
                    // Files / Documents
                    Button {
                        isImportingFiles = true
                    } label: {
                        Image(systemName: "paperclip")
                            .font(.title2)
                    }
                    
                    Spacer()
                    
                    // Encrypt button
                    Button {
                        Task { await encryptAll() }
                    } label: {
                        HStack(spacing: 8) {
                            if isEncrypting {
                                ProgressView().tint(.white)
                            }
                            Text("Encrypt & Share")
                                .fontWeight(.semibold)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(blocks.isEmpty && currentText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(.horizontal)
                .padding(.bottom, 12)
            }
        }
        .navigationTitle("New Secure Message")
        .navigationBarTitleDisplayMode(.inline)
        
        .onChange(of: selectedPhotos) { _, newValue in
            Task { await addPhotos(newValue) }
        }
        .fileImporter(isPresented: $isImportingFiles,
                      allowedContentTypes: [.data],
                      allowsMultipleSelection: true) { result in
            Task { await addFiles(result) }
        }
        .sheet(item: $encryptedFile) { file in
            ShareSheet(items: [file])
        }
        .alert("Error", isPresented: .constant(errorMessage != nil)) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }
    
    // MARK: - Adding blocks
    
    private func addCurrentText() {
        let trimmed = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        
        blocks.append(.text(trimmed))
        currentText = ""
    }
    
    private func addPhotos(_ items: [PhotosPickerItem]) async {
        for item in items {
            guard let data = try? await item.loadTransferable(type: Data.self),
                  let utType = item.supportedContentTypes.first else { continue }
            
            let ext = utType.preferredFilenameExtension ?? "jpg"
            let name = "media_\(UUID().uuidString.prefix(8)).\(ext)"
            
            blocks.append(.media(data: data, name: name, utType: utType))
        }
        selectedPhotos = []
    }
    
    private func addFiles(_ result: Result<[URL], Error>) async {
        switch result {
        case .success(let urls):
            for url in urls {
                guard url.startAccessingSecurityScopedResource() else { continue }
                defer { url.stopAccessingSecurityScopedResource() }
                
                if let data = try? Data(contentsOf: url) {
                    let name = url.deletingPathExtension().lastPathComponent
                    let ext = url.pathExtension.isEmpty ? "file" : url.pathExtension
                    blocks.append(.media(data: data, name: "\(name).\(ext)", utType: nil))
                }
            }
        case .failure(let error):
            errorMessage = error.localizedDescription
        }
    }
    
    // MARK: - Encryption (exact order preserved)
    
    private func encryptAll() async {
        isEncrypting = true
        defer { isEncrypting = false }
        
        var basketFiles: [File] = []
        
        for block in blocks {
            switch block {
            case .text(let text):
                if let data = text.data(using: .utf8) {
                    basketFiles.append(File(content: data, format: .text))
                }
            case .media(let data, let name, _):
                let ext = (name as NSString).pathExtension
                let metadata = File.Metadata(name: name, extension: ext)
                basketFiles.append(File(content: data, format: .file(metadata)))
            }
        }
        
        guard !basketFiles.isEmpty else { return }
        
        let basket = Basket(files: basketFiles, date: .now)
        
        do {
            let encoded = try JSONEncoder().encode(basket)
            guard let encryptedData = try contactManager?.encrypt(data: encoded, for: identifier) else {
                errorMessage = "Encryption failed"
                return
            }
            
            encryptedFile = EncryptedFile(content: encryptedData)
            
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

// MARK: - Supporting Types

enum ContentBlock: Identifiable {
    case text(String)
    case media(data: Data, name: String, utType: UTType?)
    
    var id: UUID { UUID() }
    
    var name: String {
        switch self {
        case .text: return "Message"
        case .media(_, let name, _): return name
        }
    }
    
    var isImage: Bool {
        guard case .media(_, _, let utType) = self else { return false }
        return utType?.conforms(to: .image) == true
    }
    
    var isVideo: Bool {
        guard case .media(_, _, let utType) = self else { return false }
        return utType?.conforms(to: .movie) == true
    }
}

struct BlockPreview: View {
    let block: ContentBlock
    let onRemove: () -> Void
    
    var body: some View {
        ZStack(alignment: .topTrailing) {
            Group {
                switch block {
                case .text(let text):
                    Text(text)
                        .padding()
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                case .media(let data, _, _) where block.isImage:
                    if let uiImage = UIImage(data: data) {
                        Image(uiImage: uiImage)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(maxHeight: 320)
                            .clipShape(RoundedRectangle(cornerRadius: 16))
                    }
                    
                case .media(_, let name, _) where block.isVideo:
                    videoPlaceholder(name: name)
                    
                case .media(_, let name, _):
                    filePlaceholder(name: name)
                }
            }
            
            Button(action: onRemove) {
                Image(systemName: "xmark.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.white, .black.opacity(0.75))
            }
            .padding(8)
        }
        .padding(.horizontal)
    }
    
    private func videoPlaceholder(name: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "video.fill")
                .font(.system(size: 60))
            Text(name)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .frame(height: 180)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }
    
    private func filePlaceholder(name: String) -> some View {
        HStack {
            Image(systemName: "doc.fill")
                .font(.largeTitle)
                .foregroundStyle(.blue)
            VStack(alignment: .leading) {
                Text(name)
                    .fontWeight(.medium)
                Text((name as NSString).pathExtension.uppercased())
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

#Preview {
    NavigationStack {
        SecureComposer(identifier: UUID().uuidString)
    }
}
