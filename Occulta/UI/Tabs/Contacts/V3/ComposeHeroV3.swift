//
//  ComposeHeroV3.swift
//  Occulta
//

import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

// MARK: - Compose Hero

struct ComposeHeroV3: View {
    @Bindable var vm: ComposeViewModel
    let headerRight:  String
    let encryptLabel: String
    let onEncrypt:    () async -> Void

    @State private var showMediaPicker = false
    @State private var showFilePicker  = false

    private var canEncrypt: Bool {
        !self.vm.draftText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || !self.vm.messages.isEmpty
    }

    private var estimatedBundleSize: Int {
        let textBytes = self.vm.draftText.utf8.count
        let fileBytes = self.vm.messages.reduce(0) { acc, file in
            guard let url  = file.url,
                  let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize
            else { return acc }
            return acc + size
        }
        return max(195, textBytes + fileBytes + 195 + self.vm.messages.count * 80)
    }

    private var estimatedBundleSizeLabel: String {
        ByteCountFormatter.string(fromByteCount: Int64(self.estimatedBundleSize), countStyle: .file)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Encrypt a message").font(.body.bold())
                Spacer()
                Text(self.headerRight)
                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .padding(.bottom, 10)

            TextField("", text: self.$vm.draftText, axis: .vertical)
                .lineLimit(4...)
                .frame(minHeight: self.vm.messages.isEmpty ? 100 : 60, alignment: .topLeading)
                .tint(.occultaAccent)

            let fileItems = self.vm.messages
                .filter { if case .file = $0.format { return true }; return false }
                .sorted { ($0.date ?? .distantPast) < ($1.date ?? .distantPast) }
            if !fileItems.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(fileItems) { file in
                            AttachmentChipV3(file: file) { self.vm.deleteMessage(file) }
                        }
                    }
                    .padding(.vertical, 8)
                }
            }

            Divider().padding(.top, self.vm.messages.isEmpty ? 10 : 2)

            HStack {
                HStack(spacing: 10) {
                    Menu {
                        Button { self.showMediaPicker = true } label: {
                            Label("Photos & Videos", systemImage: "photo")
                        }
                        Button { self.showFilePicker = true } label: {
                            Label("Browse Files", systemImage: "folder")
                        }
                    } label: {
                        ZStack {
                            Circle()
                                .fill(Color(.tertiarySystemFill))
                                .overlay(Circle().strokeBorder(Color(.separator), lineWidth: 0.5))
                                .frame(width: 30, height: 30)
                            Image(systemName: "plus")
                                .font(.system(size: 14, weight: .medium))
                                .foregroundStyle(.secondary)
                        }
                    }
                    .tint(.occultaAccent)

                    HStack(spacing: 6) {
                        Circle().fill(Color.occultaVerified).frame(width: 6, height: 6)
                        Text("~\(self.estimatedBundleSizeLabel)")
                            .font(.system(size: 10, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .contentTransition(.numericText())
                            .animation(.easeInOut(duration: 0.2), value: self.estimatedBundleSize)
                    }
                }
                Spacer()
                Button {
                    let onEncrypt = self.onEncrypt
                    Task { await onEncrypt() }
                } label: {
                    Text(self.encryptLabel)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(self.canEncrypt ? .white : .secondary)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 7)
                        .background(Capsule().fill(self.canEncrypt ? Color.occultaAccent : Color(.tertiarySystemFill)))
                }
                .disabled(!self.canEncrypt)
                .buttonStyle(.plain)
            }
            .padding(.top, 10)
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .sheet(isPresented: self.$showMediaPicker) {
            PHPickerRepresentable(isPresented: self.$showMediaPicker) { results in
                results.forEach { result in Task { await self.vm.handleMedia(result) } }
            }
        }
        .fileImporter(
            isPresented: self.$showFilePicker,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            self.vm.handleFile(result)
        }
    }
}

// MARK: - Attachment Chip

private struct AttachmentChipV3: View {
    let file:     Occulta.File
    let onRemove: () -> Void

    private var isText: Bool {
        if case .text = self.file.format { return true }
        return false
    }

    private var label: String {
        switch self.file.format {
        case .text:
            guard let data = self.file.content, let str = String(data: data, encoding: .utf8) else { return "text" }
            let truncated = str.trimmingCharacters(in: .whitespacesAndNewlines)
            return truncated.count > 28 ? String(truncated.prefix(28)) + "…" : truncated
        case .file(let meta):
            return [meta.name, meta.extension].compactMap { $0 }.joined(separator: ".")
        default:
            return "file"
        }
    }

    private var sfSymbol: String {
        if self.isText { return "paragraph" }
        guard case .file(let meta) = self.file.format else { return "doc" }
        switch meta.extension?.lowercased() {
        case "jpg", "jpeg", "png", "heic": return "photo"
        case "mov", "mp4", "m4v":          return "video"
        default:                           return "doc"
        }
    }

    private var sizeLabel: String? {
        guard !self.isText,
              let url  = self.file.url,
              let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize
        else { return nil }
        return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
    }

    var body: some View {
        HStack(spacing: 6) {
            ZStack {
                RoundedRectangle(cornerRadius: 4)
                    .fill(Color.occultaAccent)
                    .frame(width: 20, height: 20)
                Image(systemName: self.sfSymbol)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.white)
            }
            Text(self.label)
                .font(.system(size: 11, weight: .regular, design: .monospaced))
                .lineLimit(1)
            if let size = self.sizeLabel {
                Text(size)
                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .fixedSize()
            }
            Button(action: self.onRemove) {
                Image(systemName: "xmark")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.leading, 8)
        .padding(.trailing, 6)
        .padding(.vertical, 5)
        .background(Color(.tertiarySystemFill))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color(.separator), lineWidth: 0.5))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
