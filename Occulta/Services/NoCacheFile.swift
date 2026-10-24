//
//  NoCacheFile.swift
//  Occulta
//
//  File I/O that keeps the page cache out of it, in one place. The inbound `.occ` reader, the `.eatt`
//  writers, the staged-file reader and the import loop all want the same thing: no plaintext or ciphertext
//  piling up as cached pages behind the cursor, so resident memory stays a few chunks whatever the file's
//  size. STREAMING_SPEC §8.2.
//

import Foundation

nonisolated enum NoCacheFile {

    /// Opens `url` for positioned reads.
    static func reader(_ url: URL) throws -> Reader { try Reader(url: url) }

    /// Creates `url` for writing. It is deleted if anything goes wrong, and if the writer is dropped
    /// unfinished.
    static func writer(_ url: URL) throws -> Writer { try Writer(url: url) }

    // MARK: - Reader

    /// A read-only handle with `F_NOCACHE` on and read-ahead off.
    ///
    /// Reads are positioned (`pread`), so one reader serves several passes over the file, and a pass can
    /// start anywhere. The handle stays valid after the file is unlinked, which is how an inbound file is
    /// kept readable once its directory entry is gone.
    nonisolated final class Reader: @unchecked Sendable {
        private let descriptor: Int32

        /// The file's length when it was opened.
        let size: UInt64

        init(url: URL) throws {
            let fd = open(url.path(percentEncoded: false), O_RDONLY)
            guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }

            _ = fcntl(fd, F_NOCACHE, 1)   // bypass the unified buffer cache
            _ = fcntl(fd, F_RDAHEAD, 0)   // no kernel read-ahead (an int 0, not a pointer)

            var info = stat()
            guard fstat(fd, &info) == 0 else {
                let code = errno
                close(fd)
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(code))
            }
            self.descriptor = fd
            self.size = UInt64(info.st_size)
        }

        deinit { close(self.descriptor) }

        /// Up to `count` bytes at `offset`: fewer only at the end of the file, none past it.
        func read(at offset: UInt64, count: Int) throws -> Data {
            guard count > 0 else { return Data() }
            var data = Data(count: count)
            var filled = 0
            while filled < count {
                let n = data.withUnsafeMutableBytes { buffer in
                    pread(self.descriptor, buffer.baseAddress! + filled, count - filled, off_t(offset) + off_t(filled))
                }
                if n < 0 {
                    if errno == EINTR { continue }
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
                }
                if n == 0 { break }
                filled += n
            }
            if filled < count { data.removeSubrange(filled..<count) }
            return data
        }

        /// Calls `body` with consecutive pieces of `range`, each `size` bytes but for the last. Only one
        /// piece is alive at a time. Throws if the file ends before `range` does.
        func forEachChunk(range: Range<UInt64>, size: Int, _ body: (Data) throws -> Void) throws {
            var offset = range.lowerBound
            while offset < range.upperBound {
                let want = Int(min(UInt64(size), range.upperBound - offset))
                let piece = try self.read(at: offset, count: want)
                guard piece.count == want else { throw Errors.truncated }
                try body(piece)
                offset += UInt64(want)
            }
        }

        nonisolated enum Errors: Error { case truncated }
    }

    // MARK: - Writer

    /// A write handle on a new file: `.complete` protection, `F_NOCACHE`, excluded from backup.
    ///
    /// The file is removed if a write fails, and if the writer is released before `finish()`: a partial
    /// file in `tmp/` is a trace of its own.
    nonisolated final class Writer: @unchecked Sendable {
        private let url: URL
        private var descriptor: Int32
        private var position: UInt64 = 0
        private var finished = false

        init(url: URL) throws {
            self.url = url
            FileManager.default.createFile(
                atPath: url.path(percentEncoded: false), contents: nil,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
            let fd = open(url.path(percentEncoded: false), O_WRONLY)
            guard fd >= 0 else {
                let code = errno
                try? FileManager.default.removeItem(at: url)
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(code))
            }
            self.descriptor = fd
            _ = fcntl(fd, F_NOCACHE, 1)

            var excluded = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? excluded.setResourceValues(values)
        }

        deinit { self.abandon() }

        /// Bytes written so far through `write(_:)`.
        var length: UInt64 { self.position }

        /// Appends `data`.
        func write(_ data: Data) throws {
            try self.guarded {
                try self.writeFully(data, at: self.position)
                self.position += UInt64(data.count)
            }
        }

        /// Overwrites bytes at `offset`, which must already have been written: a header that is only known
        /// once the content is.
        func overwrite(_ data: Data, at offset: UInt64) throws {
            try self.guarded {
                precondition(offset + UInt64(data.count) <= self.position)
                try self.writeFully(data, at: offset)
            }
        }

        /// Flushes to disk and closes. The file is kept.
        func finish() throws {
            try self.guarded {
                guard fsync(self.descriptor) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
                self.finished = true
                close(self.descriptor)
                self.descriptor = -1
            }
        }

        /// Closes and removes the file. Safe to call at any point, and after `finish()` it does nothing.
        func abandon() {
            guard !self.finished else { return }
            self.finished = true
            if self.descriptor >= 0 { close(self.descriptor); self.descriptor = -1 }
            try? FileManager.default.removeItem(at: self.url)
        }

        private func guarded(_ body: () throws -> Void) throws {
            guard !self.finished else { throw Errors.closed }
            do { try body() } catch {
                self.abandon()
                throw error
            }
        }

        private func writeFully(_ data: Data, at offset: UInt64) throws {
            var written = 0
            while written < data.count {
                let n = data.withUnsafeBytes { buffer in
                    pwrite(self.descriptor, buffer.baseAddress! + written, data.count - written, off_t(offset) + off_t(written))
                }
                if n < 0 {
                    if errno == EINTR { continue }
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
                }
                written += n
            }
        }

        nonisolated enum Errors: Error { case closed }
    }
}
