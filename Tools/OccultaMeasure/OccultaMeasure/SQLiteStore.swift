//
//  SQLiteStore.swift
//  OccultaMeasure
//
//  A plain SQLite file through the `sqlite3` C API, one `WITHOUT ROWID` table keyed by the row's 16-byte ID.
//

import Foundation
import SQLite3

final class SQLiteStore {
    private var database: OpaquePointer?

    let path: String

    init(path: String) throws {
        self.path = path
        guard sqlite3_open_v2(path, &self.database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK else {
            throw MeasureError("sqlite3_open_v2 failed: \(self.message)")
        }
    }

    deinit {
        sqlite3_close(self.database)
    }

    private var message: String {
        self.database.map { String(cString: sqlite3_errmsg($0)) } ?? "no database"
    }

    /// Closes the connection. When it is the last one, SQLite checkpoints and, in WAL mode, deletes the `-wal`.
    func close() throws {
        let status = sqlite3_close(self.database)
        guard status == SQLITE_OK else { throw MeasureError("sqlite3_close returned \(status)") }
        self.database = nil
    }

    func execute(_ sql: String) throws {
        guard sqlite3_exec(self.database, sql, nil, nil, nil) == SQLITE_OK else {
            throw MeasureError("\(sql): \(self.message)")
        }
    }

    /// The first column of the first row `sql` returns, as text.
    func scalar(_ sql: String) throws -> String {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(self.database, sql, -1, &statement, nil) == SQLITE_OK else {
            throw MeasureError("\(sql): \(self.message)")
        }
        defer { sqlite3_finalize(statement) }

        guard sqlite3_step(statement) == SQLITE_ROW, let text = sqlite3_column_text(statement, 0) else {
            throw MeasureError("\(sql) returned no row")
        }
        return String(cString: text)
    }

    /// Whether SQLite keeps the `-wal` after the last connection closes (`SQLITE_FCNTL_PERSIST_WAL`).
    func persistsWAL() throws -> Bool {
        var flag: Int32 = -1
        guard sqlite3_file_control(self.database, nil, SQLITE_FCNTL_PERSIST_WAL, &flag) == SQLITE_OK else {
            throw MeasureError("SQLITE_FCNTL_PERSIST_WAL query failed: \(self.message)")
        }
        return flag != 0
    }

    func createTable(_ table: String) throws {
        try self.execute("CREATE TABLE \(table) (id BLOB PRIMARY KEY, body BLOB NOT NULL) WITHOUT ROWID")
    }

    func insert(_ rows: [Row], into table: String) throws {
        try self.execute("BEGIN")
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(self.database, "INSERT INTO \(table) (id, body) VALUES (?, ?)", -1, &statement, nil)
                == SQLITE_OK else { throw MeasureError("insert: \(self.message)") }
        defer { sqlite3_finalize(statement) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for row in rows {
            row.id.withUnsafeBytes { _ = sqlite3_bind_blob(statement, 1, $0.baseAddress, Int32($0.count), transient) }
            row.sealed.withUnsafeBytes { _ = sqlite3_bind_blob(statement, 2, $0.baseAddress, Int32($0.count), transient) }
            guard sqlite3_step(statement) == SQLITE_DONE else { throw MeasureError("insert: \(self.message)") }
            sqlite3_reset(statement)
        }
        try self.execute("COMMIT")
    }

    func readAll(from table: String) throws -> [Row] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(self.database, "SELECT id, body FROM \(table)", -1, &statement, nil) == SQLITE_OK else {
            throw MeasureError("read: \(self.message)")
        }
        defer { sqlite3_finalize(statement) }

        var rows: [Row] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            rows.append(Row(id: Self.blob(statement, 0), sealed: Self.blob(statement, 1)))
        }
        return rows
    }

    func fetch(id: Data, from table: String) throws -> Data {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(self.database, "SELECT body FROM \(table) WHERE id = ?", -1, &statement, nil)
                == SQLITE_OK else { throw MeasureError("fetch: \(self.message)") }
        defer { sqlite3_finalize(statement) }

        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        id.withUnsafeBytes { _ = sqlite3_bind_blob(statement, 1, $0.baseAddress, Int32($0.count), transient) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw MeasureError("fetch: no row for the ID") }
        return Self.blob(statement, 0)
    }

    private static func blob(_ statement: OpaquePointer?, _ column: Int32) -> Data {
        guard let bytes = sqlite3_column_blob(statement, column) else { return Data() }
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, column)))
    }
}
