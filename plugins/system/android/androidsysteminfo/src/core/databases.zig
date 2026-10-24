//! SQLite-backed system databases, read with the shared `zqlite` wrapper
//! over the real SQLite amalgamation:
//!
//! - `/data/system_ce/0/accounts_ce.db` — the AccountManager database:
//!   system accounts (`accounts`), their credentials (`password` column)
//!   and the per-account `extras`.
//! - `/data/system/gnssCollectData.db` — vendor GNSS statistics
//!   (`GnssCollectData`: one row per positioning session).
//!
//! The evidence bytes are not a path, so the analyzer materializes the file
//! through the host and opens the copy read-only.

const std = @import("std");
const zqlite = @import("zqlite");

/// One system account.
pub const Account = struct {
    name: []const u8,
    type: []const u8,
    password: ?[]const u8 = null,
};

/// One GNSS positioning session.
pub const GnssSession = struct {
    session_id: i64,
    /// Epoch value as stored; the caller decides seconds vs milliseconds by
    /// magnitude.
    start_time: ?i64 = null,
    /// Time to first fix, milliseconds.
    ttff: ?i64 = null,
    run_time: ?i64 = null,
    lose_times: ?i64 = null,
    sap_number: ?i64 = null,
    pdr_number: ?i64 = null,
    total_number: ?i64 = null,
    l1_cn0: ?f64 = null,
    l5_cn0: ?f64 = null,
    b1_cn0: ?f64 = null,
};

pub const OpenFlags = zqlite.OpenFlags.ReadOnly | zqlite.OpenFlags.EXResCode;

/// Reads the `accounts` table; a missing table yields an empty list. The
/// path must be NUL-terminated (`materialize` + `dupeZ`).
pub fn readAccounts(
    arena: std.mem.Allocator,
    path: [:0]const u8,
    accounts: *std.ArrayList(Account),
) error{ OutOfMemory, Db }!void {
    var conn = zqlite.open(path.ptr, OpenFlags) catch return error.Db;
    defer conn.close();

    var rows = conn.rows("SELECT name, type, password FROM accounts ORDER BY _id", .{}) catch return error.Db;
    defer rows.deinit();
    while (rows.next()) |row| {
        accounts.append(arena, .{
            .name = arena.dupe(u8, row.text(0)) catch return error.OutOfMemory,
            .type = arena.dupe(u8, row.text(1)) catch return error.OutOfMemory,
            .password = blk: {
                const value = row.nullableText(2) orelse break :blk null;
                if (value.len == 0) break :blk null;
                break :blk arena.dupe(u8, value) catch return error.OutOfMemory;
            },
        }) catch return error.OutOfMemory;
    }
    if (rows.err) |_| return error.Db;
}

/// Reads the `GnssCollectData` table; a missing table yields an empty list.
pub fn readGnss(
    arena: std.mem.Allocator,
    path: [:0]const u8,
    sessions: *std.ArrayList(GnssSession),
) error{ OutOfMemory, Db }!void {
    var conn = zqlite.open(path.ptr, OpenFlags) catch return error.Db;
    defer conn.close();

    var rows = conn.rows(
        \\SELECT _id, startTime, TTFF, runTime, loseTimes, SAPNumber, PDRNumber,
        \\       totalNumber, L1Top4MeanCn0, L5Top4MeanCn0, B1Top4MeanCn0
        \\  FROM GnssCollectData ORDER BY _id
    , .{}) catch return error.Db;
    defer rows.deinit();
    while (rows.next()) |row| {
        sessions.append(arena, .{
            .session_id = row.int(0),
            .start_time = row.nullableInt(1),
            .ttff = row.nullableInt(2),
            .run_time = row.nullableInt(3),
            .lose_times = row.nullableInt(4),
            .sap_number = row.nullableInt(5),
            .pdr_number = row.nullableInt(6),
            .total_number = row.nullableInt(7),
            .l1_cn0 = row.nullableFloat(8),
            .l5_cn0 = row.nullableFloat(9),
            .b1_cn0 = row.nullableFloat(10),
        }) catch return error.OutOfMemory;
    }
    if (rows.err) |_| return error.Db;
}

/// Whether the named table exists — lets the analyzer tell "empty database"
/// from "not the schema we expect" in its warnings.
pub fn hasTable(path: [:0]const u8, table: []const u8) bool {
    var conn = zqlite.open(path.ptr, OpenFlags) catch return false;
    defer conn.close();
    const sql = std.fmt.allocPrintSentinel(std.heap.page_allocator, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='{s}'", .{table}, 0) catch return false;
    defer std.heap.page_allocator.free(sql);
    const found = conn.row(sql, .{}) catch return false;
    if (found) |row| row.deinit();
    return found != null;
}

const testing = std.testing;

test "round-trips a fixture database through the read path" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buffer);
    const db_path = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/fixture.db", .{path_buffer[0..path_len]}, 0);
    defer testing.allocator.free(db_path);

    // Write the fixture with the same SQLite the plugin reads with.
    {
        var conn = try zqlite.open(db_path.ptr, zqlite.OpenFlags.Create | zqlite.OpenFlags.ReadWrite | zqlite.OpenFlags.EXResCode);
        defer conn.close();
        try conn.exec("CREATE TABLE accounts (_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT NOT NULL, password TEXT)", .{});
        try conn.exec("INSERT INTO accounts (name, type, password) VALUES (?1, ?2, ?3)", .{ "someone@example.com", "com.example", "secret" });
        try conn.exec("INSERT INTO accounts (name, type) VALUES (?1, ?2)", .{ "second@example.com", "com.example" });
    }

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var accounts: std.ArrayList(Account) = .empty;
    try readAccounts(arena_state.allocator(), db_path, &accounts);
    try testing.expectEqual(@as(usize, 2), accounts.items.len);
    try testing.expectEqualStrings("someone@example.com", accounts.items[0].name);
    try testing.expectEqualStrings("com.example", accounts.items[0].type);
    try testing.expectEqualStrings("secret", accounts.items[0].password.?);
    try testing.expect(accounts.items[1].password == null);
    try testing.expect(hasTable(db_path, "accounts"));
    try testing.expect(!hasTable(db_path, "missing"));
}

test "a non-database file reports a clean error" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "junk.db", .data = "not a database at all, just text padding" });
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const db_path = try std.fmt.allocPrintSentinel(testing.allocator, "{s}/junk.db", .{path_buffer[0..path_len]}, 0);
    defer testing.allocator.free(db_path);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var accounts: std.ArrayList(Account) = .empty;
    try testing.expectError(error.Db, readAccounts(arena_state.allocator(), db_path, &accounts));
    try testing.expect(!hasTable(db_path, "accounts"));
}
