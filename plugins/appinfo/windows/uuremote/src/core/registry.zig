//! Registry evidence of GameViewer/UU远程 from a user's `NTUSER.DAT`.
//!
//! Three keys carry user-level evidence (read from the live machine and
//! from evidence images alike):
//!
//!   Software\Netease\GameViewer              install dir, version, cache path
//!   Software\Netease\GameViewer\Common       installed / ever-run flags
//!   Software\Netease\GameViewer\login\userPhone
//!       one value per login: the value NAME is the phone number
//!       (`+86 10000000000`), the QWORD data is the login time in
//!       microseconds since the Unix epoch.
//!
//! `report_home_date` and friends are REG_BINARY blobs of unknown structure
//! and are deliberately skipped, like every other opaque value.

const std = @import("std");
const regf = @import("regf_zig");

const Allocator = std.mem.Allocator;

const GAMEVIEWER_KEY = "Software\\Netease\\GameViewer";

/// The registry evidence of one user hive.
pub const RegistryInfo = struct {
    app_version: ?[]const u8 = null,
    install_dir: ?[]const u8 = null,
    cache_path: ?[]const u8 = null,
    installed: ?bool = null,
    ever_run: ?bool = null,
    /// One entry per phone value under `login\userPhone`.
    logins: []const Login = &.{},
};

/// One login: the phone number and when it logged in.
pub const Login = struct {
    phone: []const u8,
    /// Unix milliseconds; null when the stored value is out of range.
    login_ms: ?i64 = null,
};

/// Reads the GameViewer keys from an in-memory hive image. Every string is
/// duped into `alloc`; free with `freeInfo`. Returns an error only when the
/// image is not a hive at all — missing keys yield an empty `RegistryInfo`.
pub fn collect(alloc: Allocator, gpa: Allocator, bytes: []const u8) (regf.Error || Allocator.Error)!RegistryInfo {
    var hive = try regf.Hive.fromBytes(gpa, bytes, null);
    defer hive.deinit();

    var info = RegistryInfo{};
    errdefer freeInfo(alloc, &info);

    info.app_version = try stringValue(alloc, &hive, GAMEVIEWER_KEY, "Version");
    info.install_dir = try stringValue(alloc, &hive, GAMEVIEWER_KEY, "instDir");
    info.cache_path = try stringValue(alloc, &hive, GAMEVIEWER_KEY, "CachePath");

    const common_key = GAMEVIEWER_KEY ++ "\\Common";
    info.installed = try flagValue(alloc, &hive, common_key, "gameviewer_installed");
    info.ever_run = try flagValue(alloc, &hive, common_key, "has_been_run");

    const phone_key = GAMEVIEWER_KEY ++ "\\login\\userPhone";
    if (hive.listValues(phone_key, gpa)) |captured| {
        var values = captured;
        defer {
            for (values.items) |*entry| entry.deinit(gpa);
            values.deinit(gpa);
        }
        var logins: std.ArrayList(Login) = .empty;
        errdefer logins.deinit(alloc);
        for (values.items) |entry| {
            // The default (unnamed) value is not a phone number.
            if (entry.name.len == 0) continue;
            var login = Login{ .phone = try alloc.dupe(u8, entry.name) };
            errdefer alloc.free(login.phone);
            switch (entry.value) {
                .qword => |number| login.login_ms = microsToMillis(number),
                .dword => |number| login.login_ms = microsToMillis(number),
                else => {},
            }
            try logins.append(alloc, login);
        }
        info.logins = try logins.toOwnedSlice(alloc);
    } else |_| {
        // No login key: the user never logged in on this machine.
    }
    return info;
}

pub fn freeInfo(alloc: Allocator, info: *RegistryInfo) void {
    inline for (.{ "app_version", "install_dir", "cache_path" }) |field| {
        if (@field(info, field)) |value| alloc.free(value);
    }
    for (info.logins) |login| alloc.free(login.phone);
    if (info.logins.len > 0) alloc.free(info.logins);
}

/// The userPhone QWORD is microseconds since the epoch (observed
/// `0x656c9bbb81934` ≈ 2026-07). Out-of-range values are kept as null rather
/// than guessed.
fn microsToMillis(micros: u64) ?i64 {
    if (micros < 1_000_000_000_000_000 or micros > 2_000_000_000_000_000) return null;
    return @intCast(micros / 1000);
}

fn stringValue(alloc: Allocator, hive: *regf.Hive, path: []const u8, name: []const u8) Allocator.Error!?[]const u8 {
    const value = hive.getValue(path, name) catch return null;
    defer value.deinit(hive.gpa);
    const text = switch (value) {
        .sz => |text| text,
        .expand_sz => |text| text,
        else => return null,
    };
    if (text.len == 0) return null;
    return try alloc.dupe(u8, text);
}

fn flagValue(alloc: Allocator, hive: *regf.Hive, path: []const u8, name: []const u8) Allocator.Error!?bool {
    const text = (try stringValue(alloc, hive, path, name)) orelse return null;
    defer alloc.free(text);
    if (std.ascii.eqlIgnoreCase(text, "true")) return true;
    if (std.ascii.eqlIgnoreCase(text, "false")) return false;
    return null;
}

const testing = std.testing;

/// Builds a synthetic NTUSER.DAT with the three GameViewer keys. The hive
/// format is exercised for real; the values carry no machine data. Public
/// so the end-to-end fixtures can embed a hive without carrying binary
/// test data.
pub fn buildFixtureHive(gpa: Allocator) ![]u8 {
    var hive = try regf.Hive.initEmpty(gpa, "NTUSER");
    defer hive.deinit();

    try setString(gpa, &hive, GAMEVIEWER_KEY, "Version", "4.41.0.2311");
    try setString(gpa, &hive, GAMEVIEWER_KEY, "instDir", "E:\\wyyc\\GameViewer");
    try setString(gpa, &hive, GAMEVIEWER_KEY, "CachePath", "C:\\Users\\u\\AppData\\Local\\GameViewer");
    try setString(gpa, &hive, GAMEVIEWER_KEY ++ "\\Common", "gameviewer_installed", "true");
    try setString(gpa, &hive, GAMEVIEWER_KEY ++ "\\Common", "has_been_run", "true");
    try setString(gpa, &hive, GAMEVIEWER_KEY ++ "\\Common", "report_home_date", "\x40\x00\x56\x00");
    try setQword(gpa, &hive, GAMEVIEWER_KEY ++ "\\login\\userPhone", "+86 10000000000", 1_784_155_960_891_228);

    return hive.toBytes(gpa);
}

fn setString(gpa: Allocator, hive: *regf.Hive, path: []const u8, name: []const u8, text: []const u8) !void {
    {
        var key = try hive.createKey(path);
        key.deinit(gpa);
    }
    // setValue copies the data; the scratch copy dies here.
    const copy = try gpa.dupe(u8, text);
    defer gpa.free(copy);
    try hive.setValue(path, name, .{ .sz = copy });
}

fn setQword(gpa: Allocator, hive: *regf.Hive, path: []const u8, name: []const u8, number: u64) !void {
    {
        var key = try hive.createKey(path);
        key.deinit(gpa);
    }
    try hive.setValue(path, name, .{ .qword = number });
}

test "reads install info, flags and logins from a hive" {
    const image = try buildFixtureHive(testing.allocator);
    defer testing.allocator.free(image);

    var info = try collect(testing.allocator, testing.allocator, image);
    defer freeInfo(testing.allocator, &info);

    try testing.expectEqualStrings("4.41.0.2311", info.app_version.?);
    try testing.expectEqualStrings("E:\\wyyc\\GameViewer", info.install_dir.?);
    try testing.expectEqualStrings("C:\\Users\\u\\AppData\\Local\\GameViewer", info.cache_path.?);
    try testing.expectEqual(true, info.installed.?);
    try testing.expectEqual(true, info.ever_run.?);
    try testing.expectEqual(@as(usize, 1), info.logins.len);
    try testing.expectEqualStrings("+86 10000000000", info.logins[0].phone);
    try testing.expectEqual(@as(i64, 1_784_155_960_891), info.logins[0].login_ms.?);
}

test "a hive without GameViewer keys yields empty info" {
    var hive = try regf.Hive.initEmpty(testing.allocator, "NTUSER");
    defer hive.deinit();
    const image = try hive.toBytes(testing.allocator);
    defer testing.allocator.free(image);

    var info = try collect(testing.allocator, testing.allocator, image);
    defer freeInfo(testing.allocator, &info);
    try testing.expect(info.app_version == null);
    try testing.expectEqual(@as(usize, 0), info.logins.len);
}

test "not a hive at all" {
    // A full-size block of junk fails the signature check.
    const junk: [4096]u8 = @splat('x');
    try testing.expectError(error.BadSignature, collect(testing.allocator, testing.allocator, &junk));
    // A too-short buffer is rejected as truncated.
    try testing.expectError(error.Truncated, collect(testing.allocator, testing.allocator, "not a hive"));
}

test "microsecond conversion bounds" {
    try testing.expect(microsToMillis(0) == null);
    try testing.expect(microsToMillis(999_999_999_999_999) == null);
    try testing.expectEqual(@as(i64, 1_784_155_960_891), microsToMillis(1_784_155_960_891_228).?);
    try testing.expect(microsToMillis(2_000_000_000_000_001) == null);
}
