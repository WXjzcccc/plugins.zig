//! LovelyCarve Android system analyzer plugin (LPP v2, SDK 0.2.x).
//!
//! Four evidence-scope analyzers over an Android `data` partition:
//!
//! - `baseinfo` 系统信息 — boot headers (dropbox SYSTEM_BOOT, last-header),
//!   framework version attributes (packages.xml) and the device users
//!   (users/*.xml); all ABX or plain text;
//! - `syslog` 系统日志 — the boot log (full logcat), DropBox entries and
//!   ANR traces;
//! - `applist` 应用列表 — packages.xml (ABX) enriched by packages.list, with
//!   the granted runtime permissions;
//! - `netrecords` 网络与其他记录 — Wi-Fi configurations (with the hotspot),
//!   Bluetooth adapter/device store, ADB authorization keys, the
//!   AccountManager database and vendor GNSS statistics (the sqlite inputs
//!   are materialized by the host and opened read-only with zqlite).
//!
//! The format parsers live under `src/core`: `abx` (Android Binary XML),
//! `xml` (plain XML), `boot`, `logcat`, `dropbox`, `packages`, `wifi`,
//! `bluetooth` and `adb`; `databases` bridges to zqlite.

const std = @import("std");
const lc = @import("lovelycarve");

const analyzers = @import("plugin/run.zig");
const records = @import("plugin/records.zig");

/// Must match `id` in plugin.toml.
pub const PLUGIN_ID = "com.wxjzc.androidsysteminfo";

/// Must match the analyzer ids in plugin.toml.
pub const BASEINFO_ANALYZER = "baseinfo";
pub const SYSLOG_ANALYZER = "syslog";
pub const APPLIST_ANALYZER = "applist";
pub const NETRECORDS_ANALYZER = "netrecords";

pub const plugin = lc.Plugin{
    .id = PLUGIN_ID,
    .records = &records.all,
    .analyzers = &.{
        lc.analyzer(BASEINFO_ANALYZER, analyzers.baseinfo),
        lc.analyzer(SYSLOG_ANALYZER, analyzers.syslog),
        lc.analyzer(APPLIST_ANALYZER, analyzers.applist),
        lc.analyzer(NETRECORDS_ANALYZER, analyzers.netrecords),
    },
};

comptime {
    lc.exportPlugin(@This());
}

test {
    _ = @import("core/abx.zig");
    _ = @import("core/adb.zig");
    _ = @import("core/boot.zig");
    _ = @import("core/bluetooth.zig");
    _ = @import("core/databases.zig");
    _ = @import("core/dropbox.zig");
    _ = @import("core/logcat.zig");
    _ = @import("core/packages.zig");
    _ = @import("core/wifi.zig");
    _ = @import("core/xml.zig");
    _ = @import("plugin/analyze.zig");
    _ = @import("plugin/run.zig");
    _ = @import("plugin/records.zig");
}

const testing = std.testing;

test "the handshake advertises every analyzer and record type" {
    var stub = lc.testing.Stub.init(testing.allocator, null, missing);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &plugin);
    defer table.destroy(table.instance);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const hello = try lc.testing.describe(alloc, &table);
    try testing.expectEqual(@as(u64, 2), hello.getUint("protocol").?);
    try testing.expectEqualStrings(PLUGIN_ID, hello.getString("plugin").?);

    const advertised = hello.get("analyzers").?.array;
    try testing.expectEqual(@as(usize, 4), advertised.len);

    // profile.fact is registered for every plugin; ours follow it.
    const schemas = hello.get("records").?.array;
    try testing.expectEqual(records.all.len + 1, schemas.len);
    try testing.expectEqualStrings("profile.fact", schemas[0].getString("type").?);
    try testing.expect(std.mem.startsWith(u8, hello.getString("schema_hash").?, "fnv1a64:"));
}

fn missing(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    method: []const u8,
    _: lc.wire.Value,
) lc.testing.Reply {
    return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
}

// ---------------------------------------------------------------------------
// Stub-host end-to-end tests: one per analyzer, over small synthetic inputs.

/// One run input of a test: id, display name and byte length.
const InputFile = struct { id: []const u8, name: []const u8, size: usize };

/// In-memory files the mock host answers `file.read` from, keyed by the
/// `file_id` the run inputs declare.
const MockFiles = struct {
    files: []const File,

    const File = struct {
        id: []const u8,
        bytes: []const u8,
    };

    fn handle(context: ?*anyopaque, alloc: std.mem.Allocator, method: []const u8, request: lc.wire.Value) lc.testing.Reply {
        const files: *const MockFiles = @ptrCast(@alignCast(context.?));
        if (!std.mem.eql(u8, method, "file.read")) {
            return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
        }
        const file_id = request.get("file_id") orelse
            return .{ .fault = .{ .code = "INVALID", .message = "no file_id" } };
        const zero: lc.wire.Value = .{ .uint = 0 };
        const offset: u64 = switch (request.get("offset") orelse zero) {
            .uint => |value| value,
            .int => |value| @intCast(value),
            else => 0,
        };
        const length: u64 = switch (request.get("length") orelse zero) {
            .uint => |value| value,
            .int => |value| @intCast(value),
            else => 0,
        };
        for (files.files) |file| {
            if (!std.mem.eql(u8, file.id, file_id.string)) continue;
            const start: usize = @intCast(@min(offset, file.bytes.len));
            const end: usize = @intCast(@min(offset + length, file.bytes.len));
            const chunk = file.bytes[start..end];
            const bytes = alloc.dupe(u8, chunk) catch
                return .{ .fault = .{ .code = "NOMEM", .message = "oom" } };
            return .{ .value = .{ .bytes = bytes } };
        }
        return .{ .fault = .{ .code = "NOT_FOUND", .message = file_id.string } };
    }
};

/// A run.start whose inputs are the given files (id, name, bytes).
fn startParams(
    alloc: std.mem.Allocator,
    analyzer: []const u8,
    files: []const InputFile,
) !lc.wire.Value {
    var inputs: std.ArrayList(lc.wire.Value) = .empty;
    for (files) |file| {
        try inputs.append(alloc, try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("file_id", lc.wire.str(file.id)),
            lc.wire.entry("name", lc.wire.str(file.name)),
            lc.wire.entry("size", lc.wire.uint(file.size)),
            lc.wire.entry("root_path", lc.wire.str(file.name)),
        }));
    }
    return lc.wire.mapOf(alloc, &.{
        lc.wire.entry("run_id", lc.wire.str("run-1")),
        lc.wire.entry("analyzer", lc.wire.str(analyzer)),
        lc.wire.entry("target", try lc.wire.mapOf(alloc, &.{
            lc.wire.entry("kind", lc.wire.str("evidence")),
            lc.wire.entry("view", try lc.wire.mapOf(alloc, &.{
                lc.wire.entry("view_id", lc.wire.str("view-1")),
                lc.wire.entry("label", lc.wire.str("evidence")),
            })),
        })),
        lc.wire.entry("inputs", .{ .array = inputs.items }),
        lc.wire.entry("locale", lc.wire.str("zh-CN")),
    });
}

/// One emitted record: the type id and its values, in schema order.
const Emitted = struct {
    record_type: []const u8,
    values: []const lc.wire.Value,
};

/// The type and values of one emitted record map.
fn emitted(record: lc.wire.Value) Emitted {
    var result = Emitted{ .record_type = "", .values = &.{} };
    if (record.get("type")) |kind| {
        if (kind == .string) result.record_type = kind.string;
    }
    if (record.get("values")) |values| {
        if (values == .array) result.values = values.array;
    }
    return result;
}

/// Runs one analyzer over the given files and returns every emitted record,
/// fetched through the stub's emit batches.
fn runAnalyzer(
    alloc: std.mem.Allocator,
    mock: *const MockFiles,
    analyzer: []const u8,
    files: []const InputFile,
) !struct { stub: *lc.testing.Stub, records: []lc.wire.Value, summary: []const u8 } {
    const stub_ptr = try alloc.create(lc.testing.Stub);
    stub_ptr.* = lc.testing.Stub.init(testing.allocator, @constCast(mock), MockFiles.handle);
    errdefer stub_ptr.deinit();
    var api = stub_ptr.api();
    var table = try lc.testing.entry(&api, &plugin);
    defer table.destroy(table.instance);

    const reply = try lc.testing.callOk(alloc, &table, 2, "run.start", try startParams(alloc, analyzer, files));
    const summary = reply.?.getString("summary") orelse "";
    return .{ .stub = stub_ptr, .records = try stub_ptr.emittedRecords(alloc), .summary = summary };
}

test "baseinfo emits device facts, boots and the user" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const boot_text =
        "isPrevious: true\n" ++
        "Build: Xiaomi/venus/venus:13/TKQ1.220829.002/V14.0.11.0.TKBCNXM:user/release-keys\n" ++
        "Hardware: venus\n" ++
        "Kernel: Linux version 5.4.233-qgki\n";
    const last_header = "Build: Xiaomi/venus/venus:13/TKQ1.220829.002/V14.0.11.0.TKBCNXM:user/release-keys\nKernel: Linux version 5.4.233-qgki\n";

    var writer = @import("core/abx_test_helper.zig").Writer{};
    defer writer.deinit();
    try writer.out.appendSlice(testing.allocator, &@import("core/abx_test_helper.zig").magic);
    try writer.document();
    try writer.startTag("packages");
    try writer.startTag("version");
    try writer.attrInt("sdkVersion", 33);
    try writer.endTag("version");
    try writer.endTag("packages");

    var user_writer = @import("core/abx_test_helper.zig").Writer{};
    defer user_writer.deinit();
    try user_writer.out.appendSlice(testing.allocator, &@import("core/abx_test_helper.zig").magic);
    try user_writer.document();
    try user_writer.startTag("user");
    try user_writer.attrInt("id", 0);
    try user_writer.attrInt("serialNumber", 0);
    try user_writer.attrInt("flags", 3091);
    try user_writer.attrString("type", "android.os.usertype.full.SYSTEM");
    try user_writer.attrLong("created", 1784039099070);
    try user_writer.endTag("user");

    const mock = MockFiles{ .files = &.{
        .{ .id = "boot", .bytes = boot_text },
        .{ .id = "header", .bytes = last_header },
        .{ .id = "packages", .bytes = writer.out.items },
        .{ .id = "user", .bytes = user_writer.out.items },
    } };
    const result = try runAnalyzer(alloc, &mock, "baseinfo", &.{
        .{ .id = "boot", .name = "SYSTEM_BOOT@1784265396953.txt", .size = boot_text.len },
        .{ .id = "header", .name = "last-header.txt", .size = last_header.len },
        .{ .id = "packages", .name = "packages.xml", .size = writer.out.items.len },
        .{ .id = "user", .name = "0.xml", .size = user_writer.out.items.len },
    });
    defer result.stub.deinit();

    var device_records: usize = 0;
    var boot_records: usize = 0;
    var user_records: usize = 0;
    var build_value: []const u8 = "";
    for (result.records) |wire_record| {
        const record = emitted(wire_record);
        if (std.mem.eql(u8, record.record_type, "androidsysteminfo.device")) {
            device_records += 1;
            if (std.mem.eql(u8, record.values[0].string, "Build")) build_value = record.values[1].string;
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.boot")) {
            boot_records += 1;
            try testing.expect(std.mem.indexOf(u8, record.values[0].string, "2026-07-17") != null);
            try testing.expectEqual(true, record.values[3].boolean);
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.user")) {
            user_records += 1;
            try testing.expectEqual(@as(u64, 0), record.values[0].uint);
        }
    }
    try testing.expectEqual(@as(usize, 4), device_records); // Build/Hardware/Kernel/sdkVersion
    try testing.expectEqual(@as(usize, 1), boot_records);
    try testing.expectEqual(@as(usize, 1), user_records);
    try testing.expectEqualStrings("Xiaomi/venus/venus:13/TKQ1.220829.002/V14.0.11.0.TKBCNXM:user/release-keys", build_value);
}

test "syslog parses logcat lines, dropbox entries and anr traces" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const bootlog =
        "Fri Jul 17 13:16:22 CST 2026\n" ++
        "--------- beginning of main\n" ++
        "07-17 13:16:20.531  1034  1034 I auditd  : first line\n" ++
        "    continuation of the first\n" ++
        "07-17 13:16:20.539  1071  1071 W libc    : Access denied finding property\n";
    const wtf =
        "Process: system_server\nSubject: SystemServiceRegistry\nDropped-Count: 0\n\nandroid.util.Log$TerribleFailure: x\n";
    const anr =
        "ProcessName : system_server\n\n----- pid 2178 at 1975-02-26 02:43:51.375379785+0800 -----\nABI: 'arm64'\n";

    const mock = MockFiles{ .files = &.{
        .{ .id = "bootlog", .bytes = bootlog },
        .{ .id = "wtf", .bytes = wtf },
        .{ .id = "anr", .bytes = anr },
    } };
    const result = try runAnalyzer(alloc, &mock, "syslog", &.{
        .{ .id = "bootlog", .name = "bootlog.txt", .size = bootlog.len },
        .{ .id = "wtf", .name = "system_server_wtf@1784230451340.txt", .size = wtf.len },
        .{ .id = "anr", .name = "anr_1975-02-26-02-43-51-372", .size = anr.len },
    });
    defer result.stub.deinit();

    var log_records: usize = 0;
    var entry_records: usize = 0;
    for (result.records) |wire_record| {
        const record = emitted(wire_record);
        if (std.mem.eql(u8, record.record_type, "androidsysteminfo.log")) {
            log_records += 1;
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.entry")) {
            entry_records += 1;
        }
    }
    try testing.expectEqual(@as(usize, 2), log_records);
    try testing.expectEqual(@as(usize, 2), entry_records);

    // The first log record carries the +08:00 time and the merged message.
    for (result.records) |wire_record| {
        const record = emitted(wire_record);
        if (std.mem.eql(u8, record.record_type, "androidsysteminfo.log")) {
            try testing.expect(std.mem.indexOf(u8, record.values[1].string, "+08:00") != null);
            try testing.expect(std.mem.indexOf(u8, record.values[7].string, "continuation") != null);
            break;
        }
    }
}

test "applist emits packages and permissions" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    var writer = @import("core/abx_test_helper.zig").Writer{};
    defer writer.deinit();
    try writer.out.appendSlice(testing.allocator, &@import("core/abx_test_helper.zig").magic);
    try writer.document();
    try writer.startTag("packages");
    try writer.startTag("package");
    try writer.attrString("name", "com.example.app");
    try writer.attrInt("userId", 10117);
    try writer.attrInt("version", 20624);
    try writer.attrString("codePath", "/data/app/~~x/com.example.app-y");
    try writer.attrString("installer", "com.xiaomi.market");
    try writer.attrLong("ft", 1776094875288);
    try writer.startTag("perms");
    try writer.startTag("item");
    try writer.attrString("name", "android.permission.INTERNET");
    try writer.attrBool("granted", true);
    try writer.endTag("item");
    try writer.endTag("perms");
    try writer.endTag("package");
    try writer.endTag("packages");

    const list = "com.example.app 10117 0 /data/user/0/com.example.app platform:targetSdkVersion=33 none 0 20624 1 @system\n";

    const mock = MockFiles{ .files = &.{
        .{ .id = "packages", .bytes = writer.out.items },
        .{ .id = "list", .bytes = list },
    } };
    const result = try runAnalyzer(alloc, &mock, "applist", &.{
        .{ .id = "packages", .name = "packages.xml", .size = writer.out.items.len },
        .{ .id = "list", .name = "packages.list", .size = list.len },
    });
    defer result.stub.deinit();

    var app_records: usize = 0;
    var permission_records: usize = 0;
    for (result.records) |wire_record| {
        const record = emitted(wire_record);
        if (std.mem.eql(u8, record.record_type, "androidsysteminfo.app")) {
            app_records += 1;
            try testing.expectEqualStrings("com.example.app", record.values[0].string);
            try testing.expectEqualStrings("/data/user/0/com.example.app", record.values[4].string);
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.permission")) {
            permission_records += 1;
            try testing.expectEqual(true, record.values[2].boolean);
        }
    }
    try testing.expectEqual(@as(usize, 1), app_records);
    try testing.expectEqual(@as(usize, 1), permission_records);
}

test "netrecords parses wifi, bluetooth and adb inputs; sqlite warns without a host" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const config_store =
        \\<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
        \\<WifiConfigStoreData><NetworkList><Network><WifiConfiguration>
        \\<string name="ConfigKey">&quot;OnePlus 9&quot;WPA_PSK</string>
        \\<string name="SSID">&quot;OnePlus 9&quot;</string>
        \\<string name="PreSharedKey">&quot;777777777&quot;</string>
        \\<long name="LastConnectedTime" value="1784265393980" />
        \\</WifiConfiguration></Network></NetworkList></WifiConfigStoreData>
    ;
    const bt_config =
        \\[Adapter]
        \\Address = 9c:bc:f0:bd:6c:36
        \\Name = Mi 11
        \\ScanMode = 1
        \\
    ;
    const adb_keys_text = "QAAAAFFDVrBPGhvp88QUSN/ndK5ACd/D15aGw3WeA3DbPOSIC0F0gPn8sX4gZ5C+nTrC8MMHXS+rZbtv user@desktop\n";
    var temp_writer = @import("core/abx_test_helper.zig").Writer{};
    defer temp_writer.deinit();
    try temp_writer.out.appendSlice(testing.allocator, &@import("core/abx_test_helper.zig").magic);
    try temp_writer.document();
    try temp_writer.startTag("keyStore");
    try temp_writer.startTag("wifiAP");
    try temp_writer.attrString("bssid", "82:46:b4:f4:e7:96");
    try temp_writer.endTag("wifiAP");
    try temp_writer.endTag("keyStore");

    const mock = MockFiles{ .files = &.{
        .{ .id = "wifi", .bytes = config_store },
        .{ .id = "bt", .bytes = bt_config },
        .{ .id = "keys", .bytes = adb_keys_text },
        .{ .id = "temp", .bytes = temp_writer.out.items },
    } };
    const result = try runAnalyzer(alloc, &mock, "netrecords", &.{
        .{ .id = "wifi", .name = "WifiConfigStore.xml", .size = config_store.len },
        .{ .id = "bt", .name = "bt_config.conf", .size = bt_config.len },
        .{ .id = "keys", .name = "adb_keys", .size = adb_keys_text.len },
        .{ .id = "temp", .name = "adb_temp_keys.xml", .size = temp_writer.out.items.len },
    });
    defer result.stub.deinit();

    var wifi_records: usize = 0;
    var bt_records: usize = 0;
    var key_records: usize = 0;
    var bssid_records: usize = 0;
    var account_records: usize = 0;
    for (result.records) |wire_record| {
        const record = emitted(wire_record);
        if (std.mem.eql(u8, record.record_type, "androidsysteminfo.wifi")) {
            wifi_records += 1;
            try testing.expectEqualStrings("777777777", record.values[3].string);
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.bluetooth")) {
            bt_records += 1;
            try testing.expectEqualStrings("Mi 11", record.values[2].string);
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.adbkey")) {
            key_records += 1;
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.bssid")) {
            bssid_records += 1;
        } else if (std.mem.eql(u8, record.record_type, "androidsysteminfo.account")) {
            account_records += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), wifi_records);
    try testing.expectEqual(@as(usize, 1), bt_records);
    try testing.expectEqual(@as(usize, 1), key_records);
    try testing.expectEqual(@as(usize, 1), bssid_records);
    // The stub host cannot materialize: the sqlite inputs become warnings.
    try testing.expectEqual(@as(usize, 0), account_records);
    var materialize_warnings: usize = 0;
    for (result.stub.warnings.items) |warning| {
        if (std.mem.eql(u8, warning.code, "ANDROIDSYSTEMINFO_MATERIALIZE_FAILED")) materialize_warnings += 1;
    }
    try testing.expectEqual(@as(usize, 0), materialize_warnings); // no db inputs in this run
}

test "an empty input set produces a summary, not a failure" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const mock = MockFiles{ .files = &.{} };
    const result = try runAnalyzer(alloc, &mock, "applist", &.{});
    defer result.stub.deinit();
    try testing.expectEqual(@as(usize, 0), result.records.len);
    try testing.expect(result.summary.len > 0);
}
