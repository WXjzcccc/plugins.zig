//! From run inputs to records, for each of the four analyzers.
//!
//! Every analyzer classifies its inputs by path, parses each file once and
//! emits records bound to their source file. A bad file becomes a run
//! warning (spec: bad files are warnings, not failures); only an
//! out-of-memory situation fails the run. The sqlite-backed inputs are
//! materialized by the host and opened read-only with zqlite.
//!
//! Memory: text files are read whole into libc-owned buffers (the largest
//! is bootlog.txt at ~13 MiB on the reference device) and freed per file;
//! parsed values live in the run's arena.

const std = @import("std");

const lc = @import("lovelycarve");
const abx = @import("../core/abx.zig");
const adb = @import("../core/adb.zig");
const boot = @import("../core/boot.zig");
const bluetooth = @import("../core/bluetooth.zig");
const databases = @import("../core/databases.zig");
const dropbox = @import("../core/dropbox.zig");
const logcat = @import("../core/logcat.zig");
const packages = @import("../core/packages.zig");
const xml = @import("../core/xml.zig");
const records = @import("records.zig");
const wifi = @import("../core/wifi.zig");

/// Largest plain-text file read per run; bootlog.txt dominates.
pub const MAX_TEXT_SIZE: u64 = 64 * 1024 * 1024;
/// Largest ABX/XML file read per run.
pub const MAX_XML_SIZE: u64 = 32 * 1024 * 1024;
/// Largest SQLite database read per run.
pub const MAX_DB_SIZE: u64 = 64 * 1024 * 1024;
/// One log record's message cap (stack-trace continuations included).
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024;

/// The display path of a file: its view path, else its volume path, else
/// its name.
pub fn displayPath(file: lc.FileRef) []const u8 {
    return file.viewPath() orelse file.rootPath() orelse file.name();
}

/// A message in the run's arena (warnings and summaries outlive the call).
fn message(run: *const lc.Run, comptime format: []const u8, args: anytype) lc.Error![]const u8 {
    return std.fmt.allocPrint(run.context().arena, format, args);
}

/// The evidence's display zone: every timestamp this plugin emits is
/// rendered at UTC+8, the zone the reference device keeps its clocks in.
/// Wall-clock inputs carrying another offset are converted, never
/// relabelled.
const ZONE_MINUTES: i64 = 8 * 60;

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn daysFromCivil(year: i32, month: u32, day: u32) i64 {
    var y: i64 = year;
    if (month <= 2) y -= 1;
    const era = @divFloor(y, 400);
    const yoe: i64 = y - era * 400;
    const m: i64 = @intCast(month);
    const shift: i64 = if (m > 2) -3 else 9;
    const doy: i64 = @divFloor(153 * (m + shift) + 2, 5) + @as(i64, @intCast(day)) - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// Epoch seconds of a wall clock that reads `h:m:s` at `offset_minutes`.
fn epochAtOffset(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32, offset_minutes: i64) i64 {
    const days = daysFromCivil(year, month, day);
    return days * 86_400 + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + @as(i64, second) - offset_minutes * 60;
}

/// Epoch seconds (plus milliseconds) rendered at UTC+8, RFC 3339.
fn zoneText(arena: std.mem.Allocator, epoch_seconds: i64, millis: u32) lc.Error![]const u8 {
    const local = epoch_seconds + ZONE_MINUTES * 60;
    const days = @divFloor(local, 86_400);
    const second_of_day: u64 = @intCast(@mod(local, 86_400));
    const civil = lc.schema.civilFromDays(days);
    const year: u32 = @intCast(@max(civil.year, 0));
    if (millis == 0) {
        return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}+08:00", .{
            year,
            civil.month,
            civil.day,
            second_of_day / 3_600,
            second_of_day % 3_600 / 60,
            second_of_day % 60,
        });
    }
    return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}+08:00", .{
        year,
        civil.month,
        civil.day,
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60,
        millis,
    });
}

/// Epoch milliseconds as a UTC+8 timestamp value.
fn millisTimestamp(arena: std.mem.Allocator, milliseconds: i64) lc.Error!lc.wire.Value {
    const seconds = @divFloor(milliseconds, 1_000);
    const millis: u32 = @intCast(@mod(milliseconds, 1_000));
    return .{ .string = try zoneText(arena, seconds, millis) };
}

/// Nil when absent.
fn optionalMillis(arena: std.mem.Allocator, milliseconds: ?i64) lc.Error!lc.wire.Value {
    const value = milliseconds orelse return .nil;
    return millisTimestamp(arena, value);
}

/// A non-negative integer as a uint value (the wire encoder's int path
/// only carries small magnitudes); small negatives fall back to int.
fn uintValue(value: i64) lc.wire.Value {
    if (value < 0) return .{ .int = value };
    return .{ .uint = @intCast(value) };
}

/// An ANR-style wall-clock time as a UTC+8 timestamp: the text's own
/// offset (defaulting to +8 when it carries none) fixes the instant, which
/// is then rendered at +8.
fn localTimestamp(arena: std.mem.Allocator, parts: dropbox.TimeParts) lc.Error!lc.wire.Value {
    const offset: i64 = parts.offset_minutes orelse ZONE_MINUTES;
    const seconds = epochAtOffset(parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second, offset);
    return .{ .string = try zoneText(arena, seconds, 0) };
}

/// Decompresses one gzip stream (a DropBox `.gz` entry) into a
/// caller-owned buffer, capped at `cap` against decompression bombs.
pub fn gunzipBytes(alloc: std.mem.Allocator, compressed: []const u8, cap: usize) error{ OutOfMemory, GzipFailed, TooLarge }![]u8 {
    if (compressed.len < 2 or compressed[0] != 0x1f or compressed[1] != 0x8b) {
        return error.GzipFailed;
    }
    const window = alloc.alloc(u8, std.compress.flate.max_window_len) catch return error.OutOfMemory;
    defer alloc.free(window);

    var input = std.Io.Reader.fixed(compressed);
    var decompressor = std.compress.flate.Decompress.init(&input, .gzip, window);
    const out = decompressor.reader.allocRemaining(alloc, .limited(cap)) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.TooLarge,
        else => error.GzipFailed,
    };
    return out;
}

/// Reads one input whole; the bytes live in the run's arena (the host
/// decodes replies there), so they are never freed individually. Every
/// failure becomes a warning.
fn readBytes(run: *const lc.Run, file: lc.FileRef, cap: u64) lc.Error!?[]u8 {
    if (file.size() > cap) {
        const detail = try message(
            run,
            "{s} 为 {d} 字节，超过读取上限 {d}，已跳过",
            .{ displayPath(file), file.size(), cap },
        );
        try run.warnFile(file, "ANDROIDSYSTEMINFO_TOO_LARGE", detail);
        run.log(.warn, detail);
        return null;
    }
    return file.readAll(cap) catch |err| {
        const detail = try message(
            run,
            "读取 {s} 失败：{s}，已跳过",
            .{ displayPath(file), @errorName(err) },
        );
        try run.warnFile(file, "ANDROIDSYSTEMINFO_READ_FAILED", detail);
        run.log(.warn, detail);
        return null;
    };
}

// ---------------------------------------------------------------------------
// baseinfo 系统信息

/// What one baseinfo run should emit (the analyzer's items option).
pub const BaseinfoItems = struct {
    device: bool = true,
    boot: bool = true,
    users: bool = true,

    pub fn fromOptions(options: lc.Options) BaseinfoItems {
        return .{
            .device = options.wants("items", "device"),
            .boot = options.wants("items", "boot"),
            .users = options.wants("items", "users"),
        };
    }
};

/// One value per attribute name; the newest file that mentions an attribute
/// wins.
const DeviceFact = struct {
    field_value: []const u8,
    file: lc.FileRef,
};

const DeviceFacts = struct {
    map: std.StringHashMapUnmanaged(DeviceFact) = .empty,

    fn put(self: *DeviceFacts, arena: std.mem.Allocator, item: []const u8, value: []const u8, file: lc.FileRef) error{OutOfMemory}!void {
        try self.map.put(arena, try arena.dupe(u8, item), .{
            .field_value = try arena.dupe(u8, value),
            .file = file,
        });
    }
};

///  — Android names each user's record file after its id.
fn isUserIdXml(name: []const u8) bool {
    if (!std.mem.endsWith(u8, name, ".xml")) return false;
    const stem = name[0 .. name.len - 4];
    if (stem.len == 0) return false;
    for (stem) |char| {
        if (char < '0' or char > '9') return false;
    }
    return true;
}

/// The boot.Header fields as device attributes.
fn putHeaderFacts(facts: *DeviceFacts, arena: std.mem.Allocator, header: boot.Header, file: lc.FileRef) error{OutOfMemory}!void {
    if (header.build) |value| try facts.put(arena, "Build", value, file);
    if (header.hardware) |value| try facts.put(arena, "Hardware", value, file);
    if (header.revision) |value| try facts.put(arena, "Revision", value, file);
    if (header.bootloader) |value| try facts.put(arena, "Bootloader", value, file);
    if (header.radio) |value| try facts.put(arena, "Radio", value, file);
    if (header.kernel) |value| try facts.put(arena, "Kernel", value, file);
}

pub fn analyzeBaseinfo(run: *const lc.Run, inputs: []const lc.FileRef, items: BaseinfoItems) lc.Error!void {
    const arena = run.context().arena;
    var boot_files: std.ArrayList(lc.FileRef) = .empty;
    var last_header: ?lc.FileRef = null;
    var packages_file: ?lc.FileRef = null;
    var user_files: std.ArrayList(lc.FileRef) = .empty;

    for (inputs) |file| {
        const name = file.name();
        if (std.mem.startsWith(u8, name, "SYSTEM_BOOT@")) {
            try boot_files.append(arena, file);
        } else if (std.mem.eql(u8, name, "last-header.txt")) {
            last_header = file;
        } else if (std.mem.eql(u8, name, "packages.xml")) {
            packages_file = file;
        } else if (isUserIdXml(name)) {
            // data/system/users/<id>.xml — one full record per user.
            try user_files.append(arena, file);
        }
        // else: users/userlist.xml and other manifests are skeletons
        // without user facts; ignored on purpose.
    }

    const before = run.emitted();
    var header_count: usize = 0;
    var user_count: usize = 0;

    // --- 系统属性 -------------------------------------------------------------
    if (items.device) {
        const section_before = run.emitted();
        try run.progress(0, 3, "系统属性");
        var facts = DeviceFacts{};

        for (boot_files.items) |file| {
            const text = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse continue;
            const header = boot.parseHeader(arena, text) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            header_count += 1;
            run.log(.info, try message(run, "已解析开机信息 {s}", .{displayPath(file)}));
            try putHeaderFacts(&facts, arena, header, file);
        }

        if (last_header) |file| {
            if (try readBytes(run, file, MAX_TEXT_SIZE)) |text| {
                    const header = boot.parseHeader(arena, text) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                };
                header_count += 1;
                run.log(.info, try message(run, "已解析最近一次开机信息 {s}", .{displayPath(file)}));
                try putHeaderFacts(&facts, arena, header, file);
            }
        }

        if (packages_file) |file| {
            if (try readBytes(run, file, MAX_XML_SIZE)) |bytes| {
                    if (abx.parse(arena, bytes)) |parsed| {
                    for (parsed.children) |child| {
                        if (!std.mem.eql(u8, child.name, "version")) continue;
                        for (child.attributes) |attribute| {
                            const value = (child.attrText(arena, attribute.name) catch null) orelse continue;
                            try facts.put(arena, attribute.name, value, file);
                        }
                    }
                    run.log(.info, try message(run, "已解析 {s} 的框架版本属性", .{displayPath(file)}));
                } else |err| {
                    var hex_buffer: [256]u8 = undefined;
                    var hex_len: usize = 0;
                    for (bytes[0..@min(bytes.len, 60)]) |byte| {
                        hex_len += (std.fmt.bufPrint(hex_buffer[hex_len..], "{x} ", .{byte}) catch break).len;
                    }
                    run.log(.debug, try message(run, "ABX 字节: {s}（{d} 字节）", .{ hex_buffer[0..hex_len], bytes.len }));
                    const detail = try message(
                        run,
                        "{s} 不是可解析的 ABX 文档：{s}，跳过其框架版本属性",
                        .{ displayPath(file), @errorName(err) },
                    );
                    try run.warnFile(file, "ANDROIDSYSTEMINFO_ABX_PARSE_FAILED", detail);
                    run.log(.warn, detail);
                }
            }
        }

        var iterator = facts.map.iterator();
        while (iterator.next()) |entry| {
            const fact = entry.value_ptr.*;
            try run.record(records.DEVICE_TYPE, &.{
                lc.wire.str(entry.key_ptr.*),
                lc.wire.str(fact.field_value),
            }).from(&fact.file).emit();
        }
        run.log(.info, try message(run, "系统属性完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    // --- 开机记录 -------------------------------------------------------------
    if (items.boot) {
        const section_before = run.emitted();
        try run.progress(1, 3, "开机记录");
        for (boot_files.items) |file| {
            // The dropbox entry name carries the boot time: SYSTEM_BOOT@<ms>.txt
            const name = file.name();
            const start = std.mem.indexOfScalar(u8, name, '@') orelse continue;
            const end = std.mem.indexOfScalar(u8, name, '.') orelse name.len;
            const millis = std.fmt.parseInt(i64, name[start + 1 .. end], 10) catch continue;
            const text = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse continue;
            const header = boot.parseHeader(arena, text) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            try run.record(records.BOOT_TYPE, &.{
                try millisTimestamp(arena, millis),
                lc.wire.str(header.build orelse ""),
                lc.wire.str(header.kernel orelse ""),
                .{ .boolean = boot.isPrevious(text) },
            }).from(&file).emit();
        }
        run.log(.info, try message(run, "开机记录完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    // --- 设备用户 -------------------------------------------------------------
    if (items.users) {
        const section_before = run.emitted();
        try run.progress(2, 3, "设备用户");
        for (user_files.items) |file| {
            const bytes = (try readBytes(run, file, MAX_XML_SIZE)) orelse continue;
            const parsed = abx.parse(arena, bytes) catch |err| {
                const detail = try message(
                    run,
                    "{s} 不是可解析的 ABX 文档：{s}，跳过",
                    .{ displayPath(file), @errorName(err) },
                );
                try run.warnFile(file, "ANDROIDSYSTEMINFO_ABX_PARSE_FAILED", detail);
                run.log(.warn, detail);
                continue;
            };
            const user = if (std.mem.eql(u8, parsed.name, "user")) parsed else (parsed.child("user") orelse continue);
            const serial = user.attrLong("serialNumber") orelse user.attrLong("id") orelse continue;
            try run.record(records.USER_TYPE, &.{
                .{ .uint = @intCast(serial) },
                uintValue(user.attrLong("id") orelse serial),
                lc.wire.str((user.attrText(arena, "type") catch null) orelse ""),
                uintValue(user.attrLong("flags") orelse 0),
                try optionalMillis(arena, user.attrLong("created")),
                try optionalMillis(arena, user.attrLong("lastLoggedIn")),
            }).from(&file).emit();
            user_count += 1;
        }
        run.log(.info, try message(run, "设备用户完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    try run.progress(3, 3, null);
    const emitted = run.emitted() - before;
    const summary = try std.fmt.allocPrint(
        arena,
        "解析 {d} 个开机信息与 {d} 个用户文件，产出 {d} 条记录",
        .{ header_count, user_count, emitted },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

// ---------------------------------------------------------------------------
// syslog 系统日志

/// What one syslog run should emit. Empty multi selections mean "every
/// buffer / every level" (documented in the README).
pub const SyslogSettings = struct {
    buffers: []const []const u8 = &.{},
    levels: []const []const u8 = &.{},

    pub fn fromOptions(arena: std.mem.Allocator, options: lc.Options) error{OutOfMemory}!SyslogSettings {
        return .{
            .buffers = try options.list(arena, "buffers"),
            .levels = try options.list(arena, "levels"),
        };
    }

    fn wantsBuffer(self: SyslogSettings, buffer: []const u8) bool {
        if (self.buffers.len == 0) return true;
        for (self.buffers) |allowed| {
            if (std.mem.eql(u8, allowed, buffer)) return true;
        }
        return false;
    }

    fn wantsLevel(self: SyslogSettings, level: u8) bool {
        if (self.levels.len == 0) return true;
        for (self.levels) |allowed| {
            // The choice ids are lowercase; logcat levels are uppercase.
            if (allowed.len == 1 and std.ascii.toUpper(allowed[0]) == level) return true;
        }
        return false;
    }
};

pub fn analyzeSyslog(run: *const lc.Run, inputs: []const lc.FileRef, settings: SyslogSettings) lc.Error!void {
    const arena = run.context().arena;
    var bootlog: ?lc.FileRef = null;
    var dropbox_files: std.ArrayList(lc.FileRef) = .empty;
    var anr_files: std.ArrayList(lc.FileRef) = .empty;

    for (inputs) |file| {
        const name = file.name();
        if (std.mem.eql(u8, name, "bootlog.txt")) {
            bootlog = file;
        } else if (std.mem.startsWith(u8, name, "anr_")) {
            try anr_files.append(arena, file);
        } else if (std.mem.startsWith(u8, name, "SYSTEM_BOOT@")) {
            // The boot headers belong to the baseinfo analyzer.
            continue;
        } else {
            try dropbox_files.append(arena, file);
        }
    }

    // --- 运行日志（bootlog.txt，logcat 全量） ---------------------------------
    var log_count: u64 = 0;
    if (bootlog) |file| {
        try run.progress(0, 2, "运行日志");
        const section_before = run.emitted();
        log_count = try emitBootlog(run, file, settings);
        run.log(.info, try message(run, "运行日志完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    // --- 系统事件（dropbox 与 ANR） -------------------------------------------
    var entry_count: u64 = 0;
    {
        try run.progress(1, 2, "系统事件");
        const section_before = run.emitted();

        for (dropbox_files.items) |file| {
            const name = file.name();
            var text: []u8 = undefined;
            // The gzip path owns its buffer (libc); plain reads live in the
            // run's arena and are never freed here.
            var owns_text = false;
            if (std.mem.endsWith(u8, name, ".gz")) {
                const compressed = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse continue;
                text = gunzipBytes(run.context().alloc, compressed, MAX_TEXT_SIZE) catch |err| {
                    const detail = try message(
                        run,
                        "解压 {s} 失败：{s}，已跳过",
                        .{ displayPath(file), @errorName(err) },
                    );
                    try run.warnFile(file, "ANDROIDSYSTEMINFO_GZIP_FAILED", detail);
                    run.log(.warn, detail);
                    continue;
                };
                owns_text = true;
                run.log(.info, try message(run, "已解压 {s}（{d} → {d} 字节）", .{
                    displayPath(file), compressed.len, text.len,
                }));
            } else {
                text = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse continue;
            }
            defer if (owns_text) run.context().alloc.free(text);
            const header = dropbox.parseEntryHeader(arena, text) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            // The entry name carries the drop time: <name>@<ms>.txt
            var time_value: lc.wire.Value = .nil;
            if (std.mem.lastIndexOfScalar(u8, name, '@')) |at| {
                const relative_end = std.mem.indexOfScalar(u8, name[at..], '.') orelse name.len - at;
                if (std.fmt.parseInt(i64, name[at + 1 .. at + relative_end], 10)) |millis| {
                    time_value = try millisTimestamp(arena, millis);
                } else |_| {}
            }
            try run.record(records.ENTRY_TYPE, &.{
                lc.wire.str(try arena.dupe(u8, displayPath(file))),
                lc.wire.str("dropbox"),
                time_value,
                lc.wire.str(lc.text.decodeLossy(arena, header.process orelse "") catch return error.OutOfMemory),
                lc.wire.str(lc.text.decodeLossy(arena, header.subject orelse "") catch return error.OutOfMemory),
                lc.wire.str(lc.text.decodeLossy(arena, header.abi orelse "") catch return error.OutOfMemory),
            }).from(&file).emit();
            run.log(.info, try message(run, "已解析 dropbox 条目 {s}", .{displayPath(file)}));
        }

        for (anr_files.items) |file| {
            const text = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse continue;
            const header = dropbox.parseEntryHeader(arena, text) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            var time_value: lc.wire.Value = .nil;
            if (header.time_text) |time_text| {
                if (dropbox.parseTimeParts(time_text)) |parts| {
                    time_value = try localTimestamp(arena, parts);
                }
            }
            if (time_value == .nil) {
                // Fall back to the file name: anr_1975-02-26-02-43-51-372
                if (std.mem.indexOfScalar(u8, file.name(), '_')) |underscore| {
                    if (dropbox.parseTimeParts(file.name()[underscore + 1 ..])) |parts| {
                        time_value = try localTimestamp(arena, parts);
                    }
                }
            }
            try run.record(records.ENTRY_TYPE, &.{
                lc.wire.str(try arena.dupe(u8, displayPath(file))),
                lc.wire.str("anr"),
                time_value,
                lc.wire.str(lc.text.decodeLossy(arena, header.process orelse "") catch return error.OutOfMemory),
                lc.wire.str(lc.text.decodeLossy(arena, header.subject orelse "") catch return error.OutOfMemory),
                lc.wire.str(lc.text.decodeLossy(arena, header.abi orelse "") catch return error.OutOfMemory),
            }).from(&file).emit();
            run.log(.info, try message(run, "已解析 ANR 记录 {s}", .{displayPath(file)}));
        }

        entry_count = run.emitted() - section_before;
        run.log(.info, try message(run, "系统事件完成，{d} 条记录", .{entry_count}));
    }

    try run.progress(2, 2, null);
    const summary = try std.fmt.allocPrint(
        arena,
        "产出 {d} 条日志与 {d} 个系统事件",
        .{ log_count, entry_count },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

/// One header line plus its continuation lines, waiting to be emitted.
const PendingLog = struct {
    entry: logcat.Entry,
    /// The banner active when the line was read: it supplies the year and
    /// the UTC offset logcat lines lack.
    banner: ?logcat.Banner,
    offset: u64,
    end: u64,
    message: std.ArrayList(u8) = .empty,
};

/// Streams bootlog.txt line by line and emits one LOG record per logcat
/// header line; continuation lines extend the previous record's message.
/// Returns the number of records emitted.
fn emitBootlog(run: *const lc.Run, file: lc.FileRef, settings: SyslogSettings) lc.Error!u64 {
    const arena = run.context().arena;
    const path = displayPath(file);
    run.log(.info, try message(run, "开始解析 {s}（{d} 字节）", .{ path, file.size() }));

    const bytes = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse return 0;

    var buffer: []const u8 = "";
    var count: u64 = 0;
    var line_number: usize = 0;
    var line_start: usize = 0;
    var banner: ?logcat.Banner = null;
    var pending: ?PendingLog = null;

    while (line_start <= bytes.len) {
        line_number += 1;
        const line_end = std.mem.indexOfScalarPos(u8, bytes, line_start, '\n') orelse bytes.len;
        var raw_line = bytes[line_start..line_end];
        if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r') {
            raw_line = raw_line[0 .. raw_line.len - 1];
        }

        if (logcat.parseBufferMarker(raw_line)) |marker| {
            buffer = marker;
        } else if (logcat.parseBanner(raw_line)) |parsed_banner| {
            banner = parsed_banner;
            run.log(.info, try message(run, "日志横幅：{d} 年 {d} 月 {d} 日", .{
                parsed_banner.year, parsed_banner.month, parsed_banner.day,
            }));
        } else if (logcat.parseLine(line_number, buffer, raw_line)) |entry| {
            try flushLog(run, file, settings, &pending, &count);
            var pending_log = PendingLog{
                .entry = entry,
                .banner = banner,
                .offset = line_start,
                .end = line_end,
                .message = .empty,
            };
            pending_log.message.appendSlice(arena, entry.message) catch return error.OutOfMemory;
            pending = pending_log;
        } else if (pending != null and raw_line.len > 0) {
            // A continuation of the previous header line (stack traces).
            const pending_log = &pending.?;
            if (pending_log.message.items.len < MAX_MESSAGE_BYTES) {
                pending_log.message.append(arena, '\n') catch return error.OutOfMemory;
                pending_log.message.appendSlice(arena, raw_line) catch return error.OutOfMemory;
                pending_log.end = line_end;
            }
        }
        // else: blank or stray line outside any record — skipped.

        if (line_end == bytes.len) break;
        line_start = line_end + 1;
        if (line_number % 1000 == 0) {
            try run.checkCancelled();
        }
        if (line_number % 20000 == 0) {
            try run.progress(0, 2, try message(run, "运行日志：已读 {d} 行", .{line_number}));
        }
    }
    try flushLog(run, file, settings, &pending, &count);
    run.log(.info, try message(run, "{s} 共 {d} 行，产出 {d} 条日志", .{ path, line_number, count }));
    return count;
}

/// Emits the pending log record, honouring the buffer/level filters.
fn flushLog(
    run: *const lc.Run,
    file: lc.FileRef,
    settings: SyslogSettings,
    pending: *?PendingLog,
    count: *u64,
) lc.Error!void {
    const arena = run.context().arena;
    const pending_log = (pending.*) orelse return;
    pending.* = null;
    const entry = pending_log.entry;
    if (!settings.wantsBuffer(entry.buffer) or !settings.wantsLevel(entry.level)) return;
    if (pending_log.message.items.len == 0) return;

    // Log buffers can carry non-UTF-8 bytes (radio firmware logs, binary
    // tags); text fields must be valid UTF-8 on the wire, so lossy-decode
    // the free-text parts.
    const tag_text = lc.text.decodeLossy(arena, entry.tag) catch return error.OutOfMemory;
    const message_text = lc.text.decodeLossy(arena, pending_log.message.items) catch return error.OutOfMemory;

    // The record's time: the banner's year and zone fix the instant of the
    // line's wall clock (an unknown zone is treated as +8, the evidence's
    // zone); every value renders at UTC+8.
    var time_value: lc.wire.Value = .nil;
    if (pending_log.banner) |banner| {
        const offset: i64 = banner.offset_minutes orelse ZONE_MINUTES;
        const seconds = epochAtOffset(
            banner.year,
            entry.month,
            entry.day,
            entry.hour,
            entry.minute,
            entry.second,
            offset,
        );
        time_value = .{ .string = try zoneText(arena, seconds, entry.millis) };
    }

    try run.record(records.LOG_TYPE, &.{
        .{ .uint = entry.number },
        time_value,
        lc.wire.str(lc.text.decodeLossy(arena, entry.buffer) catch return error.OutOfMemory),
        lc.wire.str(levelText(entry.level)),
        uintValue(entry.pid),
        uintValue(entry.tid),
        lc.wire.str(tag_text),
        lc.wire.str(message_text),
    }).from(&file).at(pending_log.offset, pending_log.end - pending_log.offset).emit();
    count.* += 1;
}

fn levelText(level: u8) []const u8 {
    return switch (level) {
        'V' => "v",
        'D' => "d",
        'I' => "i",
        'W' => "w",
        'E' => "e",
        'F' => "f",
        else => "other",
    };
}

// ---------------------------------------------------------------------------
// applist 应用列表

/// What one applist run should emit.
pub const ApplistItems = struct {
    list: bool = true,
    permissions: bool = true,

    pub fn fromOptions(options: lc.Options) ApplistItems {
        return .{
            .list = options.wants("items", "list"),
            .permissions = options.wants("items", "permissions"),
        };
    }
};

/// One per-package row from packages.list, keyed by package name.
const ListIndex = struct {
    map: std.StringHashMapUnmanaged(packages.ListEntry) = .empty,

    fn add(self: *ListIndex, arena: std.mem.Allocator, line: []const u8) error{OutOfMemory}!void {
        const entry = packages.parseListLine(line) orelse return;
        const owned_name = try arena.dupe(u8, entry.package);
        var owned = entry;
        owned.package = owned_name;
        if (owned.data_dir) |value| owned.data_dir = try arena.dupe(u8, value);
        if (owned.seinfo) |value| owned.seinfo = try arena.dupe(u8, value);
        try self.map.put(arena, owned_name, owned);
    }
};

pub fn analyzeApplist(run: *const lc.Run, inputs: []const lc.FileRef, items: ApplistItems) lc.Error!void {
    const arena = run.context().arena;
    var packages_file: ?lc.FileRef = null;
    var list_file: ?lc.FileRef = null;
    var runtime_permissions: std.ArrayList(lc.FileRef) = .empty;

    for (inputs) |file| {
        const name = file.name();
        if (std.mem.eql(u8, name, "packages.xml")) {
            packages_file = file;
        } else if (std.mem.eql(u8, name, "packages.list")) {
            list_file = file;
        } else if (std.mem.eql(u8, name, "runtime-permissions.xml")) {
            try runtime_permissions.append(arena, file);
        }
    }

    if (packages_file == null and list_file == null) {
        run.setSummary("没有发现 packages.xml 或 packages.list");
        run.log(.info, "the run resolved no package inputs");
        return;
    }

    // packages.list first: it enriches (and, as the fallback, stands in for)
    // the XML records.
    var list_index = ListIndex{};
    if (list_file) |file| {
        const text = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse "";
        if (text.len > 0) {
            var lines = std.mem.splitScalar(u8, text, '\n');
            while (lines.next()) |line| {
                try list_index.add(arena, line);
            }
            run.log(.info, try message(run, "已解析 {s}（{d} 个包）", .{
                displayPath(file), list_index.map.count(),
            }));
        }
    }

    var app_count: usize = 0;
    var permission_count: usize = 0;
    var xml_ok = false;

    if (packages_file) |file| {
        if (try readBytes(run, file, MAX_XML_SIZE)) |bytes| {
            var parsed_packages: std.ArrayList(packages.Package) = .empty;
            var parsed_permissions: std.ArrayList(packages.Permission) = .empty;
            var parsed_facts: std.ArrayList(packages.RootFact) = .empty;
            if (packages.parseXml(arena, bytes, &parsed_packages, &parsed_permissions, &parsed_facts)) |_| {
                xml_ok = true;
                if (items.list) {
                    const section_before = run.emitted();
                    try run.progress(0, 2, "应用列表");
                    for (parsed_packages.items) |package| {
                        const from_list = list_index.map.get(package.package);
                        try run.record(records.APP_TYPE, &.{
                            lc.wire.str(package.package),
                            uintValue(package.uid orelse (if (from_list) |entry| entry.uid orelse 0 else 0)),
                            uintValue(package.version_code orelse (if (from_list) |entry| entry.version_code orelse 0 else 0)),
                            lc.wire.str(package.code_path orelse ""),
                            lc.wire.str(package.data_dir orelse (if (from_list) |entry| entry.data_dir orelse "" else "")),
                            lc.wire.str(package.seinfo orelse (if (from_list) |entry| entry.seinfo orelse "" else "")),
                            lc.wire.str(package.installer orelse ""),
                            lc.wire.str(package.install_initiator orelse ""),
                            lc.wire.str(package.primary_abi orelse ""),
                            lc.wire.str(package.shared_user orelse ""),
                            .{ .boolean = package.system },
                            .{ .boolean = package.privileged },
                            .{ .boolean = package.debuggable },
                            .{ .boolean = package.orphaned },
                            try optionalMillis(arena, package.first_install_ms),
                            try optionalMillis(arena, package.last_update_ms),
                        }).from(&file).emit();
                        app_count += 1;
                    }
                    run.log(.info, try message(run, "应用列表完成，{d} 条记录", .{run.emitted() - section_before}));
                }
                if (items.permissions) {
                    const section_before = run.emitted();
                    try run.progress(1, 2, "授权权限");
                    for (parsed_permissions.items) |permission| {
                        try run.record(records.PERMISSION_TYPE, &.{
                            lc.wire.str(permission.package),
                            lc.wire.str(permission.name),
                            .{ .boolean = permission.granted },
                        }).from(&file).emit();
                        permission_count += 1;
                    }
                    run.log(.info, try message(run, "packages.xml 授权权限完成，{d} 条记录", .{run.emitted() - section_before}));
                }
                // Android 12+ keeps the runtime grants in a plain-XML file
                // of its own; that is the authoritative source on this
                // Android version (packages.xml carries no <perms> there).
                for (runtime_permissions.items) |perm_file| {
                    const section_before = run.emitted();
                    const perm_bytes = (try readBytes(run, perm_file, MAX_XML_SIZE)) orelse continue;
                    if (perm_bytes.len == 0) continue;
                    if (xml.parse(arena, perm_bytes)) |root| {
                        for (root.children) |package_node| {
                            if (!std.mem.eql(u8, package_node.name, "package")) continue;
                            const package_name = package_node.attr("name") orelse continue;
                            for (package_node.children) |permission_node| {
                                if (!std.mem.eql(u8, permission_node.name, "permission")) continue;
                                const permission_name = permission_node.attr("name") orelse continue;
                                const granted = std.mem.eql(u8, permission_node.attr("granted") orelse "false", "true");
                                try run.record(records.PERMISSION_TYPE, &.{
                                    lc.wire.str(package_name),
                                    lc.wire.str(permission_name),
                                    .{ .boolean = granted },
                                }).from(&perm_file).emit();
                                permission_count += 1;
                            }
                        }
                        run.log(.info, try message(run, "已解析 {s}（{d} 条授权）", .{
                            displayPath(perm_file), run.emitted() - section_before,
                        }));
                    } else |err| {
                        try warnXml(run, perm_file, err);
                    }
                }
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    try run.warnFile(file, "ANDROIDSYSTEMINFO_ABX_PARSE_FAILED", try message(
                        run,
                        "{s} 不是可解析的 ABX 文档：{s}",
                        .{ displayPath(file), @errorName(err) },
                    ));
                    run.log(.warn, try message(run, "{s} 解析失败（{s}）", .{ displayPath(file), @errorName(err) }));
                },
            }
        }
    }

    // Fallback: packages.list only, when the XML is missing or unreadable.
    if (!xml_ok and items.list) {
        const section_before = run.emitted();
        try run.progress(0, 2, "应用列表");
        const list_file_ref = list_file orelse return;
        var iterator = list_index.map.iterator();
        while (iterator.next()) |entry| {
            const from_list = entry.value_ptr.*;
            try run.record(records.APP_TYPE, &.{
                lc.wire.str(from_list.package),
                uintValue(from_list.uid orelse 0),
                uintValue(from_list.version_code orelse 0),
                lc.wire.str(""),
                lc.wire.str(from_list.data_dir orelse ""),
                lc.wire.str(from_list.seinfo orelse ""),
                lc.wire.str(""),
                lc.wire.str(""),
                lc.wire.str(""),
                lc.wire.str(""),
                .{ .boolean = false },
                .{ .boolean = false },
                .{ .boolean = false },
                .{ .boolean = false },
                .nil,
                .nil,
            }).from(&list_file_ref).emit();
            app_count += 1;
        }
        run.log(.info, try message(run, "应用列表（packages.list 兜底）完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    try run.progress(2, 2, null);
    const summary = try std.fmt.allocPrint(
        arena,
        "产出 {d} 个应用与 {d} 条授权权限记录",
        .{ app_count, permission_count },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

// ---------------------------------------------------------------------------
// netrecords 网络与其他记录

/// What one netrecords run should emit.
pub const NetItems = struct {
    wifi: bool = true,
    bluetooth: bool = true,
    adb: bool = true,
    accounts: bool = true,
    gnss: bool = true,

    pub fn fromOptions(options: lc.Options) NetItems {
        return .{
            .wifi = options.wants("items", "wifi"),
            .bluetooth = options.wants("items", "bluetooth"),
            .adb = options.wants("items", "adb"),
            .accounts = options.wants("items", "accounts"),
            .gnss = options.wants("items", "gnss"),
        };
    }
};

pub fn analyzeNetrecords(run: *const lc.Run, inputs: []const lc.FileRef, items: NetItems) lc.Error!void {
    const arena = run.context().arena;
    var wifi_file: ?lc.FileRef = null;
    var softap_file: ?lc.FileRef = null;
    var bt_conf: ?lc.FileRef = null;
    var bt_bak: ?lc.FileRef = null;
    var adb_keys: std.ArrayList(lc.FileRef) = .empty;
    var temp_keys: ?lc.FileRef = null;
    var account_dbs: std.ArrayList(lc.FileRef) = .empty;
    var gnss_db: ?lc.FileRef = null;

    for (inputs) |file| {
        const name = file.name();
        if (std.mem.eql(u8, name, "WifiConfigStore.xml")) {
            wifi_file = file;
        } else if (std.mem.eql(u8, name, "WifiConfigStoreSoftAp.xml")) {
            softap_file = file;
        } else if (std.mem.eql(u8, name, "bt_config.conf")) {
            bt_conf = file;
        } else if (std.mem.eql(u8, name, "bt_config.bak")) {
            bt_bak = file;
        } else if (std.mem.eql(u8, name, "adb_keys")) {
            try adb_keys.append(arena, file);
        } else if (std.mem.eql(u8, name, "adb_temp_keys.xml")) {
            temp_keys = file;
        } else if (std.mem.endsWith(u8, name, "accounts_ce.db")) {
            try account_dbs.append(arena, file);
        } else if (std.mem.eql(u8, name, "gnssCollectData.db")) {
            gnss_db = file;
        }
    }

    var wifi_count: usize = 0;
    var bt_count: usize = 0;
    var key_count: usize = 0;
    var account_count: usize = 0;
    var gnss_count: usize = 0;

    // --- Wi-Fi ------------------------------------------------------------------
    if (items.wifi) {
        try run.progress(0, 4, "Wi-Fi");
        const section_before = run.emitted();
        if (wifi_file) |file| {
            const bytes = (try readBytes(run, file, MAX_XML_SIZE)) orelse "";
            if (bytes.len > 0) {
                    var networks: std.ArrayList(wifi.Network) = .empty;
                if (wifi.parseConfigStore(arena, bytes, &networks)) |_| {
                    for (networks.items) |network| {
                        try run.record(records.WIFI_TYPE, &.{
                            lc.wire.str(network.config_key),
                            lc.wire.str(network.ssid),
                            lc.wire.str(network.security),
                            lc.wire.str(network.preshared_key orelse ""),
                            .{ .boolean = network.hidden },
                            .{ .boolean = network.shared },
                            lc.wire.str(if (network.status) |status| wifi.statusName(status) else ""),
                            try optionalMillis(arena, network.last_connected_ms),
                            try optionalMillis(arena, network.last_disconnected_ms),
                            lc.wire.str(network.creator orelse ""),
                            lc.wire.str(network.gateway_mac orelse ""),
                        }).from(&file).emit();
                        wifi_count += 1;
                    }
                    run.log(.info, try message(run, "已解析 {s}（{d} 个网络）", .{ displayPath(file), networks.items.len }));
                } else |err| {
                    try warnXml(run, file, err);
                }
            }
        }
        if (softap_file) |file| {
            const bytes = (try readBytes(run, file, MAX_XML_SIZE)) orelse "";
            if (bytes.len > 0) {
                    if (wifi.parseSoftAp(arena, bytes)) |soft_ap| {
                    if (soft_ap) |ap| {
                        try run.record(records.SOFTAP_TYPE, &.{
                            lc.wire.str(ap.ssid),
                            lc.wire.str(ap.security),
                            lc.wire.str(ap.passphrase orelse ""),
                            .{ .boolean = ap.hidden },
                            .{ .boolean = ap.auto_shutdown },
                        }).from(&file).emit();
                        wifi_count += 1;
                    }
                    run.log(.info, try message(run, "已解析 {s}", .{displayPath(file)}));
                } else |err| {
                    try warnXml(run, file, err);
                }
            }
        }
        run.log(.info, try message(run, "Wi-Fi 完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    // --- 蓝牙 -------------------------------------------------------------------
    if (items.bluetooth) {
        try run.progress(1, 4, "蓝牙");
        const section_before = run.emitted();
        // The live config wins; the .bak only stands in when there is none.
        var devices: std.ArrayList(bluetooth.Device) = .empty;
        if (bt_conf) |file| {
            const bytes = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse "";
            if (bytes.len > 0) {
                    bluetooth.parse(arena, bytes, &devices) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                };
                run.log(.info, try message(run, "已解析 {s}（{d} 条蓝牙记录）", .{ displayPath(file), devices.items.len }));
            }
        }
        if (devices.items.len == 0) {
            if (bt_bak) |file| {
                const bytes = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse "";
                if (bytes.len > 0) {
                            bluetooth.parse(arena, bytes, &devices) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    run.log(.info, try message(run, "已解析备份 {s}（{d} 条蓝牙记录）", .{ displayPath(file), devices.items.len }));
                }
            }
        }
        for (devices.items) |device| {
            try run.record(records.BLUETOOTH_TYPE, &.{
                lc.wire.str(device.address),
                lc.wire.str(device.kind),
                lc.wire.str(device.name orelse ""),
                .{ .int = device.scan_mode orelse 0 },
                .{ .int = device.discovery_timeout orelse 0 },
                lc.wire.str(device.time_created orelse ""),
                lc.wire.str(device.irk orelse ""),
                lc.wire.str(device.ir orelse ""),
                lc.wire.str(device.dhk orelse ""),
                lc.wire.str(device.er orelse ""),
                lc.wire.str(device.link_key orelse ""),
            }).from(&fileOf(device, bt_conf, bt_bak)).emit();
            bt_count += 1;
        }
        run.log(.info, try message(run, "蓝牙完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    // --- ADB 授权 -----------------------------------------------------------------
    if (items.adb) {
        try run.progress(2, 4, "ADB 授权");
        const section_before = run.emitted();
        // The digest is the record's identity; one key may appear both as a
        // permanent grant (adb_keys) and a temporary one (temp store) — the
        // permanent record wins.
        var seen_keys = std.StringHashMapUnmanaged(void).empty;
        for (adb_keys.items) |file| {
            const text = (try readBytes(run, file, MAX_TEXT_SIZE)) orelse continue;
            var keys: std.ArrayList(adb.Key) = .empty;
            adb.parseKeys(arena, text, &keys) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Corrupt => continue,
            };
            for (keys.items) |key| {
                try seen_keys.put(arena, key.digest, {});
                try run.record(records.ADBKEY_TYPE, &.{
                    lc.wire.str(key.digest),
                    lc.wire.str(key.user_host orelse ""),
                    lc.wire.str(key.kind),
                    .nil,
                }).from(&file).emit();
                key_count += 1;
            }
            run.log(.info, try message(run, "已解析 {s}（{d} 个密钥）", .{ displayPath(file), keys.items.len }));
        }
        if (temp_keys) |file| {
            const bytes = (try readBytes(run, file, MAX_XML_SIZE)) orelse "";
            if (bytes.len > 0) {
                var keys: std.ArrayList(adb.Key) = .empty;
                var bssids: std.ArrayList(adb.Bssid) = .empty;
                if (adb.parseTempKeys(arena, bytes, &keys, &bssids)) |_| {
                    for (keys.items) |key| {
                        if (seen_keys.contains(key.digest)) {
                            run.log(.info, try message(run, "密钥 {s} 已有永久授权记录，跳过临时记录", .{key.digest[0..16]}));
                            continue;
                        }
                        try seen_keys.put(arena, key.digest, {});
                        try run.record(records.ADBKEY_TYPE, &.{
                            lc.wire.str(key.digest),
                            lc.wire.str(key.user_host orelse ""),
                            lc.wire.str(key.kind),
                            try adbTimestamp(arena, key.last_connection_raw),
                        }).from(&file).emit();
                        key_count += 1;
                    }
                    for (bssids.items) |bssid| {
                        try run.record(records.BSSID_TYPE, &.{
                            lc.wire.str(bssid.bssid),
                            lc.wire.str("adb_temp_keys"),
                        }).from(&file).emit();
                    }
                    run.log(.info, try message(run, "已解析 {s}（{d} 个临时密钥、{d} 个热点 MAC）", .{
                        displayPath(file), keys.items.len, bssids.items.len,
                    }));
                } else |err| {
                    try warnAbx(run, file, err);
                }
            }
        }
        run.log(.info, try message(run, "ADB 授权完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    // --- 系统账号与 GNSS（sqlite） -------------------------------------------------
    {
        try run.progress(3, 4, "系统账号与 GNSS");
        const section_before = run.emitted();
        if (items.accounts) {
            for (account_dbs.items) |file| {
                account_count += try emitAccounts(run, file);
            }
        }
        if (items.gnss) {
            if (gnss_db) |file| {
                gnss_count = try emitGnss(run, file);
            }
        }
        run.log(.info, try message(run, "系统账号与 GNSS 完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    try run.progress(4, 4, null);
    const summary = try std.fmt.allocPrint(
        arena,
        "产出 Wi-Fi {d} 条、蓝牙 {d} 条、ADB {d} 条、账号 {d} 条、GNSS {d} 条",
        .{ wifi_count, bt_count, key_count, account_count, gnss_count },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

/// The file a bluetooth device came from: the live conf when present, else
/// the backup.
fn fileOf(device: bluetooth.Device, conf: ?lc.FileRef, bak: ?lc.FileRef) lc.FileRef {
    _ = device;
    if (conf != null) return conf.?;
    if (bak != null) return bak.?;
    unreachable;
}

fn warnXml(run: *const lc.Run, file: lc.FileRef, err: anyerror) lc.Error!void {
    try run.warnFile(file, "ANDROIDSYSTEMINFO_XML_PARSE_FAILED", try message(
        run,
        "{s} 不是可解析的 XML 文档：{s}，跳过",
        .{ displayPath(file), @errorName(err) },
    ));
    run.log(.warn, try message(run, "{s} 解析失败（{s}），跳过", .{ displayPath(file), @errorName(err) }));
}

fn warnAbx(run: *const lc.Run, file: lc.FileRef, err: anyerror) lc.Error!void {
    try run.warnFile(file, "ANDROIDSYSTEMINFO_ABX_PARSE_FAILED", try message(
        run,
        "{s} 不是可解析的 ABX 文档：{s}，跳过",
        .{ displayPath(file), @errorName(err) },
    ));
    run.log(.warn, try message(run, "{s} 解析失败（{s}），跳过", .{ displayPath(file), @errorName(err) }));
}

/// The temp store's last-connection value as a timestamp: adbd has written
/// both seconds and milliseconds across versions; the magnitude decides.
fn adbTimestamp(arena: std.mem.Allocator, raw: ?[]const u8) lc.Error!lc.wire.Value {
    const text = raw orelse return .nil;
    const value = std.fmt.parseInt(i64, text, 10) catch return .nil;
    if (value <= 0) return .nil;
    if (value > 1_000_000_000_000) {
        return millisTimestamp(arena, value);
    }
    return .{ .string = try zoneText(arena, value, 0) };
}

/// Materializes one sqlite file and emits its accounts. Returns the record
/// count; a database the schema of which does not match becomes a warning.
fn emitAccounts(run: *const lc.Run, file: lc.FileRef) lc.Error!usize {
    const arena = run.context().arena;
    if (file.size() == 0) {
        try run.warnFile(file, "ANDROIDSYSTEMINFO_DB_EMPTY", try message(
            run,
            "{s} 是空文件，已跳过",
            .{displayPath(file)},
        ));
        return 0;
    }
    if (file.size() > MAX_DB_SIZE) {
        try run.warnFile(file, "ANDROIDSYSTEMINFO_TOO_LARGE", try message(
            run,
            "{s} 为 {d} 字节，超过读取上限，已跳过",
            .{ displayPath(file), file.size() },
        ));
        return 0;
    }

    var materialized = file.materialize() catch |err| {
        try run.warnFile(file, "ANDROIDSYSTEMINFO_MATERIALIZE_FAILED", try message(
            run,
            "落盘 {s} 失败：{s}，跳过该数据库",
            .{ displayPath(file), @errorName(err) },
        ));
        run.log(.warn, try message(run, "落盘 {s} 失败（{s}），跳过", .{ displayPath(file), @errorName(err) }));
        return 0;
    };
    defer materialized.release() catch {};
    run.log(.info, try message(run, "已落盘 {s}", .{displayPath(file)}));

    const path = std.fmt.allocPrintSentinel(arena, "{s}", .{materialized.path}, 0) catch return error.OutOfMemory;
    if (!databases.hasTable(path, "accounts")) {
        try run.warnFile(file, "ANDROIDSYSTEMINFO_DB_SCHEMA", try message(
            run,
            "{s} 没有 accounts 表，跳过",
            .{displayPath(file)},
        ));
        run.log(.warn, try message(run, "{s} 缺少 accounts 表，跳过", .{displayPath(file)}));
        return 0;
    }

    var accounts: std.ArrayList(databases.Account) = .empty;
    databases.readAccounts(arena, path, &accounts) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Db => {
            try run.warnFile(file, "ANDROIDSYSTEMINFO_DB_READ_FAILED", try message(
                run,
                "读取 {s} 的 accounts 表失败（损坏或加密），跳过",
                .{displayPath(file)},
            ));
            run.log(.warn, try message(run, "读取 {s} 失败，跳过", .{displayPath(file)}));
            return 0;
        },
    };
    var count: usize = 0;
    for (accounts.items) |account| {
        try run.record(records.ACCOUNT_TYPE, &.{
            lc.wire.str(account.name),
            lc.wire.str(account.type),
            lc.wire.str(account.password orelse ""),
        }).from(&file).emit();
        count += 1;
    }
    run.log(.info, try message(run, "{s} 产出 {d} 个系统账号", .{ displayPath(file), count }));
    return count;
}

/// Materializes one sqlite file and emits its GNSS sessions.
fn emitGnss(run: *const lc.Run, file: lc.FileRef) lc.Error!usize {
    const arena = run.context().arena;
    if (file.size() == 0) return 0;
    if (file.size() > MAX_DB_SIZE) {
        try run.warnFile(file, "ANDROIDSYSTEMINFO_TOO_LARGE", try message(
            run,
            "{s} 为 {d} 字节，超过读取上限，已跳过",
            .{ displayPath(file), file.size() },
        ));
        return 0;
    }

    var materialized = file.materialize() catch |err| {
        try run.warnFile(file, "ANDROIDSYSTEMINFO_MATERIALIZE_FAILED", try message(
            run,
            "落盘 {s} 失败：{s}，跳过该数据库",
            .{ displayPath(file), @errorName(err) },
        ));
        return 0;
    };
    defer materialized.release() catch {};
    run.log(.info, try message(run, "已落盘 {s}", .{displayPath(file)}));

    const path = std.fmt.allocPrintSentinel(arena, "{s}", .{materialized.path}, 0) catch return error.OutOfMemory;
    if (!databases.hasTable(path, "GnssCollectData")) {
        try run.warnFile(file, "ANDROIDSYSTEMINFO_DB_SCHEMA", try message(
            run,
            "{s} 没有 GnssCollectData 表，跳过",
            .{displayPath(file)},
        ));
        run.log(.warn, try message(run, "{s} 缺少 GnssCollectData 表，跳过", .{displayPath(file)}));
        return 0;
    }

    var sessions: std.ArrayList(databases.GnssSession) = .empty;
    databases.readGnss(arena, path, &sessions) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Db => {
            try run.warnFile(file, "ANDROIDSYSTEMINFO_DB_READ_FAILED", try message(
                run,
                "读取 {s} 的 GnssCollectData 表失败，跳过",
                .{displayPath(file)},
            ));
            return 0;
        },
    };
    var count: usize = 0;
    for (sessions.items) |session| {
        // startTime is an epoch value; the unit varies (ms on recent builds).
        var start_value: lc.wire.Value = .nil;
        var start_raw: lc.wire.Value = .nil;
        if (session.start_time) |raw| {
            start_raw = uintValue(raw);
            if (raw > 1_000_000_000_000) {
                start_value = try millisTimestamp(arena, raw);
            } else if (raw > 1_000_000_000) {
                start_value = .{ .string = try zoneText(arena, raw, 0) };
            }
        }
        try run.record(records.GNSS_TYPE, &.{
            uintValue(session.session_id),
            start_value,
            start_raw,
            uintValue(session.ttff orelse 0),
            uintValue(session.run_time orelse 0),
            uintValue(session.lose_times orelse 0),
            uintValue(session.sap_number orelse 0),
            uintValue(session.pdr_number orelse 0),
            uintValue(session.total_number orelse 0),
            .{ .float = session.l1_cn0 orelse 0 },
            .{ .float = session.l5_cn0 orelse 0 },
            .{ .float = session.b1_cn0 orelse 0 },
        }).from(&file).emit();
        count += 1;
    }
    run.log(.info, try message(run, "{s} 产出 {d} 条 GNSS 记录", .{ displayPath(file), count }));
    return count;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "daysFromCivil matches the Unix epoch" {
    try testing.expectEqual(@as(i64, 0), daysFromCivil(1970, 1, 1));
    try testing.expectEqual(@as(i64, -1), daysFromCivil(1969, 12, 31));
    try testing.expectEqual(@as(i64, 19_752), daysFromCivil(2024, 1, 30)); // python: date(2024,1,30)-date(1970,1,1)
}

test "zoneText renders epoch values at UTC+8" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 1784265393980 ms = 2026-07-17 05:16:33.980 UTC = 13:16:33.980 +08:00
    const value = try millisTimestamp(arena, 1784265393980);
    try testing.expectEqualStrings("2026-07-17T13:16:33.980+08:00", value.string);

    // Whole seconds carry no fraction.
    const whole = try zoneText(arena, 0, 0);
    try testing.expectEqualStrings("1970-01-01T08:00:00+08:00", whole);
}

test "localTimestamp converts foreign offsets to +08:00" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A +0800 wall clock stays as-is.
    const local = try localTimestamp(arena, .{
        .year = 1975, .month = 2, .day = 26, .hour = 2, .minute = 43, .second = 51,
        .offset_minutes = 480,
    });
    try testing.expectEqualStrings("1975-02-26T02:43:51+08:00", local.string);

    // A UTC wall clock shifts eight hours forward.
    const utc = try localTimestamp(arena, .{
        .year = 2026, .month = 1, .day = 1, .hour = 0, .minute = 0, .second = 0,
        .offset_minutes = 0,
    });
    try testing.expectEqualStrings("2026-01-01T08:00:00+08:00", utc.string);

    // No offset in the text: read as +8.
    const zoneless = try localTimestamp(arena, .{
        .year = 2026, .month = 7, .day = 17, .hour = 13, .minute = 16, .second = 22,
        .offset_minutes = null,
    });
    try testing.expectEqualStrings("2026-07-17T13:16:22+08:00", zoneless.string);
}

/// `gzip.compress(b"Process: recovery\nSubject: ...")` — 87 bytes → 98.
const gz_fixture = [_]u8{
    31, 139, 8,   0,   143, 135, 220, 106, 2,   255, 11,  40,  202, 79,  78,  45,
    46, 182, 82,  40,  74,  77,  206, 47,  75,  45,  170, 228, 10, 46,  77,  202,
    74, 77,  46,  177, 82,  8,   142, 12,  14,  113, 245, 141, 15, 114, 117, 246,
    15, 115, 13,  138, 140, 247, 241, 119, 231, 114, 41,  202, 47, 40,  72,  77,
    209, 117, 206, 47,  205, 3,   42,  49,  224, 226, 130, 233, 83, 200, 201, 79,
    87,  72,  202, 79,  1,   50,  50,  243, 82,  1,   251, 80,  254, 216, 87,  0,
    0,  0,
};

test "gunzipBytes round-trips a dropbox entry" {
    const out = try gunzipBytes(testing.allocator, &gz_fixture, MAX_MESSAGE_BYTES * 4);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.startsWith(u8, out, "Process: recovery\n"));
    try testing.expect(std.mem.indexOf(u8, out, "recovery log body line") != null);

    // Not gzip at all.
    try testing.expectError(error.GzipFailed, gunzipBytes(testing.allocator, "plain text", 1024));
}

test "user record files are named after the user id" {
    try testing.expect(isUserIdXml("0.xml"));
    try testing.expect(isUserIdXml("10.xml"));
    try testing.expect(!isUserIdXml("userlist.xml"));
    try testing.expect(!isUserIdXml("0.xml.fallback"));
    try testing.expect(!isUserIdXml("packages.xml"));
}
