//! From run inputs to records: classify the hive files, parse each once, then
//! run the selected collectors.
//!
//! Memory: hives are loaded one at a time through libc's allocator and a
//! per-hive arena holds every parsed value, so a run's peak stays around two
//! copies of its largest hive (the read buffer plus the parsed image).

const std = @import("std");

const lc = @import("lovelycarve");
const hive_mod = @import("../core/hive.zig");
const profile = @import("../core/profile.zig");
const records = @import("records.zig");

/// Largest hive read per run; plugin.toml caps the process at 2 GiB.
pub const MAX_HIVE_SIZE: u64 = 1024 * 1024 * 1024;

/// What one run should emit (the analyzer's items option).
pub const Items = struct {
    sysinfo: bool = true,
    netinfo: bool = true,
    userinfo: bool = true,
    browser: bool = true,

    /// An absent or empty multi-choice selects every group.
    pub fn fromOptions(options: lc.Options) Items {
        return .{
            .sysinfo = options.wants("items", "sysinfo"),
            .netinfo = options.wants("items", "netinfo"),
            .userinfo = options.wants("items", "userinfo"),
            .browser = options.wants("items", "browser"),
        };
    }
};

/// The display path of a file: its path inside the run's view, else the path
/// inside its volume, else its name.
pub fn displayPath(file: lc.FileRef) []const u8 {
    return file.viewPath() orelse file.rootPath() orelse file.name();
}

/// Reads the whole file into a libc-owned buffer (freed by the caller).
fn readWhole(file: lc.FileRef, alloc: std.mem.Allocator, cap: u64) ![]u8 {
    const size = file.size();
    if (size > cap) return error.TooLarge;
    const length = std.math.cast(usize, size) orelse return error.TooLarge;
    const buffer = try alloc.alloc(u8, length);
    errdefer alloc.free(buffer);

    var position: usize = 0;
    while (position < length) {
        const want: u64 = @min(length - position, lc.MAX_HOST_READ);
        const reply = try file.context().callHost(lc.protocol.method.file_read, try lc.value.map(
            file.context().arena,
            &.{
                lc.value.entry("file_id", lc.value.str(file.id())),
                lc.value.entry("offset", lc.value.uint(position)),
                lc.value.entry("length", lc.value.uint(want)),
            },
        ));
        const chunk = try lc.value.intoBytes(reply, lc.protocol.method.file_read);
        if (chunk.len == 0 or chunk.len > want) return error.ShortRead;
        @memcpy(buffer[position..][0..chunk.len], chunk);
        position += chunk.len;
    }
    return buffer;
}

/// Formats a warning message in the run's arena (warnings are stored with the
/// run, so they must outlive this call).
fn message(run: *const lc.Run, comptime format: []const u8, args: anytype) lc.Error![]const u8 {
    return std.fmt.allocPrint(run.context().arena, format, args);
}

/// The classified inputs of one run.
pub const Hives = struct {
    system: ?lc.FileRef = null,
    software: ?lc.FileRef = null,
    security: ?lc.FileRef = null,
    sam: ?lc.FileRef = null,
    /// Every other `*.DAT` file (NTUSER.DAT and friends), original order.
    user_hives: []const lc.FileRef = &.{},

    /// Classifies by file name, as ForensicsTool's folder walk does.
    pub fn classify(alloc: std.mem.Allocator, inputs: []const lc.FileRef) error{OutOfMemory}!Hives {
        var hives = Hives{};
        var user_hives: std.ArrayList(lc.FileRef) = .empty;
        for (inputs) |file| {
            const name = file.name();
            if (eqlName(name, "SYSTEM")) {
                hives.system = file;
            } else if (eqlName(name, "SOFTWARE")) {
                hives.software = file;
            } else if (eqlName(name, "SAM")) {
                hives.sam = file;
            } else if (eqlName(name, "SECURITY")) {
                hives.security = file;
            } else if (std.ascii.endsWithIgnoreCase(name, ".dat")) {
                try user_hives.append(alloc, file);
            }
        }
        hives.user_hives = try user_hives.toOwnedSlice(alloc);
        return hives;
    }
};

fn eqlName(name: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, expected);
}

/// One parsed hive: the `regf` image plus the per-hive arena that owns every
/// decoded value, so the whole hive is released in one go. The file handle is
/// kept so records can carry their system source.
const ParsedHive = struct {
    path: []const u8,
    file: lc.FileRef,
    hive: hive_mod.Hive,
    arena_state: *std.heap.ArenaAllocator,

    fn deinit(self: *ParsedHive) void {
        self.hive.deinit();
        const child = std.heap.c_allocator;
        self.arena_state.deinit();
        child.destroy(self.arena_state);
    }
};

/// One registry analysis run over the classified hive inputs.
pub fn analyzeRun(run: *const lc.Run, inputs: []const lc.FileRef, items: Items) lc.Error!void {
    const run_arena = run.context().arena;
    const scratch = std.heap.c_allocator;

    var parsed: std.ArrayList(ParsedHive) = .empty;
    defer {
        for (parsed.items) |*parsed_hive| parsed_hive.deinit();
        parsed.deinit(scratch);
    }

    const hives = try Hives.classify(run_arena, inputs);

    var found: usize = hives.user_hives.len;
    if (hives.system != null) found += 1;
    if (hives.software != null) found += 1;
    if (hives.sam != null) found += 1;
    if (hives.security != null) found += 1;
    if (found == 0) {
        run.setSummary("没有发现 Windows 注册表配置单元");
        run.log(.info, "the run resolved no registry hive inputs");
        return;
    }

    // Parse every classified hive once.
    var parsed_count: usize = 0;
    for ([_]?lc.FileRef{ hives.system, hives.software, hives.security, hives.sam }) |maybe_file| {
        const file = maybe_file orelse continue;
        try loadHive(run, &parsed, &parsed_count, file, scratch);
    }
    for (hives.user_hives) |file| {
        try loadHive(run, &parsed, &parsed_count, file, scratch);
    }
    if (parsed_count == 0) {
        run.setSummary("没有可解析的注册表配置单元");
        return;
    }

    // Resolve the parsed hives by role.
    var system_hive: ?*hive_mod.Hive = null;
    var software_hive: ?*hive_mod.Hive = null;
    var sam_hive: ?*hive_mod.Hive = null;
    var security_hive: ?*hive_mod.Hive = null;
    var system_file: ?lc.FileRef = null;
    var software_file: ?lc.FileRef = null;
    var sam_file: ?lc.FileRef = null;
    var user_list: std.ArrayList(*ParsedHive) = .empty;
    for (parsed.items) |*parsed_hive| {
        const name = std.fs.path.basename(parsed_hive.path);
        if (eqlName(name, "SYSTEM")) {
            system_hive = &parsed_hive.hive;
            system_file = parsed_hive.file;
        } else if (eqlName(name, "SOFTWARE")) {
            software_hive = &parsed_hive.hive;
            software_file = parsed_hive.file;
        } else if (eqlName(name, "SAM")) {
            sam_hive = &parsed_hive.hive;
            sam_file = parsed_hive.file;
        } else if (eqlName(name, "SECURITY")) {
            security_hive = &parsed_hive.hive;
        } else {
            try user_list.append(run_arena, parsed_hive);
        }
    }

    const before = run.emitted();

    if (items.sysinfo) {
        const section_before = run.emitted();
        try run.progress(0, 4, "系统信息");
        if (software_hive) |software| {
            const items_out = profile.collectSystemInfo(run_arena, system_hive, software) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            for (items_out) |item| {
                const from_system = std.mem.eql(u8, item.item, "计算机名称") or
                    std.mem.eql(u8, item.item, "系统时区") or
                    std.mem.eql(u8, item.item, "最后一次正常关机时间(本地时区)");
                var value: lc.wire.Value = .{ .string = item.value };
                if (item.timestamp) |seconds| {
                    const timestamp = lc.record.Timestamp.fromUnix(seconds);
                    value = .{ .string = timestamp.asStr() };
                }
                var emit = run.record(records.SYSTEM_TYPE, &.{
                    lc.wire.str(item.item),
                    value,
                });
                if (from_system) {
                    emit = emit.from(&system_file.?);
                } else {
                    emit = emit.from(&software_file.?);
                }
                try emit.emit();
            }
            run.log(.info, try message(run, "系统信息完成，{d} 条记录", .{run.emitted() - section_before}));
        } else {
            try run.warn("WINSYSTEMINFO_NO_SOFTWARE", "缺少 SOFTWARE 配置单元，跳过系统信息");
            run.log(.warn, "系统信息跳过：缺少 SOFTWARE 配置单元");
        }
    }

    if (items.netinfo) {
        const section_before = run.emitted();
        try run.progress(1, 4, "网卡信息");
        if (system_hive) |system| {
            const adapters = profile.collectNetwork(run_arena, system) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            const system_file_ref = &system_file.?;
            for (adapters) |adapter| {
                try run.record(records.NETWORK_TYPE, &.{
                    lc.wire.str(adapter.interface),
                    lc.wire.str(adapter.name),
                    lc.wire.str(adapter.ip),
                    lc.wire.str(adapter.netmask),
                    lc.wire.str(adapter.gateway),
                    lc.wire.str(adapter.mac_current),
                    lc.wire.str(adapter.mac_permanent),
                    lc.wire.str(adapter.dhcp_ip),
                    lc.wire.str(adapter.dhcp_gateway),
                    lc.wire.str(adapter.dhcp_server),
                    timestampValue(adapter.lease_obtained),
                    timestampValue(adapter.lease_expires),
                }).from(system_file_ref).emit();
            }
            run.log(.info, try message(run, "网卡信息完成，{d} 条记录", .{run.emitted() - section_before}));
        } else {
            try run.warn("WINSYSTEMINFO_NO_SYSTEM", "缺少 SYSTEM 配置单元，跳过网卡信息");
            run.log(.warn, "网卡信息跳过：缺少 SYSTEM 配置单元");
        }
    }

    if (items.userinfo) {
        const section_before = run.emitted();
        try run.progress(2, 4, "用户信息");
        if (sam_hive) |sam_hive_ref| {
            const report = profile.collectUsers(run_arena, system_hive, security_hive, sam_hive_ref) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            switch (report.hashes) {
                .available => {},
                .no_system_hive => try run.warn(
                    "WINSYSTEMINFO_NO_SYSTEM",
                    "缺少 SYSTEM 配置单元，无法解密用户密码哈希",
                ),
                .no_boot_key => try run.warn("WINSYSTEMINFO_NO_BOOTKEY", "未能从 SYSTEM 提取引导密钥，密码哈希未解密"),
                .boot_key_rejected => try run.warn("WINSYSTEMINFO_BOOTKEY_MISMATCH", "引导密钥校验未通过，密码哈希未解密"),
                .malformed_sam => try run.warn("WINSYSTEMINFO_SAM_MALFORMED", "SAM 配置单元结构异常，用户信息不完整"),
            }
            const sam_file_ref = &sam_file.?;
            for (report.users) |user| {
                try run.record(records.USER_TYPE, &.{
                    lc.wire.str(user.username),
                    lc.wire.str(user.sid),
                    lc.wire.str(user.nt_hash),
                    lc.wire.str(user.full_name),
                    lc.wire.str(user.comment),
                    timestampValue(user.last_login),
                    timestampValue(user.last_pwd_change),
                    timestampValue(user.last_failed_login),
                    .{ .int = user.logon_count },
                    .{ .int = user.invalid_logon_count },
                    .{ .uint = user.user_attribute },
                    lc.wire.str(user.rid),
                }).from(sam_file_ref).emit();
            }
            run.log(.info, try message(run, "用户信息完成，{d} 条记录", .{run.emitted() - section_before}));
        } else {
            try run.warn("WINSYSTEMINFO_NO_SAM", "缺少 SAM 配置单元，跳过用户信息");
            run.log(.warn, "用户信息跳过：缺少 SAM 配置单元");
        }
    }

    if (items.browser) {
        const section_before = run.emitted();
        try run.progress(3, 4, "默认浏览器");
        for (user_list.items) |parsed_hive| {
            const progid = profile.collectBrowser(run_arena, &parsed_hive.hive) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            } orelse continue;
            if (progid.len == 0) continue;
            try run.record(records.BROWSER_TYPE, &.{
                lc.wire.str(parsed_hive.path),
                lc.wire.str(progid),
            }).from(&parsed_hive.file).emit();
        }
        run.log(.info, try message(run, "默认浏览器完成，{d} 条记录", .{run.emitted() - section_before}));
    }

    try run.progress(4, 4, null);
    const emitted = run.emitted() - before;
    const summary = try std.fmt.allocPrint(
        run_arena,
        "解析 {d} 个注册表配置单元，产出 {d} 条记录",
        .{ parsed_count, emitted },
    );
    run.setSummary(summary);
    run.log(.info, summary);
}

/// Reads and parses one hive input; a bad file becomes a run warning, not a
/// failure of the run.
fn loadHive(
    run: *const lc.Run,
    parsed: *std.ArrayList(ParsedHive),
    parsed_count: *usize,
    file: lc.FileRef,
    scratch: std.mem.Allocator,
) lc.Error!void {
    const path = displayPath(file);
    if (file.size() == 0) {
        const detail = try message(run, "{s} 是空文件，已跳过", .{path});
        try run.warnFile(file, "HIVE_EMPTY", detail);
        run.log(.warn, detail);
        return;
    }
    if (file.size() > MAX_HIVE_SIZE) {
        const detail = try message(
            run,
            "{s} 为 {d} 字节，超过上限 {d}，已跳过",
            .{ path, file.size(), MAX_HIVE_SIZE },
        );
        try run.warnFile(file, "HIVE_TOO_LARGE", detail);
        run.log(.warn, detail);
        return;
    }
    const buffer = readWhole(file, scratch, MAX_HIVE_SIZE) catch |err| {
        const detail = try message(run, "读取 {s} 失败：{s}", .{ path, @errorName(err) });
        try run.warnFile(file, "HIVE_READ_FAILED", detail);
        run.log(.err, detail);
        return;
    };
    defer scratch.free(buffer);
    const arena = run.context().alloc.create(std.heap.ArenaAllocator) catch return error.OutOfMemory;
    errdefer run.context().alloc.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    const inner = hive_mod.Hive.open(arena.allocator(), buffer) catch |err| {
        arena.deinit();
        run.context().alloc.destroy(arena);
        const detail = try message(run, "解析 {s} 失败：{s}", .{ path, @errorName(err) });
        try run.warnFile(file, "HIVE_PARSE_FAILED", detail);
        run.log(.err, detail);
        return;
    };
    try parsed.append(scratch, .{
        .path = try run.context().arena.dupe(u8, path),
        .file = file,
        .hive = inner,
        .arena_state = arena,
    });
    parsed_count.* += 1;
    run.log(.info, try message(run, "已解析配置单元 {s}（{d} 字节）", .{ path, file.size() }));
}

/// A Unix timestamp value, or nil when the event never happened.
fn timestampValue(seconds: ?i64) lc.wire.Value {
    const value = seconds orelse return .nil;
    const timestamp = lc.record.Timestamp.fromUnix(value);
    return .{ .string = timestamp.asStr() };
}

const testing = std.testing;

fn fileRef(name: []const u8) lc.FileRef {
    var cancelled = std.atomic.Value(bool).init(false);
    const ctx = lc.host.Context{
        .host = undefined,
        .cancelled = &cancelled,
        .arena = testing.allocator,
        .alloc = testing.allocator,
    };
    return lc.FileRef.init(ctx, .{ .file_id = "file", .name = name, .size = 1 });
}

test "classify splits the ForensicsTool input roles" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const inputs = [_]lc.FileRef{
        fileRef("SYSTEM"),
        fileRef("SOFTWARE"),
        fileRef("SAM"),
        fileRef("NTUSER.DAT"),
        fileRef("usrclass.dat"),
        fileRef("pagefile.sys"),
    };
    const hives = try Hives.classify(arena_state.allocator(), &inputs);
    try testing.expect(hives.system != null);
    try testing.expect(hives.software != null);
    try testing.expect(hives.sam != null);
    try testing.expectEqual(@as(usize, 2), hives.user_hives.len);
}

test "items default to everything when the option is absent" {
    const items = Items.fromOptions(lc.Options.init(.nil));
    try testing.expect(items.sysinfo and items.netinfo and items.userinfo and items.browser);
}
