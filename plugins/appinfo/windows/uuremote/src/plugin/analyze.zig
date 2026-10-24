//! From run inputs to records: classify every GameViewer input, parse each
//! once, then emit. Independent record families (account, telemetry, file
//! traces, upgrades, registry logins) emit as their file is parsed; the
//! families that need cross-file merging (devices, sessions, run logs) are
//! collected into maps and emitted at the end.
//!
//! Memory: file buffers go through libc's allocator and are freed right
//! after their per-file arena dies; every value that survives into a record
//! is duped into the run arena. The largest single read is capped at
//! `MAX_TEXT_FILE` (INI/JSON text) and `MAX_HIVE_SIZE` (NTUSER.DAT).

const std = @import("std");

const lc = @import("lovelycarve");
const ini = @import("ini_zig");

const core = @import("../core/uuremote.zig");
const registry = @import("../core/registry.zig");
const slogname = @import("../core/slogname.zig");
const records = @import("records.zig");

/// Largest INI/JSON text read per file; GameViewer text files are KBs.
pub const MAX_TEXT_FILE: u64 = 32 * 1024 * 1024;

/// The display path of a file: its path inside the run's view, else the path
/// inside its volume, else its name.
pub fn displayPath(file: lc.FileRef) []const u8 {
    return file.viewPath() orelse file.rootPath() orelse file.name();
}

/// Why one input could not be analyzed.
pub const Failure = struct {
    code: []const u8,
    message: []const u8,
};

/// One merged device row and the input that established it (the source the
/// record binds to; further sources only add flags).
const DeviceRow = struct {
    obs: core.DeviceObs,
    file: lc.FileRef,
};

/// One aggregated remote session (connection + streamer logs of the same
/// role/timestamp/pid merged).
const SessionAgg = struct {
    role: slogname.Role,
    start_ms: i64,
    pid: ?u32,
    size: u64,
    segments: u32,
    encrypted: bool,
    last_activity: ?[]const u8,
    file: lc.FileRef,
};

/// One aggregated component run log.
const RunLogAgg = struct {
    component: []const u8,
    start_ms: i64,
    pid: ?u32,
    size: u64,
    segments: u32,
    encrypted: bool,
    last_activity: ?[]const u8,
    file: lc.FileRef,
};

/// Everything one run accumulates before the merged emission.
const RunState = struct {
    arena: std.mem.Allocator,
    account: ?core.Account = null,
    account_file: ?lc.FileRef = null,
    client_uuid: ?[]const u8 = null,
    devices: std.StringHashMap(DeviceRow),
    sessions: std.StringHashMap(SessionAgg),
    run_logs: std.StringHashMap(RunLogAgg),

    fn init(arena: std.mem.Allocator) RunState {
        return .{
            .arena = arena,
            .devices = std.StringHashMap(DeviceRow).init(arena),
            .sessions = std.StringHashMap(SessionAgg).init(arena),
            .run_logs = std.StringHashMap(RunLogAgg).init(arena),
        };
    }

    fn mergeDevice(self: *RunState, obs: core.DeviceObs, file: lc.FileRef) !void {
        const entry = try self.devices.getOrPut(obs.id);
        if (!entry.found_existing) {
            entry.value_ptr.* = .{ .obs = obs, .file = file };
            return;
        }
        const merged = &entry.value_ptr.obs;
        if (obs.last_connect_ms != null) merged.last_connect_ms = obs.last_connect_ms;
        if (obs.assist_refreshed_ms != null) merged.assist_refreshed_ms = obs.assist_refreshed_ms;
        merged.privacy_seen = merged.privacy_seen or obs.privacy_seen;
        merged.server_config = merged.server_config or obs.server_config;
        merged.assist_configured = merged.assist_configured or obs.assist_configured;
        merged.transfer_cached = merged.transfer_cached or obs.transfer_cached;
    }
};

/// One analysis run over the classified inputs (either analyzer scope).
pub fn analyzeRun(run: *const lc.Run) lc.Error!void {
    const run_arena = run.context().arena;
    const inputs = run.inputsOf();
    var state = RunState.init(run_arena);

    var include_run_logs = true;
    if (run.optionValues().get("include_run_logs")) |value| {
        if (value == .boolean) include_run_logs = value.boolean;
    }

    var analyzed: u64 = 0;
    var failed: u64 = 0;
    var without_records: u64 = 0;
    var encrypted_logs: u64 = 0;

    if (inputs.len == 0) {
        run.setSummary("没有发现 UU远程（GameViewer）相关文件");
        run.log(.info, "the run resolved no GameViewer inputs");
        return;
    }

    try run.progress(0, inputs.len, null);
    for (inputs, 0..) |file, index| {
        try run.checkCancelled();
        const path = displayPath(file);
        try run.progress(index, inputs.len, path);
        run.log(.info, try message(run, "开始解析 {s}", .{path}));

        const before = run.emitted();
        if (try analyzeFile(&state, run, file, include_run_logs, &encrypted_logs)) |failure| {
            failed += 1;
            // One bad file is a warning of the run, not a failure: the other
            // inputs still produce results.
            try run.warnFile(file, failure.code, failure.message);
            run.log(.err, failure.message);
            continue;
        }
        if (run.emitted() > before) {
            analyzed += 1;
        } else {
            without_records += 1;
            run.log(.info, try message(run, "解析 {s} 完成，未产出记录", .{path}));
        }
    }

    // ---------------------------------------------------- merged emission

    // config.ini's uuid fills the client id when the JWT did not decode.
    if (state.client_uuid) |uuid| {
        if (state.account) |*account| {
            if (account.client_id == null) account.client_id = uuid;
        }
    }

    var account_count: u64 = 0;
    if (state.account) |account| {
        if (account.user_id) |user_id| {
            var emit = run.record(records.ACCOUNT_TYPE, &.{
                lc.wire.str(user_id),
                optionalText(account.device_id),
                optionalText(account.client_id),
                optionalText(account.system_id),
                optionalText(account.login_ip),
                try timestampValue(run, account.issued_at),
                optionalText(account.credential_id),
            });
            if (state.account_file) |*file| emit = emit.from(file);
            try emit.emit();
            account_count += 1;
        } else {
            run.log(.warn, try message(run, "账号信息缺少用户ID，未产出账号记录", .{}));
        }
    }

    var device_count: u64 = 0;
    var device_iterator = state.devices.valueIterator();
    while (device_iterator.next()) |row| {
        try emitDevice(run, state.account, row.obs, &row.file);
        device_count += 1;
    }

    var session_count: u64 = 0;
    var session_iterator = state.sessions.valueIterator();
    while (session_iterator.next()) |session| {
        try emitSession(run, session.*);
        session_count += 1;
    }

    var run_log_count: u64 = 0;
    if (include_run_logs) {
        var log_iterator = state.run_logs.valueIterator();
        while (log_iterator.next()) |entry| {
            try emitRunLog(run, entry.*);
            run_log_count += 1;
        }
    }

    const total = run.emitted();

    try run.progress(inputs.len, inputs.len, null);
    const summary = try std.fmt.allocPrint(
        run_arena,
        "分析 {d} 个输入，产出 {d} 条记录（账号 {d}、设备 {d}、远程会话 {d}、运行日志 {d}；失败 {d}，无记录 {d}）",
        .{ inputs.len, total, account_count, device_count, session_count, run_log_count, failed, without_records },
    );
    run.setSummary(summary);
    run.log(.info, summary);
    if (encrypted_logs > 0) {
        run.log(.info, try message(
            run,
            "{d} 个 .slog 日志为 SLOG 加密格式，仅解析文件名元数据，未解密内容",
            .{encrypted_logs},
        ));
    }
}

// ------------------------------------------------------------ per input

fn analyzeFile(
    state: *RunState,
    run: *const lc.Run,
    file: lc.FileRef,
    include_run_logs: bool,
    encrypted_logs: *u64,
) lc.Error!?Failure {
    const path = displayPath(file);
    const name = std.fs.path.basename(path);
    const extension = std.fs.path.extension(name);

    if (std.ascii.eqlIgnoreCase(name, "NTUSER.DAT")) {
        return analyzeHive(state, run, file);
    }
    if (std.ascii.eqlIgnoreCase(extension, ".slog")) {
        return analyzeSlog(state, run, file, name, path, include_run_logs, encrypted_logs);
    }
    if (std.ascii.eqlIgnoreCase(extension, ".json")) {
        return analyzeJson(state, run, file, name, path);
    }
    if (std.ascii.eqlIgnoreCase(extension, ".ini")) {
        return analyzeIni(state, run, file, path);
    }
    // Every other file (conf, data, images, binaries) is scanned and skipped.
    return null;
}

// -------------------------------------------------------------- registry

fn analyzeHive(state: *RunState, run: *const lc.Run, file: lc.FileRef) lc.Error!?Failure {
    const path = displayPath(file);
    if (file.size() == 0) {
        return .{ .code = "HIVE_EMPTY", .message = try message(run, "{s} 是空文件，已跳过", .{path}) };
    }
    // No size cap on hives: real user hives reach hundreds of MB. The peak
    // is about 2-3x the hive size (read buffer + the regf image copy), and
    // plugin.toml's memory field is the guard.
    const buffer = readWhole(file, std.math.maxInt(u64)) catch |err| {
        return .{ .code = "HIVE_READ_FAILED", .message = try message(run, "读取 {s} 失败：{s}", .{ path, @errorName(err) }) };
    };
    defer std.heap.c_allocator.free(buffer);

    var info = registry.collect(state.arena, std.heap.c_allocator, buffer) catch |err| {
        return .{ .code = "HIVE_PARSE_FAILED", .message = try message(run, "解析 {s} 失败：{s}", .{ path, @errorName(err) }) };
    };
    run.log(.info, try message(run, "解析 {s} 完成：{d} 条登录记录", .{ path, info.logins.len }));

    if (info.logins.len == 0) {
        // Keep the install facts even when the user never logged in.
        try emitLogin(run, file, &info, "(未登录)", null);
        return null;
    }
    for (info.logins) |login| {
        try emitLogin(run, file, &info, login.phone, login.login_ms);
    }
    return null;
}

// ------------------------------------------------------------ slog files

fn analyzeSlog(
    state: *RunState,
    run: *const lc.Run,
    file: lc.FileRef,
    name: []const u8,
    path: []const u8,
    include_run_logs: bool,
    encrypted_logs: *u64,
) lc.Error!?Failure {
    const parsed = slogname.parseName(name) orelse return null;

    // Only the magic is read: the body is an encrypted format that this
    // plugin does not attempt to decrypt.
    const head = file.readAt(0, 8) catch |err| {
        return .{ .code = "SLOG_READ_FAILED", .message = try message(run, "读取 {s} 头部失败：{s}", .{ path, @errorName(err) }) };
    };
    const encrypted = slogname.hasSlogMagic(head);
    if (encrypted) encrypted_logs.* += 1;

    const start_ms = parsed.start_ms orelse {
        run.log(.warn, try message(run, "{s} 的文件名没有有效时间戳，已跳过", .{path}));
        return null;
    };

    switch (parsed.kind) {
        .connection, .streamer => {
            const role_text: []const u8 = switch (parsed.role) {
                .controller => "controller",
                .controlled => "controlled",
                // A connection log without a role is not session evidence.
                .none => {
                    run.log(.warn, try message(run, "{s} 的文件名缺少会话角色，已跳过", .{path}));
                    return null;
                },
            };
            const key = try std.fmt.allocPrint(state.arena, "{s}|{d}|{d}", .{ role_text, start_ms, parsed.pid orelse 0 });
            const entry = try state.sessions.getOrPut(key);
            if (!entry.found_existing) {
                entry.value_ptr.* = .{
                    .role = parsed.role,
                    .start_ms = start_ms,
                    .pid = parsed.pid,
                    .size = file.size(),
                    .segments = 1,
                    .encrypted = encrypted,
                    .last_activity = file.timestamps().modified,
                    .file = file,
                };
            } else {
                mergeAgg(&entry.value_ptr.size, &entry.value_ptr.segments, &entry.value_ptr.encrypted, &entry.value_ptr.last_activity, file.size(), encrypted, file.timestamps().modified);
            }
        },
        .run => {
            if (!include_run_logs) return null;
            const component = try componentOf(path, state.arena);
            const key = try std.fmt.allocPrint(state.arena, "{s}|{d}|{d}", .{ component, start_ms, parsed.pid orelse 0 });
            const entry = try state.run_logs.getOrPut(key);
            if (!entry.found_existing) {
                entry.value_ptr.* = .{
                    .component = component,
                    .start_ms = start_ms,
                    .pid = parsed.pid,
                    .size = file.size(),
                    .segments = 1,
                    .encrypted = encrypted,
                    .last_activity = file.timestamps().modified,
                    .file = file,
                };
            } else {
                mergeAgg(&entry.value_ptr.size, &entry.value_ptr.segments, &entry.value_ptr.encrypted, &entry.value_ptr.last_activity, file.size(), encrypted, file.timestamps().modified);
            }
        },
        .unknown => {
            run.log(.warn, try message(run, "{s} 是未识别的 SLog 文件名，已跳过", .{path}));
        },
    }
    return null;
}

fn mergeAgg(size: *u64, segments: *u32, encrypted: *bool, last_activity: *?[]const u8, add_size: u64, add_encrypted: bool, add_modified: ?[]const u8) void {
    size.* += add_size;
    segments.* += 1;
    encrypted.* = encrypted.* or add_encrypted;
    if (last_activity.* == null) last_activity.* = add_modified;
}

/// The component of a path: the directory segment right after the `log`
/// root (client, server, service, launcher, Healthd, …), matched
/// case-insensitively like the Windows file systems.
fn componentOf(path: []const u8, arena: std.mem.Allocator) lc.Error![]const u8 {
    var it = std.mem.tokenizeScalar(u8, path, '/');
    var pending = false;
    while (it.next()) |segment| {
        if (pending) return normalizeComponent(segment, arena);
        if (std.ascii.eqlIgnoreCase(segment, "log")) pending = true;
    }
    return normalizeComponent("other", arena);
}

fn normalizeComponent(component: []const u8, arena: std.mem.Allocator) lc.Error![]const u8 {
    const table = [_]struct { name: []const u8, id: []const u8 }{
        .{ .name = "client", .id = "client" },
        .{ .name = "server", .id = "server" },
        .{ .name = "service", .id = "service" },
        .{ .name = "launcher", .id = "launcher" },
        .{ .name = "healthd", .id = "healthd" },
        .{ .name = "upgrade", .id = "upgrade" },
        .{ .name = "mumuplayer", .id = "mumu" },
    };
    for (table) |row| {
        if (std.ascii.eqlIgnoreCase(component, row.name)) {
            return arena.dupe(u8, row.id);
        }
    }
    return arena.dupe(u8, "other");
}

// ----------------------------------------------------------- json files

fn analyzeJson(state: *RunState, run: *const lc.Run, file: lc.FileRef, name: []const u8, path: []const u8) lc.Error!?Failure {
    // A telemetry session? `session.json` under a `<component>/Sentry/…` dir.
    if (std.ascii.eqlIgnoreCase(name, "session.json")) {
        return analyzeTelemetry(run, file, path);
    }
    // A cached remote file listing? `file_transfer/<device>.json`.
    if (core.transferDeviceId(name)) |device_id| {
        return analyzeTransfer(state, run, file, device_id);
    }
    // Server-issued config caches, codec caches, quick-launch caches: no
    // per-file records; they are counted as scanned.
    run.log(.debug, try message(run, "{s} 为非证据 JSON，已跳过", .{path}));
    return null;
}

fn analyzeTelemetry(run: *const lc.Run, file: lc.FileRef, path: []const u8) lc.Error!?Failure {
    const read = try readTextFile(run, file, path);
    const text = switch (read) {
        .empty => return null,
        .failure => |failure| return failure,
        .text => |text| text,
    };
    const telemetry = (core.collectTelemetry(run.context().arena, text) catch return error.OutOfMemory) orelse {
        run.log(.warn, try message(run, "{s} 不是遥测会话 JSON，已跳过", .{path}));
        return null;
    };
    try emitTelemetry(run, file, path, telemetry);
    return null;
}

fn analyzeTransfer(state: *RunState, run: *const lc.Run, file: lc.FileRef, device_id: []const u8) lc.Error!?Failure {
    const path = displayPath(file);
    const read = try readTextFile(run, file, path);
    const text = switch (read) {
        .empty => return null,
        .failure => |failure| return failure,
        .text => |text| text,
    };
    const entries = (core.collectTransferEntries(run.context().arena, text) catch return error.OutOfMemory) orelse {
        run.log(.warn, try message(run, "{s} 不是远端文件列表 JSON，已跳过", .{path}));
        return null;
    };
    for (entries) |entry| {
        try run.record(records.FILE_TRACE_TYPE, &.{
            lc.wire.str(device_id),
            lc.wire.str(entry.path),
            lc.wire.str(entry.display_name),
            lc.wire.str(entry.type_name),
            try timestampValue(run, entry.modified_ms),
        }).from(&file).emit();
    }
    // The cached listing itself also proves the device was browsed.
    try state.mergeDevice(.{ .id = try state.arena.dupe(u8, device_id), .transfer_cached = true }, file);
    run.log(.info, try message(run, "解析 {s} 完成，{d} 条远端文件痕迹", .{ path, entries.len }));
    return null;
}

/// The outcome of reading one text file.
const TextRead = union(enum) {
    /// An empty file: nothing to parse, no warning.
    empty,
    /// The file could not be read; the caller turns this into a run warning.
    failure: Failure,
    text: []const u8,
};

/// Reads a text file through the libc buffer pattern and returns it as
/// lossy-decoded UTF-8 in the run arena.
fn readTextFile(run: *const lc.Run, file: lc.FileRef, path: []const u8) lc.Error!TextRead {
    if (file.size() == 0) return .empty;
    if (file.size() > MAX_TEXT_FILE) {
        return .{ .failure = .{ .code = "FILE_TOO_LARGE", .message = try message(
            run,
            "{s} 为 {d} 字节，超过上限 {d}，已跳过",
            .{ path, file.size(), MAX_TEXT_FILE },
        ) } };
    }
    const bytes = readWhole(file, MAX_TEXT_FILE) catch |err| {
        return .{ .failure = .{ .code = "FILE_READ_FAILED", .message = try message(run, "读取 {s} 失败：{s}", .{ path, @errorName(err) }) } };
    };
    defer std.heap.c_allocator.free(bytes);
    const text = lc.text.decodeLossy(run.context().arena, bytes) catch return error.OutOfMemory;
    return .{ .text = text };
}

// ------------------------------------------------------------- ini files

fn analyzeIni(state: *RunState, run: *const lc.Run, file: lc.FileRef, path: []const u8) lc.Error!?Failure {
    if (file.size() == 0) return null;
    if (file.size() > MAX_TEXT_FILE) {
        return .{ .code = "FILE_TOO_LARGE", .message = try message(
            run,
            "{s} 为 {d} 字节，超过上限 {d}，已跳过",
            .{ path, file.size(), MAX_TEXT_FILE },
        ) };
    }
    const bytes = readWhole(file, MAX_TEXT_FILE) catch |err| {
        return .{ .code = "FILE_READ_FAILED", .message = try message(run, "读取 {s} 失败：{s}", .{ path, @errorName(err) }) };
    };
    defer std.heap.c_allocator.free(bytes);

    // The per-file arena owns the lossy text and the parsed document.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    const file_arena = arena_state.allocator();
    const text = lc.text.decodeLossy(file_arena, bytes) catch return error.OutOfMemory;
    const doc = ini.parse(file_arena, text) catch return error.OutOfMemory;
    if (doc.issues.len > 0) {
        run.log(.debug, try message(run, "{s} 有 {d} 处无法解析的行", .{ path, doc.issues.len }));
    }

    // Account identity: user_info.ini (deviceId + token under [General]).
    if (try core.collectAccount(state.arena, &doc)) |account| {
        state.account = account;
        state.account_file = file;
        run.log(.info, try message(run, "解析 {s} 完成：账号 {s}", .{ path, account.user_id orelse "?" }));
        return null;
    }
    // Install uuid: config.ini (fills the account's client id).
    if (try core.collectInstallUuid(state.arena, &doc)) |uuid| {
        state.client_uuid = uuid;
        run.log(.info, try message(run, "解析 {s} 完成：客户端UUID {s}", .{ path, uuid }));
        return null;
    }
    // Devices: the three INI sources, merged into the device map.
    var matched = false;
    for (try core.collectLatestDevices(state.arena, &doc)) |obs| {
        matched = true;
        try state.mergeDevice(obs, file);
    }
    for (try core.collectPrivacyDevices(state.arena, &doc)) |obs| {
        matched = true;
        try state.mergeDevice(obs, file);
    }
    for (try core.collectAssistDevices(state.arena, &doc)) |obs| {
        matched = true;
        try state.mergeDevice(obs, file);
    }
    if (matched) {
        run.log(.info, try message(run, "解析 {s} 完成：关联设备信息已合并", .{path}));
        return null;
    }
    // Upgrades: version-shaped sections in upgrade/upgrade.ini.
    if (try core.collectUpgrades(state.arena, &doc)) |upgrades| {
        for (upgrades) |upgrade| {
            try emitUpgrade(run, file, upgrade);
        }
        run.log(.info, try message(run, "解析 {s} 完成，{d} 条升级记录", .{ path, upgrades.len }));
        return null;
    }
    // Everything else (user_setting.ini, global_config.ini, sensor
    // config, …) carries no evidence this plugin records.
    return null;
}

// ------------------------------------------------------------- emission

fn timestampValue(run: *const lc.Run, ms: ?i64) lc.Error!lc.wire.Value {
    const value = ms orelse return .nil;
    // Format into the run arena: `Timestamp` owns an inline buffer, and a
    // slice into a local would dangle before the record is encoded.
    const timestamp = lc.record.Timestamp.fromUnixMillis(value);
    const text = try run.context().arena.dupe(u8, timestamp.asStr());
    return .{ .string = text };
}

fn optionalText(text: ?[]const u8) lc.wire.Value {
    const value = text orelse return .nil;
    if (value.len == 0) return .nil;
    return .{ .string = value };
}

fn optionalBool(flag: ?bool) lc.wire.Value {
    const value = flag orelse return .nil;
    return .{ .boolean = value };
}

fn emitDevice(run: *const lc.Run, account: ?core.Account, obs: core.DeviceObs, file: *const lc.FileRef) lc.Error!void {
    var role: []const u8 = "remote";
    if (account) |acc| {
        if (acc.device_id) |local| {
            if (std.mem.eql(u8, local, obs.id)) role = "local";
        }
    }
    try run.record(records.DEVICE_TYPE, &.{
        lc.wire.str(obs.id),
        lc.wire.str(role),
        try timestampValue(run, obs.last_connect_ms),
        .{ .boolean = obs.assist_configured },
        try timestampValue(run, obs.assist_refreshed_ms),
        .{ .boolean = obs.privacy_seen },
        .{ .boolean = obs.server_config },
        .{ .boolean = obs.transfer_cached },
    }).from(file).emit();
}

fn emitSession(run: *const lc.Run, session: SessionAgg) lc.Error!void {
    const role: []const u8 = switch (session.role) {
        .controller => "controller",
        else => "controlled",
    };
    try run.record(records.SESSION_TYPE, &.{
        lc.wire.str(role),
        try timestampValue(run, session.start_ms),
        optionalText(session.last_activity),
        if (session.pid) |pid| lc.wire.uint(pid) else .nil,
        lc.wire.uint(session.size),
        lc.wire.uint(session.segments),
        .{ .boolean = session.encrypted },
    }).from(&session.file).emit();
}

fn emitRunLog(run: *const lc.Run, entry: RunLogAgg) lc.Error!void {
    try run.record(records.RUN_LOG_TYPE, &.{
        lc.wire.str(entry.component),
        try timestampValue(run, entry.start_ms),
        if (entry.pid) |pid| lc.wire.uint(pid) else .nil,
        lc.wire.uint(entry.size),
        lc.wire.uint(entry.segments),
        .{ .boolean = entry.encrypted },
    }).from(&entry.file).emit();
}

fn emitTelemetry(run: *const lc.Run, file: lc.FileRef, path: []const u8, telemetry: core.Telemetry) lc.Error!void {
    const component = try componentOf(path, run.context().arena);
    try run.record(records.TELEMETRY_TYPE, &.{
        lc.wire.str(component),
        optionalText(telemetry.release),
        optionalText(telemetry.user_id),
        optionalText(telemetry.session_id),
        optionalText(telemetry.started),
        optionalText(telemetry.status),
        if (telemetry.errors) |errors| lc.wire.uint(@intCast(@max(errors, 0))) else .nil,
    }).from(&file).emit();
}

fn emitUpgrade(run: *const lc.Run, file: lc.FileRef, upgrade: core.Upgrade) lc.Error!void {
    try run.record(records.UPGRADE_TYPE, &.{
        lc.wire.str(upgrade.version),
        try timestampValue(run, upgrade.discovered_ms),
        if (upgrade.status) |status| lc.wire.uint(@intCast(@max(status, 0))) else .nil,
        optionalText(upgrade.previous_version),
        optionalText(upgrade.update_type),
        optionalText(upgrade.subtitle),
        optionalText(upgrade.install_path),
        optionalText(upgrade.download_url),
        optionalText(upgrade.md5),
        optionalText(upgrade.error_message),
    }).from(&file).emit();
}

fn emitLogin(run: *const lc.Run, file: lc.FileRef, info: *const registry.RegistryInfo, phone: []const u8, login_ms: ?i64) lc.Error!void {
    try run.record(records.LOGIN_TYPE, &.{
        lc.wire.str(phone),
        try timestampValue(run, login_ms),
        optionalText(info.app_version),
        optionalText(info.install_dir),
        optionalText(info.cache_path),
        optionalBool(info.installed),
        optionalBool(info.ever_run),
    }).from(&file).emit();
}

// ---------------------------------------------------------------- helpers

/// Formats a message in the run's arena (warnings are stored with the run,
/// so they must outlive this call).
fn message(run: *const lc.Run, comptime format: []const u8, args: anytype) lc.Error![]const u8 {
    return std.fmt.allocPrint(run.context().arena, format, args);
}

/// Reads the whole file into a libc-owned buffer (freed by the caller).
fn readWhole(file: lc.FileRef, cap: u64) (lc.Error || error{ TooLarge, ShortRead })![]u8 {
    if (file.size() > cap) return error.TooLarge;
    const length = std.math.cast(usize, file.size()) orelse return error.TooLarge;
    const buffer = try std.heap.c_allocator.alloc(u8, length);
    errdefer std.heap.c_allocator.free(buffer);
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

const testing = std.testing;

fn fileRef(name: []const u8, size: u64) lc.FileRef {
    var cancelled = std.atomic.Value(bool).init(false);
    const ctx = lc.host.Context{
        .host = undefined,
        .cancelled = &cancelled,
        .arena = testing.allocator,
        .alloc = testing.allocator,
    };
    return lc.FileRef.init(ctx, .{ .file_id = "file", .name = name, .size = size });
}

test "component detection from log paths" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("client", try componentOf("GameViewer/log/client/Log/log_1.slog", arena));
    try testing.expectEqualStrings("healthd", try componentOf("GameViewer/log/Healthd/log/log_1.slog", arena));
    try testing.expectEqualStrings("server", try componentOf("GameViewer/log/server/MuMuPlayer/x.slog", arena));
    try testing.expectEqualStrings("client", try componentOf("GameViewer/log/client/Sentry/abc.run/session.json", arena));
    try testing.expectEqualStrings("other", try componentOf("somewhere/else/log_1.slog", arena));
}

test "fileRef helper builds a FileRef" {
    const file = fileRef("config.ini", 10);
    try testing.expectEqualStrings("config.ini", file.name());
    try testing.expectEqual(@as(u64, 10), file.size());
}
