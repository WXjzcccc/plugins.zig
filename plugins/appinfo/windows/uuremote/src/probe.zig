//! Dev tool: run the extraction over real GameViewer files from disk and
//! print what the plugin would emit — no host involved. This is how the
//! plugin was validated against a live installation.
//!
//!   zig build probe
//!   zig-out/bin/probe.exe user_info.ini setting_x.ini upgrade.ini \
//!       file_transfer/xxx.json session.json connection_log_xxx.slog \
//!       NTUSER.DAT [more files ...]
//!
//! The classification mirrors `plugin/analyze.zig`: NTUSER.DAT goes through
//! the registry reader, `.slog` files only get their names parsed (the
//! content is an encrypted format), INI/JSON files are classified by
//! signature.

const std = @import("std");
const ini = @import("ini_zig");
const regf = @import("regf_zig");

const core = @import("core/uuremote.zig");
const registry = @import("core/registry.zig");
const slogname = @import("core/slogname.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) {
        std.debug.print("usage: probe <file> [more files ...]\n", .{});
        std.process.exit(2);
    }

    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();

    for (args[1..]) |path| {
        _ = scratch.reset(.retain_capacity);
        std.debug.print("\n== {s} ==\n", .{path});

        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, scratch.allocator(), .limited(1 << 30)) catch |err| {
            std.debug.print("  cannot read: {t}\n", .{err});
            continue;
        };
        const name = std.fs.path.basename(path);
        const extension = std.fs.path.extension(name);

        if (std.ascii.eqlIgnoreCase(name, "NTUSER.DAT")) {
            probeHive(gpa, scratch.allocator(), bytes);
        } else if (std.ascii.eqlIgnoreCase(extension, ".slog")) {
            probeSlog(name, bytes);
        } else if (std.ascii.eqlIgnoreCase(extension, ".json")) {
            probeJson(scratch.allocator(), name, bytes);
        } else if (std.ascii.eqlIgnoreCase(extension, ".ini")) {
            probeIni(scratch.allocator(), bytes);
        } else {
            std.debug.print("  (no parser for .{s} files)\n", .{extension});
        }
    }
}

fn probeHive(gpa: std.mem.Allocator, arena: std.mem.Allocator, bytes: []const u8) void {
    var info = registry.collect(arena, gpa, bytes) catch |err| {
        std.debug.print("  not a hive ({t})\n", .{err});
        return;
    };
    defer registry.freeInfo(arena, &info);
    if (info.app_version) |version| std.debug.print("  version:      {s}\n", .{version});
    if (info.install_dir) |dir| std.debug.print("  install dir:  {s}\n", .{dir});
    if (info.cache_path) |path| std.debug.print("  cache path:   {s}\n", .{path});
    if (info.installed) |flag| std.debug.print("  installed:    {}\n", .{flag});
    if (info.ever_run) |flag| std.debug.print("  ever run:     {}\n", .{flag});
    for (info.logins) |login| {
        if (login.login_ms) |ms| {
            const stamp = lcTimestamp(ms);
            std.debug.print("  login:        {s} at {s}\n", .{ login.phone, stamp });
        } else {
            std.debug.print("  login:        {s}\n", .{login.phone});
        }
    }
    if (info.logins.len == 0) std.debug.print("  (no logins)\n", .{});
}

fn probeSlog(name: []const u8, bytes: []const u8) void {
    if (slogname.hasSlogMagic(bytes)) {
        std.debug.print("  content:      SLOG 加密格式（未解密）\n", .{});
    } else {
        std.debug.print("  content:      非 SLOG 魔数（{d} 字节）\n", .{bytes.len});
    }
    if (slogname.parseName(name)) |parsed| {
        std.debug.print("  kind:         {s}\n", .{@tagName(parsed.kind)});
        std.debug.print("  role:         {s}\n", .{@tagName(parsed.role)});
        if (parsed.start_ms) |ms| std.debug.print("  start:        {s}\n", .{lcTimestamp(ms)});
        if (parsed.pid) |pid| std.debug.print("  pid:          {d}\n", .{pid});
        std.debug.print("  segment:      {d}\n", .{parsed.segment});
    } else {
        std.debug.print("  (not an SLog name)\n", .{});
    }
}

fn probeJson(arena: std.mem.Allocator, name: []const u8, bytes: []const u8) void {
    if (std.mem.eql(u8, name, "session.json")) {
        if (core.collectTelemetry(arena, bytes)) |telemetry| {
            if (telemetry) |value| {
                if (value.release) |release| std.debug.print("  release:      {s}\n", .{release});
                if (value.user_id) |user| std.debug.print("  user:         {s}\n", .{user});
                if (value.started) |started| std.debug.print("  started:      {s}\n", .{started});
                return;
            }
        } else |_| {}
        std.debug.print("  (not a telemetry session)\n", .{});
        return;
    }
    if (core.transferDeviceId(name)) |device_id| {
        const entries = core.collectTransferEntries(arena, bytes) catch null;
        if (entries) |list| {
            std.debug.print("  device:       {s}\n", .{device_id});
            std.debug.print("  entries:      {d}\n", .{list.len});
            for (list) |entry| {
                std.debug.print("    [{s}] {s} -> {s}\n", .{ entry.type_name, entry.display_name, entry.path });
            }
            return;
        }
    }
    std.debug.print("  (no evidence parser for this JSON)\n", .{});
}

fn probeIni(arena: std.mem.Allocator, bytes: []const u8) void {
    const doc = ini.parse(arena, bytes) catch return;
    defer doc.deinit(arena);
    std.debug.print("  sections:     {d}, issues: {d}\n", .{ doc.sections.len, doc.issues.len });

    if (core.collectAccount(arena, &doc) catch null) |account| {
        if (account.user_id) |user| std.debug.print("  user id:      {s}\n", .{user});
        if (account.device_id) |device| std.debug.print("  device id:    {s}\n", .{device});
        if (account.client_id) |client| std.debug.print("  client id:    {s}\n", .{client});
        if (account.system_id) |system| std.debug.print("  system id:    {s}\n", .{system});
        if (account.login_ip) |ip| std.debug.print("  login ip:     {s}\n", .{ip});
        if (account.issued_at) |ms| std.debug.print("  issued at:    {s}\n", .{lcTimestamp(ms * 1000)});
        std.debug.print("  token:        {s}\n", .{if (account.token_decoded) "decoded" else "not decodable"});
        return;
    }
    if (core.collectInstallUuid(arena, &doc) catch null) |uuid| {
        std.debug.print("  client uuid:  {s}\n", .{uuid});
        return;
    }
    var any = false;
    for (core.collectLatestDevices(arena, &doc) catch &.{}) |obs| {
        any = true;
        std.debug.print("  device:       {s} last_connect={s}\n", .{
            obs.id,
            if (obs.last_connect_ms) |ms| lcTimestamp(ms) else "?",
        });
    }
    for (core.collectPrivacyDevices(arena, &doc) catch &.{}) |obs| {
        any = true;
        std.debug.print("  device:       {s} privacy_prompt_seen\n", .{obs.id});
    }
    for (core.collectAssistDevices(arena, &doc) catch &.{}) |obs| {
        any = true;
        std.debug.print("  device:       {s} assist code (DPAPI, not decrypted)\n", .{obs.id});
    }
    if (core.collectUpgrades(arena, &doc) catch null) |upgrades| {
        for (upgrades) |upgrade| {
            any = true;
            std.debug.print("  upgrade:      {s} status={any} at {s}\n", .{
                upgrade.version,
                upgrade.status,
                if (upgrade.discovered_ms) |ms| lcTimestamp(ms) else "?",
            });
            if (upgrade.subtitle) |subtitle| std.debug.print("    {s}\n", .{subtitle});
            if (upgrade.error_message) |error_message| std.debug.print("    error: {s}\n", .{error_message});
        }
    }
    if (!any) std.debug.print("  (no evidence structures found)\n", .{});
}

var timestamp_buffer: [48]u8 = undefined;

/// Renders a Unix-millisecond timestamp as UTC via the SDK's formatter.
/// The `Timestamp` owns an inline buffer, so the text is copied out before
/// the value dies.
fn lcTimestamp(ms: i64) []const u8 {
    const lc = @import("lovelycarve");
    const timestamp = lc.record.Timestamp.fromUnixMillis(ms);
    const text = timestamp.asStr();
    @memcpy(timestamp_buffer[0..text.len], text);
    return timestamp_buffer[0..text.len];
}
