//! Dev tool: run the analysis core over real hive files from disk and print
//! what the plugin would emit — no host involved.
//!
//!   zig build probe
//!   zig-out/bin/probe.exe SYSTEM SOFTWARE SAM [NTUSER.DAT ...]
//!
//! The file NAMES decide the role (SYSTEM / SOFTWARE / SAM / *.DAT), exactly
//! like the evidence-scope classification.

const std = @import("std");
const lc = @import("lovelycarve");
const bootkey = @import("core/bootkey.zig");
const hive_mod = @import("core/hive.zig");
const profile = @import("core/profile.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) {
        std.debug.print("usage: probe <SYSTEM> <SOFTWARE> <SAM> [NTUSER.DAT ...]\n", .{});
        std.process.exit(2);
    }

    var system_hive: ?hive_mod.Hive = null;
    var software_hive: ?hive_mod.Hive = null;
    var sam_hive: ?hive_mod.Hive = null;
    var user_hives: std.ArrayList(hive_mod.Hive) = .empty;
    defer {
        if (system_hive) |*hive| hive.deinit();
        if (software_hive) |*hive| hive.deinit();
        if (sam_hive) |*hive| hive.deinit();
        for (user_hives.items) |*hive| hive.deinit();
        user_hives.deinit(gpa);
    }

    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();

    for (args[1..]) |path| {
        const name = std.fs.path.basename(path);
        _ = scratch.reset(.retain_capacity);
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, scratch.allocator(), .limited(1 << 30)) catch |err| {
            std.debug.print("cannot read {s}: {t}\n", .{ path, err });
            continue;
        };
        const hive = hive_mod.Hive.open(gpa, bytes) catch |err| {
            std.debug.print("{s}: not a hive ({t})\n", .{ name, err });
            continue;
        };
        std.debug.print("loaded {s} ({d} bytes)\n", .{ name, bytes.len });
        if (std.ascii.eqlIgnoreCase(name, "SYSTEM")) {
            system_hive = hive;
        } else if (std.ascii.eqlIgnoreCase(name, "SOFTWARE")) {
            software_hive = hive;
        } else if (std.ascii.eqlIgnoreCase(name, "SAM")) {
            sam_hive = hive;
        } else {
            try user_hives.append(gpa, hive);
        }
    }

    // --- boot key -----------------------------------------------------------
    if (system_hive) |*system| {
        const control_set = try bootkey.controlSetName(system, arena);
        std.debug.print("\ncontrol set = {s}\n", .{control_set});
        if (try bootkey.bootKey(system, arena)) |key| {
            std.debug.print("boot key    = {x}\n", .{&key});
        } else {
            std.debug.print("boot key    = <missing>\n", .{});
        }
    }

    // --- system info ----------------------------------------------------------
    if (software_hive) |*software| {
        var values: std.heap.ArenaAllocator = .init(gpa);
        defer values.deinit();
        std.debug.print("\n== 系统信息 ==\n", .{});
        const items = try profile.collectSystemInfo(values.allocator(), if (system_hive) |*s| s else null, software);
        for (items) |item| {
            if (item.timestamp) |seconds| {
                const timestamp = lc.record.Timestamp.fromUnix(seconds);
                std.debug.print("  {s}: {s}\n", .{ item.item, timestamp.asStr() });
            } else {
                std.debug.print("  {s}: {s}\n", .{ item.item, item.value });
            }
        }
    }

    // --- network ----------------------------------------------------------------
    if (system_hive) |*system| {
        var values: std.heap.ArenaAllocator = .init(gpa);
        defer values.deinit();
        std.debug.print("\n== 网卡信息 ==\n", .{});
        const adapters = try profile.collectNetwork(values.allocator(), system);
        for (adapters) |adapter| {
            std.debug.print("  {s} ({s})\n", .{ adapter.name, adapter.interface });
            std.debug.print("    ip {s} / {s} gw {s}\n", .{ adapter.ip, adapter.netmask, adapter.gateway });
            std.debug.print("    mac {s} / {s}\n", .{ adapter.mac_current, adapter.mac_permanent });
            std.debug.print("    dhcp {s} via {s} gw {s}\n", .{ adapter.dhcp_ip, adapter.dhcp_server, adapter.dhcp_gateway });
        }
    }

    // --- users --------------------------------------------------------------------
    if (sam_hive) |*sam_hive_ref| {
        var values: std.heap.ArenaAllocator = .init(gpa);
        defer values.deinit();
        std.debug.print("\n== 用户信息 ==\n", .{});
        const report = try profile.collectUsers(values.allocator(), if (system_hive) |*s| s else null, sam_hive_ref);
        std.debug.print("  hash availability: {s}\n", .{@tagName(report.hashes)});
        for (report.users) |user| {
            std.debug.print("  {s}  sid={s} rid={s}\n", .{ user.username, user.sid, user.rid });
            std.debug.print("    nt hash {s}\n", .{user.nt_hash});
            if (user.last_login) |seconds| {
                const timestamp = lc.record.Timestamp.fromUnix(seconds);
                std.debug.print("    last login {s}\n", .{timestamp.asStr()});
            }
            std.debug.print("    logons {d} failed {d} attr 0x{x}\n", .{ user.logon_count, user.invalid_logon_count, user.user_attribute });
        }
    }

    // --- browser ---------------------------------------------------------------
    if (user_hives.items.len != 0) {
        std.debug.print("\n== 默认浏览器 ==\n", .{});
        for (user_hives.items) |*hive| {
            var values: std.heap.ArenaAllocator = .init(gpa);
            defer values.deinit();
            const progid = try profile.collectBrowser(values.allocator(), hive);
            std.debug.print("  {s}\n", .{progid orelse "<no UserChoice>"});
        }
    }
}
