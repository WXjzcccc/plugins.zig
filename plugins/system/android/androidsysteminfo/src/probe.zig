//! Dev tool: run every analyzer's parser core over real Android data
//! partition files from disk and print what the plugin would emit — no host
//! involved.
//!
//!   zig build probe
//!   zig-out/bin/probe.exe <file> [more files ...]
//!
//! The file NAMES route each input to the parser that owns it, exactly like
//! the run-time classification. SQLite databases are opened read-only in
//! place — probe passes their paths straight through.

const std = @import("std");
const abx = @import("core/abx.zig");
const adb = @import("core/adb.zig");
const boot = @import("core/boot.zig");
const bluetooth = @import("core/bluetooth.zig");
const databases = @import("core/databases.zig");
const logcat = @import("core/logcat.zig");
const packages = @import("core/packages.zig");
const wifi = @import("core/wifi.zig");

const MAX_FILE: usize = 64 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) {
        std.debug.print(
            "usage: probe <SYSTEM_BOOT@*.txt|last-header.txt|packages.xml|users/*.xml|bootlog.txt|dropbox/*|anr/*|packages.list|WifiConfigStore.xml|WifiConfigStoreSoftAp.xml|bt_config.conf|adb_keys|adb_temp_keys.xml|accounts_ce.db|gnssCollectData.db> ...\n",
            .{},
        );
        std.process.exit(2);
    }

    for (args[1..]) |path| {
        const name = std.fs.path.basename(path);
        std.debug.print("\n===== {s} =====\n", .{path});

        // The sqlite inputs keep their path; everything else is read once.
        if (std.mem.endsWith(u8, name, ".db")) {
            try probeDb(arena, name, path);
            continue;
        }
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(MAX_FILE)) catch |err| {
            std.debug.print("cannot read: {t}\n", .{err});
            continue;
        };
        defer gpa.free(bytes);
        std.debug.print("({d} bytes)\n", .{bytes.len});
        try probeFile(arena, name, bytes);
    }
}

fn probeFile(arena: std.mem.Allocator, name: []const u8, bytes: []const u8) !void {
    if (std.mem.endsWith(u8, name, ".xml") and
        std.mem.indexOf(u8, name, "packages") == null and
        std.mem.indexOf(u8, name, "WifiConfigStore") == null and
        std.mem.indexOf(u8, name, "adb_temp_keys") == null)
    {
        // data/system/users/<id>.xml — an ABX user record.
        const root = abx.parse(arena, bytes) catch |err| {
            std.debug.print("  parse failed: {t}\n", .{err});
            return;
        };
        const user = if (std.mem.eql(u8, root.name, "user")) root else (root.child("user") orelse return);
        inline for (.{ "id", "serialNumber", "flags" }) |field| {
            if (user.attrLong(field)) |value| std.debug.print("  {s}: {d}\n", .{ field, value });
        }
        if (user.attrText(arena, "type") catch null) |value| std.debug.print("  type: {s}\n", .{value});
        if (user.attrLong("created")) |ms| std.debug.print("  created_ms: {d}\n", .{ms});
        if (user.attrLong("lastLoggedIn")) |ms| std.debug.print("  last_logged_in_ms: {d}\n", .{ms});
        return;
    }
    if (std.mem.startsWith(u8, name, "SYSTEM_BOOT@") or std.mem.eql(u8, name, "last-header.txt")) {
        const header = try boot.parseHeader(arena, bytes);
        std.debug.print("  isPrevious: {}\n", .{boot.isPrevious(bytes)});
        inline for (.{ "build", "hardware", "revision", "bootloader", "radio", "kernel" }) |field| {
            if (@field(header, field)) |value| std.debug.print("  {s}: {s}\n", .{ field, value });
        }
        return;
    }
    if (std.mem.eql(u8, name, "packages.xml")) {
        var parsed_packages: std.ArrayList(packages.Package) = .empty;
        var parsed_permissions: std.ArrayList(packages.Permission) = .empty;
        var facts: std.ArrayList(packages.RootFact) = .empty;
        packages.parseXml(arena, bytes, &parsed_packages, &parsed_permissions, &facts) catch |err| {
            std.debug.print("  parse failed: {t}\n", .{err});
            return;
        };
        for (facts.items) |fact| std.debug.print("  fact {s} = {s}\n", .{ fact.item, fact.value });
        std.debug.print("  packages: {d}, permissions: {d}\n", .{ parsed_packages.items.len, parsed_permissions.items.len });
        for (parsed_packages.items, 0..) |package, index| {
            if (index >= 5) break;
            std.debug.print("  {s} uid={any} version={any} installer={any}\n", .{
                package.package, package.uid, package.version_code, package.installer,
            });
        }
        return;
    }
    if (std.mem.eql(u8, name, "bootlog.txt")) {
        var banner: ?logcat.Banner = null;
        var buffer: []const u8 = "";
        var lines: usize = 0;
        var headers: usize = 0;
        var iter = std.mem.splitScalar(u8, bytes, '\n');
        while (iter.next()) |line| {
            lines += 1;
            if (logcat.parseBanner(line)) |parsed| {
                banner = parsed;
            } else if (logcat.parseBufferMarker(line)) |marker| {
                buffer = marker;
            } else if (logcat.parseLine(headers + 1, buffer, line) != null) {
                headers += 1;
            }
        }
        if (banner) |b| std.debug.print("  banner: {d}-{d}-{d} offset={any}\n", .{ b.year, b.month, b.day, b.offset_minutes });
        std.debug.print("  lines: {d}, logcat headers: {d}, last buffer: {s}\n", .{ lines, headers, buffer });
        return;
    }
    if (std.mem.eql(u8, name, "adb_keys")) {
        var keys: std.ArrayList(adb.Key) = .empty;
        try adb.parseKeys(arena, bytes, &keys);
        std.debug.print("  keys: {d}\n", .{keys.items.len});
        for (keys.items, 0..) |key, index| {
            if (index >= 5) break;
            std.debug.print("  {s} {s} {s}\n", .{ key.digest[0..16], key.kind, key.user_host orelse "-" });
        }
        return;
    }
    if (std.mem.eql(u8, name, "adb_temp_keys.xml")) {
        var keys: std.ArrayList(adb.Key) = .empty;
        var bssids: std.ArrayList(adb.Bssid) = .empty;
        adb.parseTempKeys(arena, bytes, &keys, &bssids) catch |err| {
            std.debug.print("  parse failed: {t}\n", .{err});
            return;
        };
        std.debug.print("  temp keys: {d}, bssids: {d}\n", .{ keys.items.len, bssids.items.len });
        for (keys.items, 0..) |key, index| {
            if (index >= 5) break;
            std.debug.print("  {s} {s} last={any}\n", .{ key.digest[0..16], key.user_host orelse "-", key.last_connection_raw });
        }
        for (bssids.items) |bssid| std.debug.print("  bssid {s}\n", .{bssid.bssid});
        return;
    }
    if (std.mem.eql(u8, name, "WifiConfigStore.xml")) {
        var networks: std.ArrayList(wifi.Network) = .empty;
        wifi.parseConfigStore(arena, bytes, &networks) catch |err| {
            std.debug.print("  parse failed: {t}\n", .{err});
            return;
        };
        std.debug.print("  networks: {d}\n", .{networks.items.len});
        for (networks.items) |network| {
            std.debug.print("  {s} security={s} psk={s} connected={any}\n", .{
                network.ssid, network.security, network.preshared_key orelse "-", network.last_connected_ms,
            });
        }
        return;
    }
    if (std.mem.eql(u8, name, "WifiConfigStoreSoftAp.xml")) {
        const soft_ap = wifi.parseSoftAp(arena, bytes) catch |err| {
            std.debug.print("  parse failed: {t}\n", .{err});
            return;
        };
        if (soft_ap) |ap| {
            std.debug.print("  ssid={s} security={s} passphrase={s}\n", .{ ap.ssid, ap.security, ap.passphrase orelse "-" });
        } else {
            std.debug.print("  no SoftAp section\n", .{});
        }
        return;
    }
    if (std.mem.eql(u8, name, "bt_config.conf") or std.mem.eql(u8, name, "bt_config.bak")) {
        var devices: std.ArrayList(bluetooth.Device) = .empty;
        try bluetooth.parse(arena, bytes, &devices);
        for (devices.items) |device| {
            std.debug.print("  {s} {s} name={any} scan={any}\n", .{ device.kind, device.address, device.name, device.scan_mode });
        }
        return;
    }
    if (std.mem.startsWith(u8, name, "anr_") or std.mem.indexOf(u8, name, "wtf") != null) {
        const header = try @import("core/dropbox.zig").parseEntryHeader(arena, bytes);
        std.debug.print("  process={any} subject={any} time={any} abi={any}\n", .{
            header.process, header.subject, header.time_text, header.abi,
        });
        return;
    }
    std.debug.print("  (no probe for {s})\n", .{name});
}

fn probeDb(arena: std.mem.Allocator, name: []const u8, path: []const u8) !void {
    const path_z = try std.fmt.allocPrintSentinel(arena, "{s}", .{path}, 0);
    if (std.mem.endsWith(u8, name, "accounts_ce.db")) {
        std.debug.print("  accounts table: {}\n", .{databases.hasTable(path_z, "accounts")});
        var accounts: std.ArrayList(databases.Account) = .empty;
        databases.readAccounts(arena, path_z, &accounts) catch |err| {
            std.debug.print("  read failed: {t}\n", .{err});
            return;
        };
        std.debug.print("  accounts: {d}\n", .{accounts.items.len});
        for (accounts.items, 0..) |account, index| {
            if (index >= 5) break;
            std.debug.print("  {s} ({s}) password={s}\n", .{
                account.name, account.type, if (account.password != null) "<set>" else "-",
            });
        }
        return;
    }
    if (std.mem.eql(u8, name, "gnssCollectData.db")) {
        std.debug.print("  GnssCollectData table: {}\n", .{databases.hasTable(path_z, "GnssCollectData")});
        var sessions: std.ArrayList(databases.GnssSession) = .empty;
        databases.readGnss(arena, path_z, &sessions) catch |err| {
            std.debug.print("  read failed: {t}\n", .{err});
            return;
        };
        std.debug.print("  sessions: {d}\n", .{sessions.items.len});
        for (sessions.items, 0..) |session, index| {
            if (index >= 5) break;
            std.debug.print("  session {d} start={any} ttff={any}\n", .{ session.session_id, session.start_time, session.ttff });
        }
        return;
    }
    std.debug.print("  (no probe for {s})\n", .{name});
}
