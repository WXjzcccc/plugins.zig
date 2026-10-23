//! The four collectors of the Windows registry analysis: system information,
//! network adapters, user accounts and the default browser.
//!
//! Port of ForensicsTool's `analyzers/winreg/winRegAnalyzer.go`, section by
//! section. Hive paths are root-relative (`regf` addresses keys from the root
//! key's children), which is why the SAM paths here start at `Domains` while
//! the original opened `SAM\Domains\Account`.

const std = @import("std");
const hive_mod = @import("hive.zig");
const bootkey = @import("bootkey.zig");
const sam = @import("sam.zig");

const Allocator = std.mem.Allocator;
const Hive = hive_mod.Hive;

// ---------------------------------------------------------------------------
// System information
// ---------------------------------------------------------------------------

pub const SystemItem = struct {
    item: []const u8,
    /// Text value; set when `timestamp` is not.
    value: []const u8 = "",
    /// Unix seconds; set for the date items.
    timestamp: ?i64 = null,
};

/// Collects the system information rows. The SOFTWARE hive is required (as in
/// the original); items that live in SYSTEM degrade to empty values.
pub fn collectSystemInfo(
    alloc: Allocator,
    system_hive: ?*Hive,
    software_hive: *Hive,
) error{OutOfMemory}![]SystemItem {
    const version_path = "Microsoft\\Windows NT\\CurrentVersion";
    var items: std.ArrayList(SystemItem) = .empty;

    // A `set` helper keeps the port close to the original's ordered rows.
    const Context = struct {
        alloc: Allocator,
        items: *std.ArrayList(SystemItem),
        system_hive: ?*Hive,
        software_hive: *Hive,

        fn put(self: @This(), item: []const u8, value: []const u8) !void {
            try self.items.append(self.alloc, .{ .item = item, .value = value });
        }
        fn putTime(self: @This(), item: []const u8, unix: ?i64) !void {
            try self.items.append(self.alloc, .{ .item = item, .timestamp = unix });
        }
        fn softwareString(self: @This(), path: []const u8, name: []const u8) ![]const u8 {
            return (try self.software_hive.stringValue(path, name, self.alloc)) orelse "";
        }
        fn systemString(self: @This(), path: []const u8, name: []const u8) ![]const u8 {
            const hive = self.system_hive orelse return "";
            return (try hive.stringValue(path, name, self.alloc)) orelse "";
        }
    };

    const ctx = Context{ .alloc = alloc, .items = &items, .system_hive = system_hive, .software_hive = software_hive };

    try ctx.put("Build信息", try ctx.softwareString(version_path, "BuildLabEx"));
    try ctx.put("Build版本", try ctx.softwareString(version_path, "CurrentBuildNumber"));
    try ctx.put("计算机名称", try computerName(alloc, system_hive));
    try ctx.put("版本信息", try ctx.softwareString(version_path, "EditionID"));
    const install_date = software_hive.dwordValue(version_path, "InstallDate");
    try ctx.putTime("安装时间(本地时区)", if (install_date) |seconds| @as(i64, seconds) else null);
    try ctx.put("系统名称", try ctx.softwareString(version_path, "ProductName"));
    try ctx.put("发行ID", try ctx.softwareString(version_path, "ReleaseId"));
    try ctx.put("产品ID", try ctx.softwareString(version_path, "ProductId"));
    try ctx.put("注册所有者", try ctx.softwareString(version_path, "RegisteredOwner"));
    try ctx.put("注册组织", try ctx.softwareString(version_path, "RegisteredOrganization"));
    try ctx.put("系统时区", try timeZone(alloc, system_hive, software_hive));
    try ctx.putTime("最后一次正常关机时间(本地时区)", try lastShutdownTime(system_hive, alloc));
    const spkp_path = version_path ++ "\\SoftwareProtectionPlatform";
    if (software_hive.hasKey(spkp_path)) {
        try ctx.put("产品密钥备份(非当前密钥)", try ctx.softwareString(spkp_path, "BackupProductKeyDefault"));
    }
    try ctx.put("上次登录的用户", try ctx.softwareString(
        "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI",
        "LastLoggedOnUser",
    ));
    return items.toOwnedSlice(alloc);
}

/// `<ControlSet>\Control\ComputerName\ComputerName` → `ComputerName`.
fn computerName(alloc: Allocator, system_hive: ?*Hive) error{OutOfMemory}![]const u8 {
    const hive = system_hive orelse return "";
    const path = try std.fmt.allocPrint(alloc, "{s}\\Control\\ComputerName\\ComputerName", .{try bootkey.controlSetName(hive, alloc)});
    return (try hive.stringValue(path, "ComputerName", alloc)) orelse "";
}

/// The time zone display name: the key name from SYSTEM, the friendly name
/// from the SOFTWARE time zones list.
fn timeZone(alloc: Allocator, system_hive: ?*Hive, software_hive: *Hive) error{OutOfMemory}![]const u8 {
    const hive = system_hive orelse return "";
    const path = try std.fmt.allocPrint(alloc, "{s}\\Control\\TimeZoneInformation", .{try bootkey.controlSetName(hive, alloc)});
    const key_name = (try hive.stringValue(path, "TimeZoneKeyName", alloc)) orelse return "";
    if (key_name.len == 0) return "";
    const zones = "Microsoft\\Windows NT\\CurrentVersion\\Time Zones";
    const zone_path = try std.fmt.allocPrint(alloc, "{s}\\{s}", .{ zones, key_name });
    return (try software_hive.stringValue(zone_path, "Display", alloc)) orelse "";
}

/// `ShutdownTime`, an 8-byte FILETIME in `<ControlSet>\Control\Windows`.
fn lastShutdownTime(system_hive: ?*Hive, alloc: Allocator) error{OutOfMemory}!?i64 {
    const hive = system_hive orelse return null;
    const path = try std.fmt.allocPrint(alloc, "{s}\\Control\\Windows", .{try bootkey.controlSetName(hive, alloc)});
    const raw = (try hive.binaryValue(path, "ShutdownTime", alloc)) orelse return null;
    if (raw.len < 8) return null;
    const filetime = std.mem.readInt(u64, raw[0..8], .little);
    if (filetime == 0) return null;
    return hive_mod.filetimeToUnix(filetime);
}

// ---------------------------------------------------------------------------
// Network adapters
// ---------------------------------------------------------------------------

pub const NetworkAdapter = struct {
    interface: []const u8,
    name: []const u8 = "",
    mac_current: []const u8 = "",
    mac_permanent: []const u8 = "",
    ip: []const u8 = "",
    netmask: []const u8 = "",
    gateway: []const u8 = "",
    dhcp_ip: []const u8 = "",
    dhcp_gateway: []const u8 = "",
    dhcp_server: []const u8 = "",
    /// Unix seconds, from the DHCP lease dwords.
    lease_obtained: ?i64 = null,
    lease_expires: ?i64 = null,
};

/// Collects one row per TCP/IP interface of the current control set.
pub fn collectNetwork(alloc: Allocator, system_hive: *Hive) error{OutOfMemory}![]NetworkAdapter {
    const control_set = try bootkey.controlSetName(system_hive, alloc);
    const interfaces_path = try std.fmt.allocPrint(
        alloc,
        "{s}\\Services\\Tcpip\\Parameters\\Interfaces",
        .{control_set},
    );
    // A missing or corrupt Interfaces key just means no adapters to report.
    const names = system_hive.subkeys(interfaces_path, alloc) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => &[_][]const u8{},
    };

    var adapters: std.ArrayList(NetworkAdapter) = .empty;
    for (names) |name| {
        var adapter = NetworkAdapter{ .interface = name };
        const interface_path = try std.fmt.allocPrint(alloc, "{s}\\{s}", .{ interfaces_path, name });
        const upper = try toUpper(alloc, name);

        const device_path = try std.fmt.allocPrint(
            alloc,
            "{s}\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{s}\\connection",
            .{ control_set, upper },
        );
        adapter.name = (try system_hive.stringValue(device_path, "Name", alloc)) orelse "";

        const kernel_path = try std.fmt.allocPrint(
            alloc,
            "{s}\\Control\\NetworkSetup2\\Interfaces\\{s}\\Kernel",
            .{ control_set, upper },
        );
        if (try system_hive.binaryValue(kernel_path, "CurrentAddress", alloc)) |raw| {
            adapter.mac_current = try macString(alloc, raw);
        }
        if (try system_hive.binaryValue(kernel_path, "PermanentAddress", alloc)) |raw| {
            adapter.mac_permanent = try macString(alloc, raw);
        }

        adapter.dhcp_ip = (try system_hive.stringValue(interface_path, "DhcpIPAddress", alloc)) orelse "";
        adapter.dhcp_gateway = try system_hive.firstMultiSz(interface_path, "DhcpDefaultGateway", alloc);
        adapter.dhcp_server = (try system_hive.stringValue(interface_path, "DhcpServer", alloc)) orelse "";
        adapter.lease_obtained = leaseTime(system_hive, interface_path, "LeaseObtainedTime");
        adapter.lease_expires = leaseTime(system_hive, interface_path, "LeaseTerminatesTime");
        adapter.ip = try system_hive.firstMultiSz(interface_path, "IPAddress", alloc);
        adapter.netmask = try system_hive.firstMultiSz(interface_path, "SubnetMask", alloc);
        adapter.gateway = try system_hive.firstMultiSz(interface_path, "DefaultGateway", alloc);
        try adapters.append(alloc, adapter);
    }
    return adapters.toOwnedSlice(alloc);
}

fn leaseTime(hive: *Hive, path: []const u8, name: []const u8) ?i64 {
    const seconds = hive.dwordValue(path, name) orelse return null;
    if (seconds == 0) return null;
    return @as(i64, seconds);
}

/// `aa:bb:cc:…` from raw address bytes.
fn macString(alloc: Allocator, bytes: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (bytes, 0..) |byte, index| {
        if (index != 0) try out.append(alloc, ':');
        try out.print(alloc, "{x:0>2}", .{byte});
    }
    return out.toOwnedSlice(alloc);
}

fn toUpper(alloc: Allocator, text: []const u8) error{OutOfMemory}![]const u8 {
    const out = try alloc.dupe(u8, text);
    for (out) |*char| char.* = std.ascii.toUpper(char.*);
    return out;
}

// ---------------------------------------------------------------------------
// User accounts
// ---------------------------------------------------------------------------

pub const UserInfo = struct {
    username: []const u8,
    full_name: []const u8 = "",
    comment: []const u8 = "",
    sid: []const u8 = "",
    /// The RID in the `%08x` form the account subkey is named by.
    rid: []const u8 = "",
    /// Decrypted NT hash in hex; the well-known empty-password constant; or
    /// "" when decryption was impossible.
    nt_hash: []const u8 = "",
    /// Unix seconds; null for "never".
    last_login: ?i64 = null,
    last_pwd_change: ?i64 = null,
    last_failed_login: ?i64 = null,
    logon_count: i32 = 0,
    invalid_logon_count: i32 = 0,
    user_attribute: u32 = 0,
};

/// Why NT hash decryption was not possible, for a single run warning.
pub const HashAvailability = union(enum) {
    available,
    no_system_hive,
    no_boot_key,
    boot_key_rejected,
    malformed_sam,
};

pub const UserReport = struct {
    users: []UserInfo,
    hashes: HashAvailability,
};

/// Collects the SAM user accounts. The SAM hive is required; the SYSTEM hive
/// only matters for hash decryption.
pub fn collectUsers(
    alloc: Allocator,
    system_hive: ?*Hive,
    sam_hive: *Hive,
) error{OutOfMemory}!UserReport {
    const account_path = "SAM\\Domains\\Account";
    const v_value = (try sam_hive.binaryValue(account_path, "V", alloc)) orelse
        return .{ .users = &.{}, .hashes = .malformed_sam };
    const f_value = (try sam_hive.binaryValue(account_path, "F", alloc)) orelse
        return .{ .users = &.{}, .hashes = .malformed_sam };
    const domain_f = sam.DomainF.parse(f_value) orelse
        return .{ .users = &.{}, .hashes = .malformed_sam };
    const sid_prefix = try sam.machineSid(v_value, alloc);

    // The user hash blobs follow the domain key data's scheme.
    const domain_is_aes = if (domain_f.key0) |key0| key0 == .aes else false;

    // Hash decryption state, prepared once.
    var hashed_boot_key: ?[16]u8 = null;
    var hashes: HashAvailability = .available;
    const boot_key: ?[16]u8 = if (system_hive) |hive| try bootkey.bootKey(hive, alloc) else null;
    if (boot_key == null) {
        hashes = if (system_hive == null) .no_system_hive else .no_boot_key;
    } else if (domain_f.key0) |key0| {
        hashed_boot_key = sam.hashedBootKey(alloc, key0, boot_key.?) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
        };
        if (hashed_boot_key == null) hashes = .boot_key_rejected;
    } else {
        hashes = .malformed_sam;
    }

    const names_path = try std.fmt.allocPrint(alloc, "{s}\\Users\\Names", .{account_path});
    const user_names = sam_hive.subkeys(names_path, alloc) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => &[_][]const u8{},
    };

    var users: std.ArrayList(UserInfo) = .empty;
    for (user_names) |user_name| {
        const name_path = try std.fmt.allocPrint(alloc, "{s}\\{s}", .{ names_path, user_name });
        // The default value of a name key carries the RID as its registry
        // type (the data is empty) — the same trick ForensicsTool uses.
        const rid = sam_hive.valueType(name_path, "") orelse continue;
        const rid_hex = try std.fmt.allocPrint(alloc, "{x:0>8}", .{rid});
        const account_key_path = try std.fmt.allocPrint(alloc, "{s}\\Users\\{s}", .{ account_path, rid_hex });

        var info = UserInfo{
            .username = user_name,
            .rid = rid_hex,
            .sid = try std.fmt.allocPrint(alloc, "{s}-{d}", .{ sid_prefix, rid }),
        };

        const user_f_raw = try sam_hive.binaryValue(account_key_path, "F", alloc);
        const user_v_raw = try sam_hive.binaryValue(account_key_path, "V", alloc);
        if (user_v_raw) |raw| {
            if (sam.UserV.parse(raw)) |user_v| {
                info.full_name = try user_v.fullName(alloc);
                info.comment = try user_v.comment(alloc);
            }
        }
        if (user_f_raw) |raw| {
            if (sam.UserF.parse(raw)) |user_f| {
                info.last_login = filetimeOrNull(user_f.last_login);
                info.last_pwd_change = filetimeOrNull(user_f.last_pwd_change);
                info.last_failed_login = filetimeOrNull(user_f.last_failed_login);
                info.logon_count = user_f.logon_count;
                info.invalid_logon_count = user_f.invalid_logon_count;
                info.user_attribute = user_f.user_attribute;
            }
        }
        if (user_v_raw) |raw| {
            if (sam.UserV.parse(raw)) |user_v| {
                const result = try sam.decryptNtHash(alloc, hashed_boot_key, rid, user_v.ntHash(domain_is_aes));
                switch (result) {
                    .hash => |hash| {
                        const hex = std.fmt.bytesToHex(hash, .lower);
                        info.nt_hash = try alloc.dupe(u8, &hex);
                    },
                    .empty => info.nt_hash = sam.DEFAULT_NT_HASH,
                    .unavailable => {},
                }
            }
        }
        try users.append(alloc, info);
    }
    return .{ .users = try users.toOwnedSlice(alloc), .hashes = hashes };
}

fn filetimeOrNull(filetime: u64) ?i64 {
    if (filetime == 0) return null;
    return hive_mod.filetimeToUnix(filetime);
}

// ---------------------------------------------------------------------------
// Default browser
// ---------------------------------------------------------------------------

/// The HTTP `UserChoice` ProgId of one NTUSER-class hive; null when the key
/// does not exist (e.g. USRCLASS.DAT, which the original also scans).
pub fn collectBrowser(alloc: Allocator, hive: *Hive) error{OutOfMemory}!?[]const u8 {
    const path = "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice";
    return hive.stringValue(path, "ProgId", alloc);
}

const testing = std.testing;

test "macString formats bytes with colons" {
    const out = try macString(testing.allocator, &.{ 0x00, 0x1a, 0xff });
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("00:1a:ff", out);
}

test "empty filetimes report as null" {
    try testing.expectEqual(@as(?i64, null), filetimeOrNull(0));
    try testing.expectEqual(@as(?i64, 0), filetimeOrNull(116_444_736_000_000_000));
}
