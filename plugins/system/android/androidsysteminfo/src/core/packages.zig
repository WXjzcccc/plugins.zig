//! Installed-package records from `/data/system/packages.xml` (ABX) and the
//! `/data/system/packages.list` line format.
//!
//! packages.xml is the package manager's authoritative database: one
//! `<package>` element per package with the install metadata, plus a
//! `<perms>` child listing every granted runtime permission. packages.list
//! is the coarser per-line dump (`name uid debugFlag dataDir seinfo ...`);
//! it fills in the data directory and seinfo that packages.xml does not
//! carry, and stands in when the XML cannot be parsed.

const std = @import("std");
const abx = @import("abx.zig");

/// One installed package.
pub const Package = struct {
    package: []const u8,
    uid: ?i64 = null,
    version_code: ?i64 = null,
    code_path: ?[]const u8 = null,
    data_dir: ?[]const u8 = null,
    seinfo: ?[]const u8 = null,
    installer: ?[]const u8 = null,
    install_initiator: ?[]const u8 = null,
    primary_abi: ?[]const u8 = null,
    shared_user: ?[]const u8 = null,
    system: bool = false,
    privileged: bool = false,
    debuggable: bool = false,
    orphaned: bool = false,
    /// `ft` / `ut` in packages.xml: epoch milliseconds (hex-encoded on the
    /// wire, decoded by the ABX parser).
    first_install_ms: ?i64 = null,
    last_update_ms: ?i64 = null,
};

/// One granted permission of one package.
pub const Permission = struct {
    package: []const u8,
    name: []const u8,
    granted: bool,
};

/// Device-level facts from the packages.xml root: the framework's own
/// `<version>` elements carry the SDK level, database version and the
/// fingerprint of each storage volume.
pub const RootFact = struct {
    item: []const u8,
    value: []const u8,
};

/// Parses packages.xml. `packages` and `permissions` are appended to; the
/// caller owns the lists' memory (they live in the arena).
pub fn parseXml(
    arena: std.mem.Allocator,
    bytes: []const u8,
    packages: *std.ArrayList(Package),
    permissions: *std.ArrayList(Permission),
    facts: *std.ArrayList(RootFact),
) abx.Error!void {
    const root = try abx.parse(arena, bytes);

    // Root facts: sdkVersion/databaseVersion sit on the <version> children,
    // one per storage volume; the root also has a fingerprint attribute on
    // older versions. Render every scalar attribute of each <version>.
    for (root.children) |child| {
        if (!std.mem.eql(u8, child.name, "version")) continue;
        for (child.attributes) |attribute| {
            const rendered = child.attrText(arena, attribute.name) catch continue;
            const value = rendered orelse continue;
            const item = try std.fmt.allocPrint(arena, "{s}", .{attribute.name});
            try facts.append(arena, .{ .item = item, .value = value });
        }
    }

    // Packages live in a <packages> child (or directly under the root on
    // some versions): walk everything named "package".
    try collectPackages(arena, root, packages, permissions);
}

fn collectPackages(
    arena: std.mem.Allocator,
    node: *const abx.Node,
    packages: *std.ArrayList(Package),
    permissions: *std.ArrayList(Permission),
) abx.Error!void {
    for (node.children) |child| {
        if (std.mem.eql(u8, child.name, "package")) {
            try appendPackage(arena, child, packages, permissions);
        }
        try collectPackages(arena, child, packages, permissions);
    }
}

fn appendPackage(
    arena: std.mem.Allocator,
    node: *const abx.Node,
    packages: *std.ArrayList(Package),
    permissions: *std.ArrayList(Permission),
) abx.Error!void {
    const name = node.attrText(arena, "name") catch return error.OutOfMemory;
    if (name == null or name.?.len == 0) return;
    const package_name = name.?;

    // ApplicationInfo flags carried in publicFlags: 1 = SYSTEM,
    // 2 = DEBUGGABLE. privateFlags bit 23 = PRIVILEGED. Both attributes are
    // 32-bit values stored as signed longs on the wire; truncate to the low
    // 32 bits before interpreting the flag bits.
    const public_flags: u32 = @bitCast(@as(i32, @truncate(node.attrLong("publicFlags") orelse 0)));
    const private_flags: u32 = @bitCast(@as(i32, @truncate(node.attrLong("privateFlags") orelse 0)));

    var package = Package{
        .package = package_name,
        .uid = node.attrLong("userId") orelse node.attrLong("sharedUserId"),
        .version_code = node.attrLong("version"),
        .code_path = node.attrText(arena, "codePath") catch null,
        .installer = node.attrText(arena, "installer") catch null,
        .install_initiator = node.attrText(arena, "installInitiator") catch null,
        .primary_abi = node.attrText(arena, "primaryCpuAbi") catch null,
        .shared_user = node.attrText(arena, "sharedUser") catch null,
        .system = public_flags & 1 != 0,
        .debuggable = public_flags & 2 != 0,
        .privileged = private_flags & (1 << 23) != 0,
        .orphaned = node.attrBool("isOrphaned") orelse false,
        .first_install_ms = node.attrLong("ft"),
        .last_update_ms = node.attrLong("ut"),
    };
    // `sharedUser` on the element is a name only on old versions; newer ones
    // reference `sharedUserId` (a numeric uid).
    if (package.shared_user == null) {
        if (node.attrLong("sharedUserId")) |uid| {
            package.shared_user = std.fmt.allocPrint(arena, "{d}", .{uid}) catch null;
        }
    }
    try packages.append(arena, package);

    // Granted permissions: <perms><item name="..." granted="true" .../>.
    if (node.child("perms")) |perms| {
        for (perms.children) |item| {
            if (!std.mem.eql(u8, item.name, "item")) continue;
            const permission_name = item.attrText(arena, "name") catch null;
            if (permission_name == null) continue;
            const granted = item.attr("granted") != null and switch (item.attr("granted").?) {
                .boolean => |boolean| boolean,
                .string => |text| std.ascii.eqlIgnoreCase(text, "true"),
                else => false,
            };
            try permissions.append(arena, .{
                .package = package_name,
                .name = permission_name.?,
                .granted = granted,
            });
        }
    }
}

/// One line of packages.list, best effort: the column layout gained columns
/// over Android versions; the first five are stable.
pub const ListEntry = struct {
    package: []const u8,
    uid: ?i64 = null,
    data_dir: ?[]const u8 = null,
    seinfo: ?[]const u8 = null,
    version_code: ?i64 = null,
};

/// Parses one packages.list line; null for blank/malformed lines.
pub fn parseListLine(line: []const u8) ?ListEntry {
    var parts = std.mem.tokenizeAny(u8, line, " \t");
    const name = parts.next() orelse return null;
    if (name.len == 0) return null;
    var entry = ListEntry{ .package = name };
    const uid_text = parts.next() orelse return entry;
    entry.uid = std.fmt.parseInt(i64, uid_text, 10) catch null;
    _ = parts.next(); // debugFlag
    entry.data_dir = parts.next();
    entry.seinfo = parts.next();
    _ = parts.next(); // gids (may be "none")
    _ = parts.next(); // newer columns; column 7 carries the version code
    if (parts.next()) |version_text| {
        entry.version_code = std.fmt.parseInt(i64, version_text, 10) catch null;
    }
    return entry;
}

const testing = std.testing;

test "parses packages.list lines" {
    const entry = parseListLine(
        "com.miui.screenrecorder 1000 0 /data/user/0/com.miui.screenrecorder platform:privapp:targetSdkVersion=29 2001,1065 0 31206091 1 @null",
    ).?;
    try testing.expectEqualStrings("com.miui.screenrecorder", entry.package);
    try testing.expectEqual(@as(?i64, 1000), entry.uid);
    try testing.expectEqualStrings("/data/user/0/com.miui.screenrecorder", entry.data_dir.?);
    try testing.expectEqualStrings("platform:privapp:targetSdkVersion=29", entry.seinfo.?);
    try testing.expectEqual(@as(?i64, 31206091), entry.version_code);
    try testing.expect(parseListLine("") == null);
}

test "parses a small packages.xml" {
    var writer = @import("abx_test_helper.zig").Writer{};
    defer writer.deinit();
    try writer.out.appendSlice(testing.allocator, &@import("abx_test_helper.zig").magic);
    try writer.document();
    try writer.startTag("packages");
    try writer.startTag("version");
    try writer.attrInt("sdkVersion", 33);
    try writer.attrLong("databaseVersion", 47);
    try writer.endTag("version");
    try writer.startTag("package");
    try writer.attrString("name", "com.example.app");
    try writer.attrInt("userId", 10117);
    try writer.attrInt("version", 20624);
    try writer.attrString("codePath", "/data/app/~~x/com.example.app-y");
    try writer.attrString("installer", "com.xiaomi.market");
    try writer.attrLongHex("ft", 1776094875288);
    try writer.attrBool("isOrphaned", true);
    try writer.startTag("perms");
    try writer.startTag("item");
    try writer.attrString("name", "android.permission.INTERNET");
    try writer.attrBool("granted", true);
    try writer.endTag("item");
    try writer.startTag("item");
    try writer.attrString("name", "android.permission.CAMERA");
    try writer.attrBool("granted", false);
    try writer.endTag("item");
    try writer.endTag("perms");
    try writer.endTag("package");
    try writer.endTag("packages");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    var packages: std.ArrayList(Package) = .empty;
    var permissions: std.ArrayList(Permission) = .empty;
    var facts: std.ArrayList(RootFact) = .empty;
    try parseXml(alloc, writer.out.items, &packages, &permissions, &facts);

    try testing.expectEqual(@as(usize, 1), packages.items.len);
    const package = packages.items[0];
    try testing.expectEqualStrings("com.example.app", package.package);
    try testing.expectEqual(@as(?i64, 10117), package.uid);
    try testing.expectEqual(@as(?i64, 20624), package.version_code);
    try testing.expectEqualStrings("com.xiaomi.market", package.installer.?);
    try testing.expectEqual(@as(?i64, 1776094875288), package.first_install_ms);
    try testing.expect(package.orphaned);
    try testing.expect(!package.system);

    try testing.expectEqual(@as(usize, 2), permissions.items.len);
    try testing.expect(permissions.items[0].granted);
    try testing.expect(!permissions.items[1].granted);

    var sdk_found = false;
    for (facts.items) |fact| {
        if (std.mem.eql(u8, fact.item, "sdkVersion")) {
            try testing.expectEqualStrings("33", fact.value);
            sdk_found = true;
        }
    }
    try testing.expect(sdk_found);
}
