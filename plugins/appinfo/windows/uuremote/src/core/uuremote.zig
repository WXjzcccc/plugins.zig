//! Evidence collectors over GameViewer (UU远程) configuration files.
//!
//! Every collector takes an already-parsed INI document (or a JSON buffer)
//! and turns it into plain structs; the plugin layer owns classification,
//! merging and record emission. All returned strings are duped into the
//! caller's allocator — in practice the run arena, so they live as long as
//! the run.
//!
//! Encrypted values are deliberately *not* decoded:
//! - `remote_assist_code.ini` stores the assist code as a Windows DPAPI
//!   blob (`AQAAANCMnd8…`) — recorded as "configured", content skipped.
//! - `.slog` logs are an encrypted format — see `slogname.zig` for what the
//!   file names still prove.
//! - The user-facing numeric device id (e.g. 398918340) does not appear in
//!   any plaintext artifact; only the internal 16-character identifiers are
//!   recoverable.

const std = @import("std");
const ini = @import("ini_zig");
const jwt = @import("jwt.zig");

const Allocator = std.mem.Allocator;

/// The internal identifier shape GameViewer uses for devices and user ids:
/// 16 lowercase-alphanumeric characters.
pub fn isInternalId(text: []const u8) bool {
    if (text.len != 16) return false;
    for (text) |c| {
        if (!std.ascii.isAlphanumeric(c)) return false;
    }
    // The ids seen in the wild are lowercase; an all-digit string is not one.
    if (!std.ascii.isLower(text[0]) and !std.ascii.isDigit(text[0])) return false;
    return true;
}

/// Whether a millisecond value is a plausible wall-clock timestamp
/// (2001-09..2033-05). Guards against counters misread as timestamps.
pub fn plausibleMillis(ms: i64) bool {
    return ms >= 1_000_000_000_000 and ms <= 2_000_000_000_000;
}

/// Whether a second value is a plausible wall-clock timestamp.
pub fn plausibleSeconds(s: i64) bool {
    return s >= 1_000_000_000 and s <= 2_000_000_000;
}

// ---------------------------------------------------------------- account

/// The account recorded in `user_info.ini`, enriched from the JWT payload.
pub const Account = struct {
    user_id: ?[]const u8 = null,
    device_id: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    system_id: ?[]const u8 = null,
    login_ip: ?[]const u8 = null,
    credential_id: ?[]const u8 = null,
    issued_at: ?i64 = null,
    /// Whether the JWT payload decoded at all.
    token_decoded: bool = false,
};

/// Reads `user_info.ini` content. Returns null when the text is not a
/// user_info file (no deviceId/token under `[General]`).
pub fn collectAccount(alloc: Allocator, doc: *const ini.Document) Allocator.Error!?Account {
    const device_id = doc.get("General", "deviceId") orelse return null;
    const token = doc.get("General", "token") orelse return null;
    if (device_id.len == 0 or token.len == 0) return null;

    var account = Account{ .device_id = try alloc.dupe(u8, device_id) };
    if (doc.get("General", "userId")) |user_id| {
        if (user_id.len > 0) account.user_id = try alloc.dupe(u8, user_id);
    }
    if (try jwt.decodePayload(alloc, token)) |claim| {
        account.token_decoded = true;
        if (claim.sub) |sub| {
            // The JWT's subject is the authoritative user id.
            if (account.user_id == null or !std.mem.eql(u8, account.user_id.?, sub)) {
                if (account.user_id) |old| alloc.free(old);
                account.user_id = sub;
            } else {
                alloc.free(sub);
            }
        }
        if (claim.device_id) |value| {
            alloc.free(value); // already taken from the ini; the ini is the file of record
        }
        account.client_id = claim.client_id;
        account.system_id = claim.system_id;
        account.login_ip = claim.ip;
        account.credential_id = claim.jti;
        account.issued_at = claim.issued_at;
    }
    return account;
}

/// The install uuid from `config.ini` (`[General] uuid=`), which fills the
/// account's client id when the JWT did not decode. Returns null when the
/// text is not a config file with a uuid.
pub fn collectInstallUuid(alloc: Allocator, doc: *const ini.Document) Allocator.Error!?[]const u8 {
    const uuid = doc.get("General", "uuid") orelse return null;
    if (uuid.len == 0 or doc.get("General", "deviceId") != null) return null;
    return try alloc.dupe(u8, uuid);
}

// ----------------------------------------------------------------- devices

/// One observation about a device, from any single source. The plugin
/// merges observations of the same id across sources.
pub const DeviceObs = struct {
    id: []const u8,
    /// From `[deviceslatest]`: the last time this account connected out.
    last_connect_ms: ?i64 = null,
    /// From `security.ini`: the privacy-screen prompt appeared for it.
    privacy_seen: bool = false,
    /// From `config/server/<id>.ini`: a per-device display config exists.
    server_config: bool = false,
    /// From `remote_assist_code.ini`: an assist code is configured (DPAPI).
    assist_configured: bool = false,
    assist_refreshed_ms: ?i64 = null,
    /// From `file_transfer/<id>.json`: a remote file listing is cached.
    transfer_cached: bool = false,
};

/// `[deviceslatest]` of the per-account `setting_<uid>.ini`: device id ->
/// last-connected timestamp (milliseconds).
pub fn collectLatestDevices(alloc: Allocator, doc: *const ini.Document) Allocator.Error![]DeviceObs {
    var out: std.ArrayList(DeviceObs) = .empty;
    errdefer out.deinit(alloc);
    const section = findSection(doc, "deviceslatest") orelse return &.{};
    for (section.entries) |entry| {
        if (!isInternalId(entry.key)) continue;
        const ms = std.fmt.parseInt(i64, entry.value, 10) catch continue;
        if (!plausibleMillis(ms)) continue;
        try out.append(alloc, .{
            .id = try alloc.dupe(u8, entry.key),
            .last_connect_ms = ms,
        });
    }
    return out.toOwnedSlice(alloc);
}

/// `security.ini`: sections named `privacy_screen_not_set_prompt_<id>` prove
/// a connection to that device happened (the prompt shows on first use).
pub fn collectPrivacyDevices(alloc: Allocator, doc: *const ini.Document) Allocator.Error![]DeviceObs {
    const prefix = "privacy_screen_not_set_prompt_";
    var out: std.ArrayList(DeviceObs) = .empty;
    errdefer out.deinit(alloc);
    for (doc.sections) |section| {
        if (!std.mem.startsWith(u8, section.name, prefix)) continue;
        const id = section.name[prefix.len..];
        if (!isInternalId(id)) continue;
        try out.append(alloc, .{ .id = try alloc.dupe(u8, id), .privacy_seen = true });
    }
    return out.toOwnedSlice(alloc);
}

/// `remote_assist_code.ini`: one section per local device with its assist
/// code settings. The `code`/`customize_code` values are DPAPI blobs and are
/// intentionally not interpreted. Sections without a code (the bare
/// per-device sections of other INI files match the same name shape) are
/// not evidence of an assist configuration and yield nothing.
pub fn collectAssistDevices(alloc: Allocator, doc: *const ini.Document) Allocator.Error![]DeviceObs {
    var out: std.ArrayList(DeviceObs) = .empty;
    errdefer out.deinit(alloc);
    for (doc.sections) |section| {
        if (!isInternalId(section.name)) continue;
        if (section.entries.len == 0) continue;
        var obs = DeviceObs{ .id = try alloc.dupe(u8, section.name), .assist_configured = false };
        for (section.entries) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key, "code") or
                std.ascii.eqlIgnoreCase(entry.key, "customize_code"))
            {
                obs.assist_configured = true;
            } else if (std.ascii.eqlIgnoreCase(entry.key, "last_refresh_time")) {
                const s = std.fmt.parseInt(i64, entry.value, 10) catch continue;
                if (plausibleSeconds(s)) obs.assist_refreshed_ms = s * 1000;
            }
        }
        if (!obs.assist_configured) {
            alloc.free(obs.id);
            continue;
        }
        try out.append(alloc, obs);
    }
    return out.toOwnedSlice(alloc);
}

// ---------------------------------------------------------- file transfer

/// One cached entry of a remote device's file listing (from
/// `file_transfer/<device>.json`).
pub const TransferEntry = struct {
    display_name: []const u8,
    path: []const u8,
    type_name: []const u8,
    modified_ms: ?i64 = null,
};

/// Parses the cached remote listing. Returns null when the buffer is not a
/// JSON array of entries.
pub fn collectTransferEntries(alloc: Allocator, bytes: []const u8) Allocator.Error!?[]TransferEntry {
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch return null;
    defer parsed.deinit();
    const items = switch (parsed.value) {
        .array => |items| items,
        else => return null,
    };

    var out: std.ArrayList(TransferEntry) = .empty;
    errdefer out.deinit(alloc);
    for (items.items) |item| {
        const object = switch (item) {
            .object => |map| map,
            else => continue,
        };
        const path = jsonText(object.get("filePath")) orelse continue;
        try out.append(alloc, .{
            .display_name = try alloc.dupe(u8, jsonText(object.get("displayName")) orelse ""),
            .path = try alloc.dupe(u8, path),
            .type_name = try alloc.dupe(u8, jsonText(object.get("typeName")) orelse ""),
            .modified_ms = jsonTimestamp(object.get("modifiedTimestamp")),
        });
    }
    return try out.toOwnedSlice(alloc);
}

/// The device id of a `file_transfer/<id>.json` or `<id>_list.json` name.
pub fn transferDeviceId(name: []const u8) ?[]const u8 {
    var stem = name;
    if (std.ascii.endsWithIgnoreCase(stem, ".json")) stem = stem[0 .. stem.len - 5];
    if (std.ascii.endsWithIgnoreCase(stem, "_list")) stem = stem[0 .. stem.len - 5];
    if (!isInternalId(stem)) return null;
    return stem;
}

// --------------------------------------------------------------- upgrades

/// One row of `upgrade/upgrade.ini`: a version the updater discovered and
/// (tried to) install.
pub const Upgrade = struct {
    version: []const u8,
    status: ?i64 = null,
    previous_version: ?[]const u8 = null,
    discovered_ms: ?i64 = null,
    update_type: ?[]const u8 = null,
    subtitle: ?[]const u8 = null,
    install_path: ?[]const u8 = null,
    download_url: ?[]const u8 = null,
    md5: ?[]const u8 = null,
    error_message: ?[]const u8 = null,
};

/// A `4.39.2.1561`-shaped section header.
fn isVersionSection(name: []const u8) bool {
    var groups: usize = 0;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 6) return false;
        for (part) |c| {
            if (!std.ascii.isDigit(c)) return false;
        }
        groups += 1;
    }
    return groups >= 3 and groups <= 4;
}

/// Parses `upgrade/upgrade.ini`. Returns null when no section looks like an
/// upgrade record.
pub fn collectUpgrades(alloc: Allocator, doc: *const ini.Document) Allocator.Error!?[]Upgrade {
    var found = false;
    for (doc.sections) |section| {
        if (isVersionSection(section.name) and section.entries.len > 0) {
            found = true;
            break;
        }
    }
    if (!found) return null;

    var out: std.ArrayList(Upgrade) = .empty;
    errdefer out.deinit(alloc);
    for (doc.sections) |section| {
        if (!isVersionSection(section.name) or section.entries.len == 0) continue;
        var upgrade = Upgrade{ .version = try alloc.dupe(u8, section.name) };
        for (section.entries) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key, "status")) {
                upgrade.status = std.fmt.parseInt(i64, entry.value, 10) catch null;
            } else if (std.ascii.eqlIgnoreCase(entry.key, "previousversion")) {
                if (entry.value.len > 0) upgrade.previous_version = try alloc.dupe(u8, entry.value);
            } else if (std.ascii.eqlIgnoreCase(entry.key, "first_discovered_timestamp")) {
                const ms = std.fmt.parseInt(i64, entry.value, 10) catch continue;
                if (plausibleMillis(ms)) upgrade.discovered_ms = ms;
            } else if (std.ascii.eqlIgnoreCase(entry.key, "update_type")) {
                if (entry.value.len > 0) upgrade.update_type = try alloc.dupe(u8, entry.value);
            } else if (std.ascii.eqlIgnoreCase(entry.key, "subtitle")) {
                if (entry.value.len > 0) upgrade.subtitle = try alloc.dupe(u8, entry.value);
            } else if (std.ascii.eqlIgnoreCase(entry.key, "installfilepath")) {
                if (entry.value.len > 0) upgrade.install_path = try alloc.dupe(u8, entry.value);
            } else if (std.ascii.eqlIgnoreCase(entry.key, "url")) {
                if (entry.value.len > 0) upgrade.download_url = try alloc.dupe(u8, entry.value);
            } else if (std.ascii.eqlIgnoreCase(entry.key, "md5")) {
                if (entry.value.len > 0) upgrade.md5 = try alloc.dupe(u8, entry.value);
            } else if (std.ascii.eqlIgnoreCase(entry.key, "errormsg")) {
                if (entry.value.len > 0) upgrade.error_message = try alloc.dupe(u8, entry.value);
            }
        }
        try out.append(alloc, upgrade);
    }
    return try out.toOwnedSlice(alloc);
}

// -------------------------------------------------------------- telemetry

/// One Sentry `session.json`: a component's telemetry run.
pub const Telemetry = struct {
    release: ?[]const u8 = null,
    environment: ?[]const u8 = null,
    user_id: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    status: ?[]const u8 = null,
    started: ?[]const u8 = null,
    errors: ?i64 = null,
};

/// Parses a Sentry `session.json`. Returns null when the buffer is not one.
pub fn collectTelemetry(alloc: Allocator, bytes: []const u8) Allocator.Error!?Telemetry {
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch return null;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |map| map,
        else => return null,
    };
    if (object.get("sid") == null and object.get("started") == null) return null;

    var out = Telemetry{};
    out.user_id = try dupeJsonText(alloc, object.get("did"));
    out.session_id = try dupeJsonText(alloc, object.get("sid"));
    out.status = try dupeJsonText(alloc, object.get("status"));
    out.started = try dupeJsonText(alloc, object.get("started"));
    if (object.get("errors")) |value| {
        out.errors = switch (value) {
            .integer => |number| number,
            else => null,
        };
    }
    if (object.get("attrs")) |attrs| {
        if (attrs == .object) {
            out.release = try dupeJsonText(alloc, attrs.object.get("release"));
            out.environment = try dupeJsonText(alloc, attrs.object.get("environment"));
        }
    }
    return out;
}

// ---------------------------------------------------------------- helpers

fn findSection(doc: *const ini.Document, name: []const u8) ?*const ini.Section {
    for (doc.sections) |*section| {
        if (std.ascii.eqlIgnoreCase(section.name, name)) return section;
    }
    return null;
}

fn jsonText(value: ?std.json.Value) ?[]const u8 {
    return switch (value orelse return null) {
        .string => |text| text,
        else => null,
    };
}

fn dupeJsonText(alloc: Allocator, value: ?std.json.Value) Allocator.Error!?[]const u8 {
    const text = jsonText(value) orelse return null;
    if (text.len == 0) return null;
    return try alloc.dupe(u8, text);
}

/// `modifiedTimestamp` fields are second counts as strings; "0" means never.
fn jsonTimestamp(value: ?std.json.Value) ?i64 {
    const text = jsonText(value) orelse return null;
    const s = std.fmt.parseInt(i64, text, 10) catch return null;
    if (!plausibleSeconds(s)) return null;
    return s * 1000;
}

/// Frees a device list returned by one of the collectors.
pub fn freeDevices(alloc: Allocator, devices: []const DeviceObs) void {
    for (devices) |device| alloc.free(device.id);
    alloc.free(devices);
}

/// Frees a transfer-entry list returned by `collectTransferEntries`.
pub fn freeTransferEntries(alloc: Allocator, entries: []const TransferEntry) void {
    for (entries) |entry| {
        alloc.free(entry.display_name);
        alloc.free(entry.path);
        alloc.free(entry.type_name);
    }
    alloc.free(entries);
}

/// Frees an upgrade list returned by `collectUpgrades`.
pub fn freeUpgrades(alloc: Allocator, upgrades: []const Upgrade) void {
    for (upgrades) |upgrade| {
        alloc.free(upgrade.version);
        inline for (.{ "previous_version", "update_type", "subtitle", "install_path", "download_url", "md5", "error_message" }) |field| {
            if (@field(upgrade, field)) |value| alloc.free(value);
        }
    }
    alloc.free(upgrades);
}

const testing = std.testing;

const user_info_ini =
    \\[General]
    \\deviceId=dev0000000000001
    \\token=eyJhbGciOiJIUzI1NiIsImtpZCI6InYyIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzg0Mjc0Mjk4LCJqdGkiOiJkMGUxMTkwOS0wMDAwIiwiZGV2aWNlX2lkIjoiZGV2YWJjIiwiY2xpZW50X2lkIjoiY2xpZW50LXV1aWQiLCJzeXN0ZW1faWQiOiJzeXMtMTIzIiwiaXAiOiIxMTQuMjMzLjE1My41OCJ9.sig
    \\userId=user123
;

test "collects the account from user_info.ini and its JWT" {
    const doc = try ini.parse(testing.allocator, user_info_ini);
    defer doc.deinit(testing.allocator);
    const account = (try collectAccount(testing.allocator, &doc)).?;
    defer {
        if (account.user_id) |v| testing.allocator.free(v);
        if (account.device_id) |v| testing.allocator.free(v);
        if (account.client_id) |v| testing.allocator.free(v);
        if (account.system_id) |v| testing.allocator.free(v);
        if (account.login_ip) |v| testing.allocator.free(v);
        if (account.credential_id) |v| testing.allocator.free(v);
    }
    try testing.expectEqualStrings("user123", account.user_id.?);
    try testing.expectEqualStrings("dev0000000000001", account.device_id.?);
    try testing.expect(account.token_decoded);
    try testing.expectEqualStrings("client-uuid", account.client_id.?);
    try testing.expectEqualStrings("114.233.153.58", account.login_ip.?);
    try testing.expectEqual(@as(i64, 1784274298), account.issued_at.?);
}

test "install uuid only from config.ini, not user_info.ini" {
    const config = try ini.parse(testing.allocator,
        \\[General]
        \\uuid=e63d9c4b-8bdc-46ab-9001-084eaca29964
        \\auto_run=1
    );
    defer config.deinit(testing.allocator);
    const uuid = (try collectInstallUuid(testing.allocator, &config)).?;
    defer testing.allocator.free(uuid);
    try testing.expectEqualStrings("e63d9c4b-8bdc-46ab-9001-084eaca29964", uuid);

    const user_file = try ini.parse(testing.allocator, user_info_ini);
    defer user_file.deinit(testing.allocator);
    try testing.expect(try collectInstallUuid(testing.allocator, &user_file) == null);
}

test "collects deviceslatest, privacy prompts and assist settings" {
    const setting = try ini.parse(testing.allocator,
        \\[deviceslatest]
        \\remote0000000001=1791980872063
        \\remote0000000002=1790500088753
        \\notadevice=1
        \\
        \\[remote0000000001]
        \\quality=3
    );
    defer setting.deinit(testing.allocator);
    const latest = try collectLatestDevices(testing.allocator, &setting);
    defer freeDevices(testing.allocator, latest);
    try testing.expectEqual(@as(usize, 2), latest.len);
    try testing.expectEqualStrings("remote0000000001", latest[0].id);
    try testing.expectEqual(@as(i64, 1791980872063), latest[0].last_connect_ms.?);

    const security = try ini.parse(testing.allocator,
        \\[privacy_screen_not_set_prompt_remote0000000001]
        \\connection_seen=1
        \\[privacy_screen_not_set_prompt_short]
        \\connection_seen=1
    );
    defer security.deinit(testing.allocator);
    const privacy = try collectPrivacyDevices(testing.allocator, &security);
    defer freeDevices(testing.allocator, privacy);
    try testing.expectEqual(@as(usize, 1), privacy.len);
    try testing.expect(privacy[0].privacy_seen);

    const assist = try ini.parse(testing.allocator,
        \\[dev0000000000001]
        \\code=AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA...
        \\refresh_type=6
        \\last_refresh_time=1788356451
        \\enable_remote=1
    );
    defer assist.deinit(testing.allocator);
    const assists = try collectAssistDevices(testing.allocator, &assist);
    defer freeDevices(testing.allocator, assists);
    try testing.expectEqual(@as(usize, 1), assists.len);
    try testing.expect(assists[0].assist_configured);
    try testing.expect(assists[0].assist_refreshed_ms != null);
}

test "collects transfer entries and validates device file names" {
    const json_text =
        \\[{"displayName":"桌面","filePath":"C:\\Users\\admin\\Desktop","fileType":0,
        \\"iconType":"desktop","modifiedTimestamp":"1788580675","typeName":"folder"},
        \\{"displayName":"Windows (C:)","filePath":"C:","fileType":2,
        \\"iconType":"disk","modifiedTimestamp":"0","typeName":"disk"}]
    ;
    const entries = (try collectTransferEntries(testing.allocator, json_text)).?;
    defer freeTransferEntries(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("C:\\Users\\admin\\Desktop", entries[0].path);
    try testing.expectEqualStrings("桌面", entries[0].display_name);
    try testing.expectEqual(@as(i64, 1788580675_000), entries[0].modified_ms.?);
    try testing.expect(entries[1].modified_ms == null);

    try testing.expectEqualStrings("remote0000000001", transferDeviceId("remote0000000001.json").?);
    try testing.expectEqualStrings("remote0000000001", transferDeviceId("remote0000000001_list.json").?);
    try testing.expect(transferDeviceId("config.json") == null);
}

test "collects upgrade rows" {
    const doc = try ini.parse(testing.allocator,
        \\[public]
        \\starttimestamp=1789555364163
        \\
        \\[4.39.2.1561]
        \\status=3
        \\installfilepath=E:/wyyc/GameViewer/setup/UURemote_Setup_4.39.2.1561.exe
        \\subtitle=\x4fee\x590d\x5df2\x77e5\x95ee\x9898
        \\errormsg=CreateProcessAsUser: 2
        \\previousversion=4.39.0.1331
        \\update_type=UpdateDaily
        \\first_discovered_timestamp=1788870169445
        \\
        \\[4.41.0.2311]
        \\status=0
        \\md5=AB36603436AF8A60D5D04AAC6AF1FEEE
    );
    defer doc.deinit(testing.allocator);
    const upgrades = (try collectUpgrades(testing.allocator, &doc)).?;
    defer freeUpgrades(testing.allocator, upgrades);
    try testing.expectEqual(@as(usize, 2), upgrades.len);
    try testing.expectEqualStrings("4.39.2.1561", upgrades[0].version);
    try testing.expectEqual(@as(i64, 3), upgrades[0].status.?);
    try testing.expectEqualStrings("修复已知问题", upgrades[0].subtitle.?);
    try testing.expectEqual(@as(i64, 1788870169445), upgrades[0].discovered_ms.?);
    try testing.expectEqualStrings("4.39.0.1331", upgrades[0].previous_version.?);
    try testing.expectEqualStrings("AB36603436AF8A60D5D04AAC6AF1FEEE", upgrades[1].md5.?);
}

test "collects telemetry sessions" {
    const json_text =
        \\{"init":true,"sid":"b8a05464-0000","status":"ok","did":"user000000000001",
        \\"errors":0,"started":"2026-10-24T03:10:15.855Z","duration":0,
        \\"attrs":{"release":"4.41.0","environment":"healthd_prod"}}
    ;
    const telemetry = (try collectTelemetry(testing.allocator, json_text)).?;
    defer {
        if (telemetry.release) |v| testing.allocator.free(v);
        if (telemetry.environment) |v| testing.allocator.free(v);
        if (telemetry.user_id) |v| testing.allocator.free(v);
        if (telemetry.session_id) |v| testing.allocator.free(v);
        if (telemetry.status) |v| testing.allocator.free(v);
        if (telemetry.started) |v| testing.allocator.free(v);
    }
    try testing.expectEqualStrings("4.41.0", telemetry.release.?);
    try testing.expectEqualStrings("user000000000001", telemetry.user_id.?);
    try testing.expectEqualStrings("2026-10-24T03:10:15.855Z", telemetry.started.?);
    try testing.expectEqual(@as(i64, 0), telemetry.errors.?);

    try testing.expect(try collectTelemetry(testing.allocator, "[1,2]") == null);
    try testing.expect(try collectTelemetry(testing.allocator, "not json") == null);
}

test "internal id shape checks" {
    try testing.expect(isInternalId("remote0000000001"));
    try testing.expect(isInternalId("user000000000001"));
    try testing.expect(!isInternalId("remote000000000"));
    try testing.expect(!isInternalId("remote0000000001x"));
    try testing.expect(!isInternalId("REMOTE000000001"));
    try testing.expect(!isInternalId("privacy_screen_no"));
}
