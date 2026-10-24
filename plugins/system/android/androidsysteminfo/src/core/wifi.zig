//! Wi-Fi configuration records from `/data/misc/apexdata/com.android.wifi/`:
//! `WifiConfigStore.xml` (saved networks) and `WifiConfigStoreSoftAp.xml`
//! (the hotspot configuration). Both are plain XML in the TypedXmlSerializer
//! shape handled by [`xml`].
//!
//! Saved networks carry the SSID, the security type, the preshared key in
//! cleartext and the last connect/disconnect times — the core existence
//! evidence of "this device has been on this network".

const std = @import("std");
const xml = @import("xml.zig");

/// One saved Wi-Fi network.
pub const Network = struct {
    /// The WifiConfiguration ConfigKey, e.g. `"OnePlus 9"WPA_PSK`.
    config_key: []const u8,
    /// SSID without the quotes.
    ssid: []const u8,
    security: []const u8,
    /// PreSharedKey without the quotes, when the network has one.
    preshared_key: ?[]const u8 = null,
    hidden: bool = false,
    shared: bool = true,
    auto_join: bool = true,
    /// WifiConfiguration.Status: 0 enabled, 1 current, 2 disabled.
    status: ?i64 = null,
    last_connected_ms: ?i64 = null,
    last_disconnected_ms: ?i64 = null,
    creator: ?[]const u8 = null,
    gateway_mac: ?[]const u8 = null,
};

/// One hotspot (SoftAp) configuration.
pub const SoftAp = struct {
    ssid: []const u8,
    security: []const u8,
    passphrase: ?[]const u8 = null,
    hidden: bool = false,
    auto_shutdown: bool = true,
};

pub const Error = xml.Error;

/// WifiConfiguration.SecurityParams security types (Android 13).
pub fn securityTypeName(type_id: i64) []const u8 {
    return switch (type_id) {
        0 => "OPEN",
        1 => "WEP",
        2 => "PSK",
        3 => "EAP",
        4 => "SAE",
        5 => "EAP_WPA3_ENTERPRISE_192BIT",
        6 => "OWE",
        7 => "WAPI_PSK",
        8 => "WAPI_CERT",
        9 => "EAP_WPA3_ENTERPRISE",
        10 => "OSEN",
        11 => "PASSPOINT_R1",
        12 => "PASSPOINT_R2",
        13 => "PASSPOINT_R3",
        else => "UNKNOWN",
    };
}

/// WifiConfiguration.Status names.
pub fn statusName(status: i64) []const u8 {
    return switch (status) {
        0 => "ENABLED",
        1 => "CURRENT",
        2 => "DISABLED",
        else => "UNKNOWN",
    };
}

/// SoftApConfiguration security types — a different enum from the client
/// side (1 is WPA2_PSK here, not WEP).
pub fn softApSecurityName(type_id: i64) []const u8 {
    return switch (type_id) {
        0 => "OPEN",
        1 => "WPA2_PSK",
        2 => "WPA3_SAE_TRANSITIONAL",
        3 => "WPA3_SAE",
        4 => "OWE_TRANSITIONAL",
        5 => "OWE",
        6 => "WAPI_PSK",
        7 => "WAPI_CERT",
        8 => "ENTERPRISE",
        9 => "DPP",
        else => "UNKNOWN",
    };
}

/// Strips one layer of double quotes Android puts around SSIDs and keys.
pub fn unquote(value: []const u8) []const u8 {
    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
        return value[1 .. value.len - 1];
    }
    return value;
}

/// Parses WifiConfigStore.xml; appends one record per `<Network>`.
pub fn parseConfigStore(arena: std.mem.Allocator, bytes: []const u8, networks: *std.ArrayList(Network)) Error!void {
    const root = try xml.parse(arena, bytes);
    const list = root.child("NetworkList") orelse return;
    for (list.children) |network_node| {
        const config = network_node.child("WifiConfiguration") orelse continue;
        var network = Network{
            .config_key = try arena.dupe(u8, text(config, "ConfigKey") orelse ""),
            .ssid = try arena.dupe(u8, unquote(text(config, "SSID") orelse "")),
            .security = try arena.dupe(u8, "OPEN"),
        };
        if (network.config_key.len == 0 and network.ssid.len == 0) continue;
        if (network.config_key.len == 0) {
            network.config_key = network.ssid;
        }

        // Security: the ConfigKey suffix names it for WPA-era networks;
        // SecurityParamsList is authoritative when present.
        if (config.child("SecurityParamsList")) |params| {
            var names: std.ArrayList(u8) = .empty;
            for (params.children) |param| {
                const type_id = int(param, "SecurityType") orelse continue;
                if (names.items.len > 0) try names.append(arena, ',');
                try names.appendSlice(arena, securityTypeName(type_id));
            }
            if (names.items.len > 0) network.security = names.items;
        } else if (std.mem.endsWith(u8, network.config_key, "WPA_PSK")) {
            network.security = "PSK";
        } else if (std.mem.endsWith(u8, network.config_key, "WPA2_PSK")) {
            network.security = "PSK";
        } else if (std.mem.endsWith(u8, network.config_key, "WEP")) {
            network.security = "WEP";
        } else if (std.mem.endsWith(u8, network.config_key, "EAP")) {
            network.security = "EAP";
        } else if (std.mem.endsWith(u8, network.config_key, "SAE")) {
            network.security = "SAE";
        }

        network.preshared_key = blk: {
            const raw = text(config, "PreSharedKey") orelse break :blk null;
            const unquoted = unquote(raw);
            if (unquoted.len == 0) break :blk null;
            break :blk try arena.dupe(u8, unquoted);
        };
        network.hidden = boolean(config, "HiddenSSID") orelse false;
        network.shared = boolean(config, "Shared") orelse true;
        network.auto_join = boolean(config, "AutoJoinEnabled") orelse true;
        network.status = int(config, "Status");
        network.last_connected_ms = long(config, "LastConnectedTime");
        network.last_disconnected_ms = long(config, "LastDisconnectedTime");
        network.creator = text(config, "CreatorName");
        network.gateway_mac = text(config, "DefaultGwMacAddress");
        try networks.append(arena, network);
    }
}

/// Parses WifiConfigStoreSoftAp.xml into the one hotspot configuration.
pub fn parseSoftAp(arena: std.mem.Allocator, bytes: []const u8) Error!?SoftAp {
    const root = try xml.parse(arena, bytes);
    const soft_ap = root.child("SoftAp") orelse return null;
    const ssid = unquote(text(soft_ap, "WifiSsid") orelse "");
    if (ssid.len == 0) return null;
    const security_type = int(soft_ap, "SecurityType") orelse 0;
    return .{
        .ssid = try arena.dupe(u8, ssid),
        .security = softApSecurityName(security_type),
        .passphrase = blk: {
            const raw = text(soft_ap, "Passphrase") orelse break :blk null;
            if (raw.len == 0) break :blk null;
            break :blk try arena.dupe(u8, raw);
        },
        .hidden = boolean(soft_ap, "HiddenSSID") orelse false,
        .auto_shutdown = boolean(soft_ap, "AutoShutdownEnabled") orelse true,
    };
}

/// The typed child `<type name="key">…</type>`: WifiConfigStore writes
/// TypedXmlSerializer output where the ELEMENT is the value's type and the
/// `name` attribute is the field key.
fn typedChild(node: *const xml.Node, element_type: []const u8, key: []const u8) ?*const xml.Node {
    for (node.children) |candidate| {
        if (!std.mem.eql(u8, candidate.name, element_type)) continue;
        const name = candidate.attr("name") orelse continue;
        if (std.mem.eql(u8, name, key)) return candidate;
    }
    return null;
}

/// The `<string name="X">text</string>` child's text, if any.
fn text(node: *const xml.Node, key: []const u8) ?[]const u8 {
    const child = typedChild(node, "string", key) orelse return null;
    if (child.text.len == 0) return null;
    return child.text;
}

/// The `<int name="X" value="N" />` child's value.
fn int(node: *const xml.Node, key: []const u8) ?i64 {
    const child = typedChild(node, "int", key) orelse return null;
    const value = child.attr("value") orelse return null;
    return std.fmt.parseInt(i64, std.mem.trim(u8, value, " "), 10) catch null;
}

/// The `<long name="X" value="N" />` child's value.
fn long(node: *const xml.Node, key: []const u8) ?i64 {
    const child = typedChild(node, "long", key) orelse return null;
    const value = child.attr("value") orelse return null;
    return std.fmt.parseInt(i64, std.mem.trim(u8, value, " "), 10) catch null;
}

/// The `<boolean name="X" value="true|false" />` child's value.
fn boolean(node: *const xml.Node, key: []const u8) ?bool {
    const child = typedChild(node, "boolean", key) orelse return null;
    const value = child.attr("value") orelse return null;
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return null;
}

const testing = std.testing;

const config_store_sample =
    \\<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
    \\<WifiConfigStoreData>
    \\<int name="Version" value="3" />
    \\<NetworkList>
    \\<Network>
    \\<WifiConfiguration>
    \\<string name="ConfigKey">&quot;OnePlus 9&quot;WPA_PSK</string>
    \\<string name="SSID">&quot;OnePlus 9&quot;</string>
    \\<string name="PreSharedKey">&quot;777777777&quot;</string>
    \\<boolean name="HiddenSSID" value="false" />
    \\<boolean name="Shared" value="true" />
    \\<int name="Status" value="2" />
    \\<long name="LastDisconnectedTime" value="1784265818329" />
    \\<long name="LastConnectedTime" value="1784265393980" />
    \\<string name="DefaultGwMacAddress">82:46:b4:f4:e7:96</string>
    \\<string name="CreatorName">android.uid.system:1000</string>
    \\<SecurityParamsList>
    \\<SecurityParams><int name="SecurityType" value="2" /></SecurityParams>
    \\<SecurityParams><int name="SecurityType" value="4" /></SecurityParams>
    \\</SecurityParamsList>
    \\</WifiConfiguration>
    \\</Network>
    \\<Network>
    \\<WifiConfiguration>
    \\<string name="ConfigKey">&quot;OpenWiFi&quot;NONE</string>
    \\<string name="SSID">&quot;OpenWiFi&quot;</string>
    \\</WifiConfiguration>
    \\</Network>
    \\</NetworkList>
    \\</WifiConfigStoreData>
;

const soft_ap_sample =
    \\<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
    \\<WifiConfigStoreData>
    \\<int name="Version" value="3" />
    \\<SoftAp>
    \\<string name="WifiSsid">&quot;Mi 11&quot;</string>
    \\<boolean name="HiddenSSID" value="false" />
    \\<int name="SecurityType" value="1" />
    \\<string name="Passphrase">pwhgad9c722krk3</string>
    \\<boolean name="AutoShutdownEnabled" value="true" />
    \\</SoftAp>
    \\</WifiConfigStoreData>
;

test "parses saved networks and the hotspot" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    var networks: std.ArrayList(Network) = .empty;
    try parseConfigStore(alloc, config_store_sample, &networks);
    try testing.expectEqual(@as(usize, 2), networks.items.len);

    const first = networks.items[0];
    try testing.expectEqualStrings("\"OnePlus 9\"WPA_PSK", first.config_key);
    try testing.expectEqualStrings("OnePlus 9", first.ssid);
    try testing.expectEqualStrings("PSK,SAE", first.security);
    try testing.expectEqualStrings("777777777", first.preshared_key.?);
    try testing.expectEqual(@as(?i64, 2), first.status);
    try testing.expectEqual(@as(?i64, 1784265393980), first.last_connected_ms);
    try testing.expectEqualStrings("82:46:b4:f4:e7:96", first.gateway_mac.?);
    try testing.expectEqualStrings("DISABLED", statusName(first.status.?));

    const open = networks.items[1];
    try testing.expectEqualStrings("OPEN", open.security);
    try testing.expect(open.preshared_key == null);

    const soft_ap = (try parseSoftAp(alloc, soft_ap_sample)).?;
    try testing.expectEqualStrings("Mi 11", soft_ap.ssid);
    try testing.expectEqualStrings("WPA2_PSK", soft_ap.security);
    try testing.expectEqualStrings("pwhgad9c722krk3", soft_ap.passphrase.?);
    try testing.expect(soft_ap.auto_shutdown);
}
