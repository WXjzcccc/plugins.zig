//! Conversion from the parser model to positional record values.
//!
//! The record schemas of records.zig are positional: a value list follows the
//! field order of its schema. This module is the single place that knows both
//! sides, so a schema change and its value change happen together.
//!
//! Text that the host requires to be non-empty (paths, hashes, enumerations)
//! is never emitted as nil: an absent value becomes an empty string, which the
//! field kinds accept, while int / boolean / timestamp fields keep nil to mean
//! "not present in the package".

const std = @import("std");

const lc = @import("lovelycarve");
const model = @import("../core/model.zig");
const records = @import("records.zig");

/// A string field value: the text, or an empty string when the model has none.
fn text(value: ?[]const u8) lc.wire.Value {
    return lc.wire.str(value orelse "");
}

fn uint(value: ?u64) lc.wire.Value {
    return if (value) |number| lc.wire.uint(number) else .nil;
}

fn uint32(value: ?u32) lc.wire.Value {
    return if (value) |number| lc.wire.uint(number) else .nil;
}

fn boolean(value: ?bool) lc.wire.Value {
    return if (value) |flag| .{ .boolean = flag } else .nil;
}

/// A list field: the strings, or nil when there are none.
fn list(alloc: std.mem.Allocator, values: []const []const u8) lc.Error!lc.wire.Value {
    if (values.len == 0) return .nil;
    const items = try alloc.alloc(lc.wire.Value, values.len);
    for (values, items) |value, *slot| slot.* = lc.wire.str(value);
    return .{ .array = items };
}

/// A hash field from raw digest bytes.
fn digest(alloc: std.mem.Allocator, bytes: []const u8) lc.Error!lc.wire.Value {
    return lc.wire.str(try std.fmt.allocPrint(alloc, "{x}", .{bytes}));
}

/// wire.mapOf with the codec's error set mapped to the SDK's: a record value
/// only fails to encode when memory runs out.
fn mapOf(alloc: std.mem.Allocator, entries: []const lc.wire.Entry) lc.Error!lc.wire.Value {
    return lc.wire.mapOf(alloc, entries) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => lc.errorcodes.fail("PROTOCOL_ERROR", "a record value is not encodable"),
    };
}

/// The display text of a manifest value: the resolved string when the resource
/// table supplied one, else the raw attribute text.
fn valueText(value: model.Value) []const u8 {
    return value.display() orelse "";
}

/// apk.info: one row per package.
pub fn infoValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    analysis: *const model.Analysis,
) lc.Error![]const lc.wire.Value {
    const info = &analysis.info;
    const values = try alloc.alloc(lc.wire.Value, records.INFO.fields.len);
    values[0] = text(package_name);
    values[1] = text(valueText(info.application_label));
    values[2] = text(valueText(info.version_name));
    values[3] = uint(info.version_code);
    values[4] = uint32(info.sdk.min);
    values[5] = uint32(info.sdk.target);
    values[6] = uint32(info.sdk.compile);
    values[7] = text(info.launcher_activity);
    values[8] = boolean(info.debuggable);
    values[9] = boolean(info.allow_backup);
    values[10] = lc.wire.uint(info.file_size);
    values[11] = if (info.sha256) |sha| try digest(alloc, &sha) else .nil;
    values[12] = lc.wire.uint(info.archive.file_count);
    values[13] = lc.wire.uint(info.archive.compressed_size);
    values[14] = lc.wire.uint(info.archive.uncompressed_size);
    values[15] = try packageNames(alloc, info.resources.packages);
    values[16] = lc.wire.uint(info.resources.value_count);
    values[17] = lc.wire.uint(info.resources.resolved_references);
    values[18] = lc.wire.uint(info.resources.unresolved_references);
    values[19] = try schemeNames(alloc, info.signing);
    values[20] = try detectionNames(alloc, info.protections);
    values[21] = try detectionNames(alloc, info.frameworks);
    values[22] = .{ .boolean = info.signing.cryptographic_verification_performed };
    return values;
}

fn packageNames(alloc: std.mem.Allocator, packages: []const model.ResourcePackage) lc.Error!lc.wire.Value {
    if (packages.len == 0) return .nil;
    const names = try alloc.alloc([]const u8, packages.len);
    for (packages, names) |package, *slot| slot.* = package.name;
    return list(alloc, names);
}

/// The signature schemes present in the package, as choice ids.
fn schemeNames(alloc: std.mem.Allocator, signing: model.SigningInfo) lc.Error!lc.wire.Value {
    var names: std.ArrayList([]const u8) = .empty;
    if (signing.has_v1) try names.append(alloc, "jar_v1");
    if (signing.has_v2) try names.append(alloc, "apk_v2");
    if (signing.has_v3) try names.append(alloc, "apk_v3");
    if (signing.has_v31) try names.append(alloc, "apk_v31");
    if (signing.has_source_stamp) try names.append(alloc, "source_stamp");
    return list(alloc, names.items);
}

fn detectionNames(alloc: std.mem.Allocator, detections: []const model.Detection) lc.Error!lc.wire.Value {
    if (detections.len == 0) return .nil;
    const names = try alloc.alloc([]const u8, detections.len);
    for (detections, names) |detection, *slot| slot.* = detection.name;
    return list(alloc, names);
}

/// apk.component: one row per manifest component.
pub fn componentValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    component: model.Component,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.COMPONENT.fields.len);
    values[0] = text(package_name);
    values[1] = text(@tagName(component.kind));
    values[2] = text(component.name);
    values[3] = text(component.target_activity);
    values[4] = boolean(component.exported);
    values[5] = boolean(component.enabled);
    values[6] = text(component.permission);
    values[7] = text(component.process);
    values[8] = text(component.authorities);
    values[9] = text(valueText(component.label));
    values[10] = try intentFiltersJson(alloc, component.intent_filters);
    values[11] = try metadataJson(alloc, component.meta_data);
    return values;
}

fn intentFiltersJson(alloc: std.mem.Allocator, filters: []const model.IntentFilter) lc.Error!lc.wire.Value {
    if (filters.len == 0) return .nil;
    const items = try alloc.alloc(lc.wire.Value, filters.len);
    for (filters, items) |filter, *slot| {
        slot.* = try mapOf(alloc, &.{
            lc.wire.entry("actions", try list(alloc, filter.actions)),
            lc.wire.entry("categories", try list(alloc, filter.categories)),
            lc.wire.entry("data", try intentDataJson(alloc, filter.data)),
        });
    }
    return .{ .array = items };
}

fn intentDataJson(alloc: std.mem.Allocator, data: []const model.IntentData) lc.Error!lc.wire.Value {
    if (data.len == 0) return .nil;
    const items = try alloc.alloc(lc.wire.Value, data.len);
    for (data, items) |entry, *slot| {
        var fields: std.ArrayList(lc.wire.Entry) = .empty;
        if (entry.scheme) |value| try fields.append(alloc, lc.wire.entry("scheme", text(value)));
        if (entry.host) |value| try fields.append(alloc, lc.wire.entry("host", text(value)));
        if (entry.port) |value| try fields.append(alloc, lc.wire.entry("port", text(value)));
        if (entry.path) |value| try fields.append(alloc, lc.wire.entry("path", text(value)));
        if (entry.path_prefix) |value| try fields.append(alloc, lc.wire.entry("path_prefix", text(value)));
        if (entry.path_pattern) |value| try fields.append(alloc, lc.wire.entry("path_pattern", text(value)));
        if (entry.mime_type) |value| try fields.append(alloc, lc.wire.entry("mime_type", text(value)));
        slot.* = try mapOf(alloc, fields.items);
    }
    return .{ .array = items };
}

fn metadataJson(alloc: std.mem.Allocator, items: []const model.MetaData) lc.Error!lc.wire.Value {
    if (items.len == 0) return .nil;
    const values = try alloc.alloc(lc.wire.Value, items.len);
    for (items, values) |item, *slot| {
        slot.* = try mapOf(alloc, &.{
            lc.wire.entry("name", text(item.name)),
            lc.wire.entry("value", text(valueText(item.value))),
            lc.wire.entry("kind", text(@tagName(item.value.kind))),
        });
    }
    return .{ .array = values };
}

/// apk.permission: one row per declared permission.
pub fn permissionValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    permission: model.Permission,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.PERMISSION.fields.len);
    values[0] = text(package_name);
    values[1] = text(permission.name);
    values[2] = text(riskName(permission.risk));
    values[3] = uint32(permission.max_sdk_version);
    values[4] = uint32(permission.uses_permission_flags);
    values[5] = text(permission.display_name);
    values[6] = text(permission.description);
    return values;
}

fn riskName(risk: model.PermissionRisk) []const u8 {
    return switch (risk) {
        .normal => "normal",
        .sensitive => "sensitive",
        .dangerous => "dangerous",
        .unknown => "unknown",
    };
}

/// apk.feature: one row per uses-feature element.
pub fn featureValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    feature: model.Feature,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.FEATURE.fields.len);
    values[0] = text(package_name);
    values[1] = text(feature.name);
    values[2] = uint32(feature.gl_es_version);
    values[3] = boolean(feature.required);
    return values;
}

/// apk.metadata: one row per application meta-data element.
pub fn metadataValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    item: model.MetaData,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.METADATA.fields.len);
    values[0] = text(package_name);
    values[1] = text(item.name);
    values[2] = text(valueText(item.value));
    values[3] = text(@tagName(item.value.kind));
    return values;
}

/// apk.signer: one row per signer of every scheme.
pub fn signerValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    signer: model.Signer,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.SIGNER.fields.len);
    values[0] = text(package_name);
    values[1] = text(@tagName(signer.scheme));
    values[2] = uint32(signer.min_sdk);
    values[3] = uint32(signer.max_sdk);
    values[4] = try algorithmNames(alloc, signer.signature_algorithm_ids, true);
    values[5] = try algorithmNames(alloc, signer.digest_algorithm_ids, false);
    values[6] = lc.wire.uint(signer.certificates.len);
    return values;
}

fn algorithmNames(
    alloc: std.mem.Allocator,
    ids: []const u32,
    signature: bool,
) lc.Error!lc.wire.Value {
    if (ids.len == 0) return .nil;
    const algorithms = @import("../core/signing/algorithms.zig");
    const names = try alloc.alloc([]const u8, ids.len);
    for (ids, names) |id, *slot| {
        slot.* = if (signature) algorithms.apkSignatureName(id) else algorithms.digestName(id);
    }
    return list(alloc, names);
}

/// apk.certificate: one row per certificate of every signer.
pub fn certificateValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    scheme: model.SignatureScheme,
    certificate: model.Certificate,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.CERTIFICATE.fields.len);
    values[0] = text(package_name);
    values[1] = text(@tagName(scheme));
    values[2] = text(certificate.serial_number);
    values[3] = try digest(alloc, &certificate.sha256);
    values[4] = try digest(alloc, &certificate.sha1);
    values[5] = try digest(alloc, &certificate.md5);
    values[6] = text(try describeName(alloc, certificate.subject));
    values[7] = text(try describeName(alloc, certificate.issuer));
    values[8] = try timeValue(alloc, certificate.not_before);
    values[9] = try timeValue(alloc, certificate.not_after);
    values[10] = text(certificate.signature_algorithm_name);
    values[11] = text(certificate.public_key_algorithm_name);
    values[12] = uint32(certificate.public_key_bits);
    return values;
}

/// "CN=x, O=y" over the parts the certificate carries.
fn describeName(alloc: std.mem.Allocator, name: model.DistinguishedName) lc.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const parts = [_]struct { label: []const u8, value: ?[]const u8 }{
        .{ .label = "CN", .value = name.common_name },
        .{ .label = "O", .value = name.organization },
        .{ .label = "OU", .value = name.organizational_unit },
        .{ .label = "C", .value = name.country },
        .{ .label = "ST", .value = name.state },
        .{ .label = "L", .value = name.locality },
    };
    for (parts) |part| {
        const value = part.value orelse continue;
        if (value.len == 0) continue;
        if (out.items.len != 0) try out.appendSlice(alloc, ", ");
        try out.appendSlice(alloc, part.label);
        try out.append(alloc, '=');
        try out.appendSlice(alloc, value);
    }
    return out.items;
}

/// A certificate validity time as an RFC 3339 timestamp.
///
/// X.509 stores YYMMDDHHMMSSZ (UTCTime) or YYYYMMDDHHMMSSZ (GeneralizedTime).
/// Both are UTC; a value that does not parse stays nil rather than becoming a
/// wrong time.
///
/// The timestamp lives in an inline buffer, so its text is copied into the
/// record arena: the value must outlive this call.
fn timeValue(alloc: std.mem.Allocator, raw: ?[]const u8) lc.Error!lc.wire.Value {
    const text_value = raw orelse return .nil;
    const timestamp = parseX509Time(text_value) orelse return .nil;
    return lc.wire.str(try std.fmt.allocPrint(alloc, "{s}", .{timestamp.asStr()}));
}

fn parseX509Time(raw: []const u8) ?lc.Timestamp {
    if (raw.len == 13 and raw[12] == 'Z') {
        // UTCTime: 1950-2049, per RFC 5280.
        const year = twoDigits(raw[0..2]) orelse return null;
        const full_year: i32 = if (year >= 50) 1900 + @as(i32, @intCast(year)) else 2000 + @as(i32, @intCast(year));
        return utcTimestamp(
            full_year,
            twoDigits(raw[2..4]) orelse return null,
            twoDigits(raw[4..6]) orelse return null,
            twoDigits(raw[6..8]) orelse return null,
            twoDigits(raw[8..10]) orelse return null,
            twoDigits(raw[10..12]) orelse return null,
        );
    }
    if (raw.len == 15 and raw[14] == 'Z') {
        const year = fourDigits(raw[0..4]) orelse return null;
        return utcTimestamp(
            @intCast(year),
            twoDigits(raw[4..6]) orelse return null,
            twoDigits(raw[6..8]) orelse return null,
            twoDigits(raw[8..10]) orelse return null,
            twoDigits(raw[10..12]) orelse return null,
            twoDigits(raw[12..14]) orelse return null,
        );
    }
    return null;
}

/// The UTC instant of a calendar time, as the SDK renders it (2024-01-01T00:00:00Z).
fn utcTimestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) ?lc.Timestamp {
    const days = lc.schema.daysFromCivil(year, month, day);
    const seconds = days * 86_400 +
        @as(i64, @intCast(hour)) * 3_600 +
        @as(i64, @intCast(minute)) * 60 +
        @as(i64, @intCast(@min(second, 59)));
    // Round-trip through the SDK parser so an impossible date is refused.
    const stamp = lc.Timestamp.fromUnix(seconds);
    if (lc.schema.parseTimestamp(stamp.asStr()) == null) return null;
    return stamp;
}

fn twoDigits(raw: []const u8) ?u32 {
    if (raw.len != 2) return null;
    if (raw[0] < '0' or raw[0] > '9' or raw[1] < '0' or raw[1] > '9') return null;
    return @as(u32, raw[0] - '0') * 10 + (raw[1] - '0');
}

fn fourDigits(raw: []const u8) ?u32 {
    if (raw.len != 4) return null;
    var total: u32 = 0;
    for (raw) |digit| {
        if (digit < '0' or digit > '9') return null;
        total = total * 10 + (digit - '0');
    }
    return total;
}

/// apk.detection: one row per packer / framework detection.
pub fn detectionValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    category: []const u8,
    detection: model.Detection,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.DETECTION.fields.len);
    values[0] = text(package_name);
    values[1] = text(category);
    values[2] = text(detection.name);
    values[3] = try list(alloc, detection.evidence);
    return values;
}

/// apk.entry: one row per ZIP entry.
pub fn entryValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    entry: model.ArchiveEntry,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.ENTRY.fields.len);
    values[0] = text(package_name);
    values[1] = text(entry.name);
    values[2] = text(methodName(entry.method));
    values[3] = lc.wire.uint(entry.compressed_size);
    values[4] = lc.wire.uint(entry.uncompressed_size);
    values[5] = lc.wire.str(try std.fmt.allocPrint(alloc, "{x:0>8}", .{entry.crc32}));
    values[6] = lc.wire.uint(entry.local_header_offset);
    return values;
}

fn methodName(method: u16) []const u8 {
    return switch (method) {
        0 => "store",
        8 => "deflate",
        else => "other",
    };
}

/// apk.diagnostic: one row per recoverable parser diagnostic.
pub fn diagnosticValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    diagnostic: model.Diagnostic,
) lc.Error![]const lc.wire.Value {
    const values = try alloc.alloc(lc.wire.Value, records.DIAGNOSTIC.fields.len);
    values[0] = text(package_name);
    values[1] = text(stageName(diagnostic.stage));
    values[2] = text(severityName(diagnostic.severity));
    values[3] = text(diagnostic.code);
    values[4] = text(diagnostic.message);
    values[5] = text(diagnostic.entry_name);
    values[6] = if (diagnostic.offset) |offset| lc.wire.uint(offset) else .nil;
    return values;
}

fn stageName(stage: model.DiagnosticStage) []const u8 {
    return switch (stage) {
        .input => "input",
        .archive => "archive",
        .manifest => "manifest",
        .resources => "resources",
        .signing => "signing",
    };
}

fn severityName(severity: model.DiagnosticSeverity) []const u8 {
    return switch (severity) {
        .info => "info",
        .warning => "warning",
        .error_value => "error",
    };
}

/// apk.icon: one row for the extracted launcher icon.
pub fn iconValues(
    alloc: std.mem.Allocator,
    package_name: []const u8,
    analysis: *const model.Analysis,
) lc.Error![]const lc.wire.Value {
    const info = &analysis.info;
    const values = try alloc.alloc(lc.wire.Value, records.ICON.fields.len);
    values[0] = text(package_name);
    values[1] = text(info.icon_entry);
    const kind = if (info.icon_bytes.len != 0)
        "bitmap"
    else if (info.icon_svg.len != 0)
        "svg"
    else
        "adaptive";
    values[2] = text(kind);
    values[3] = lc.wire.uint(info.icon_bytes.len);
    values[4] = if (info.icon_bytes.len != 0) try sha256(alloc, info.icon_bytes) else .nil;
    values[5] = lc.wire.uint(info.icon_background_bytes.len);
    return values;
}

fn sha256(alloc: std.mem.Allocator, bytes: []const u8) lc.Error!lc.wire.Value {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return digest(alloc, &hash);
}

const testing = std.testing;

test "x509 times become RFC 3339 timestamps" {
    try testing.expectEqualStrings(
        "2024-01-01T00:00:00Z",
        parseX509Time("240101000000Z").?.asStr(),
    );
    try testing.expectEqualStrings(
        "1999-12-31T23:59:59Z",
        parseX509Time("991231235959Z").?.asStr(),
    );
    try testing.expectEqualStrings(
        "2034-01-01T00:00:00Z",
        parseX509Time("20340101000000Z").?.asStr(),
    );
    // A value that is not a time stays absent rather than becoming a wrong one.
    try testing.expectEqual(null, parseX509Time("240101000000"));
    try testing.expectEqual(null, parseX509Time("24010100000"));
    try testing.expectEqual(null, parseX509Time(""));
}

test "signature schemes list only what the package has" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const none = try schemeNames(alloc, .{});
    try testing.expectEqual(lc.wire.Value.nil, none);

    const both = try schemeNames(alloc, .{ .has_v1 = true, .has_v2 = true });
    try testing.expectEqual(@as(usize, 2), both.array.len);
    try testing.expectEqualStrings("jar_v1", both.array[0].string);
    try testing.expectEqualStrings("apk_v2", both.array[1].string);
}

test "a distinguished name keeps the parts it has" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();

    const name = try describeName(alloc, .{
        .common_name = "Release",
        .organization = "Example",
        .country = "CN",
    });
    try testing.expectEqualStrings("CN=Release, O=Example, C=CN", name);
    try testing.expectEqualStrings("", try describeName(alloc, .{}));
}
