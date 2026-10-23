const std = @import("std");
const embeded_asset = @import("../../embeded_asset.zig");
const model = @import("../model.zig");
const zip = @import("../../utils/zip/archive.zig");
const logging = @import("../../utils/logging.zig");

const log = logging.scoped(.apk_catalog);

const Allocator = std.mem.Allocator;

pub fn enrichAndDetect(allocator: Allocator, archive: *const zip.Archive, info: *model.ApkInfo) !void {
    log.info(@src(), "catalog enrichment started permissions={d} archive_entries={d}", .{ info.permissions.len, archive.entries.len });
    var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();
    const scratch_allocator = scratch.allocator();

    const descriptions = try parseObject(scratch_allocator, embeded_asset.permission_descriptions);
    const sensitive = try parseObject(scratch_allocator, embeded_asset.sensitive_permissions);
    enrichPermissions(allocator, info.permissions, descriptions, sensitive);

    const protections_json = try parseObject(scratch_allocator, embeded_asset.apkpackdata);
    info.protections = try detectProtections(allocator, archive.entries, info.components, protections_json);
    const built_bytes = std.mem.trim(u8, embeded_asset.built_info, " \t\r\n");
    info.frameworks = if (built_bytes.len == 0)
        &.{}
    else
        try detectFrameworks(allocator, archive.entries, try parseObject(scratch_allocator, built_bytes));
    log.info(@src(), "catalog enrichment completed protections={d} frameworks={d}", .{ info.protections.len, info.frameworks.len });
}

fn parseObject(allocator: Allocator, bytes: []const u8) !std.json.ObjectMap {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    return parsed.value.object;
}

fn enrichPermissions(
    allocator: Allocator,
    permissions: []const model.Permission,
    descriptions: std.json.ObjectMap,
    sensitive: std.json.ObjectMap,
) void {
    const items = @constCast(permissions);
    const sensitive_list = arrayFor(sensitive, "sensitive_permissions");
    const danger_list = arrayFor(sensitive, "danger_permissions");
    for (items) |*permission| {
        if (descriptions.get(permission.name)) |entry| {
            if (entry.object.get("name")) |value| if (value == .string) {
                permission.display_name = allocator.dupe(u8, value.string) catch |err| blk: {
                    log.warn(@src(), "permission display name omitted permission={s} error={s}", .{ permission.name, @errorName(err) });
                    break :blk null;
                };
            };
            if (entry.object.get("description")) |value| if (value == .string) {
                permission.description = allocator.dupe(u8, value.string) catch |err| blk: {
                    log.warn(@src(), "permission description omitted permission={s} error={s}", .{ permission.name, @errorName(err) });
                    break :blk null;
                };
            };
        }
        permission.risk = if (containsString(danger_list, permission.name)) .dangerous else if (containsString(sensitive_list, permission.name)) .sensitive else .normal;
    }
}

fn detectProtections(
    allocator: Allocator,
    entries: []const zip.Entry,
    components: []const model.Component,
    rules: std.json.ObjectMap,
) ![]const model.Detection {
    var output: std.ArrayList(model.Detection) = .empty;
    errdefer output.deinit(allocator);
    var iterator = rules.iterator();
    while (iterator.next()) |rule_entry| {
        const name = rule_entry.key_ptr.*;
        const rule = rule_entry.value_ptr.*;
        if (rule != .object) continue;
        var evidence: std.ArrayList([]const u8) = .empty;
        defer evidence.deinit(allocator);
        collectExactEvidence(entries, arrayFor(rule.object, "sopath"), &evidence, allocator);
        collectSonameEvidence(entries, arrayFor(rule.object, "soname"), &evidence, allocator);
        collectExactEvidence(entries, arrayFor(rule.object, "other"), &evidence, allocator);
        collectRegexEvidence(entries, arrayFor(rule.object, "soregex"), &evidence, allocator);
        collectClassEvidence(entries, components, arrayFor(rule.object, "jclass"), &evidence, allocator);
        if (evidence.items.len == 0) continue;
        try output.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .evidence = try copyStrings(allocator, evidence.items),
        });
    }
    return output.toOwnedSlice(allocator);
}

fn detectFrameworks(allocator: Allocator, entries: []const zip.Entry, rules: std.json.ObjectMap) ![]const model.Detection {
    var output: std.ArrayList(model.Detection) = .empty;
    errdefer output.deinit(allocator);
    var iterator = rules.iterator();
    while (iterator.next()) |rule_entry| {
        if (std.mem.startsWith(u8, rule_entry.key_ptr.*, "_")) continue;
        var evidence: std.ArrayList([]const u8) = .empty;
        defer evidence.deinit(allocator);
        collectFrameworkEvidence(entries, rule_entry.value_ptr.*, &evidence, allocator);
        if (evidence.items.len != 0) try output.append(allocator, .{
            .name = try allocator.dupe(u8, rule_entry.key_ptr.*),
            .evidence = try copyStrings(allocator, evidence.items),
        });
    }
    if (output.items.len == 0) {
        if (rules.get("_default")) |default_value| if (default_value == .string) {
            try output.append(allocator, .{
                .name = try allocator.dupe(u8, default_value.string),
                .evidence = &.{},
            });
        };
    }
    return output.toOwnedSlice(allocator);
}

fn collectFrameworkEvidence(
    entries: []const zip.Entry,
    rule: std.json.Value,
    output: *std.ArrayList([]const u8),
    allocator: Allocator,
) void {
    switch (rule) {
        .string => collectMarker(entries, rule.string, false, output, allocator),
        .array => for (rule.array.items) |value| if (value == .string) {
            collectMarker(entries, value.string, false, output, allocator);
        },
        .object => {
            var fields = rule.object.iterator();
            while (fields.next()) |field| {
                const regex = containsIgnoreCase(field.key_ptr.*, "regex");
                switch (field.value_ptr.*) {
                    .string => collectMarker(entries, field.value_ptr.string, regex, output, allocator),
                    .array => for (field.value_ptr.array.items) |value| if (value == .string) {
                        collectMarker(entries, value.string, regex, output, allocator);
                    },
                    else => {},
                }
            }
        },
        else => {},
    }
}

fn collectMarker(entries: []const zip.Entry, marker: []const u8, regex: bool, output: *std.ArrayList([]const u8), allocator: Allocator) void {
    for (entries) |entry| {
        const matched = if (regex)
            simpleRegexMatch(entry.name, marker)
        else
            std.mem.eql(u8, entry.name, marker) or std.mem.startsWith(u8, entry.name, marker) or
                std.mem.endsWith(u8, entry.name, marker) or std.mem.indexOf(u8, entry.name, marker) != null;
        if (matched) appendEvidence(output, allocator, entry.name);
    }
}

fn containsIgnoreCase(value: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > value.len) return false;
    for (0..value.len - needle.len + 1) |index| {
        if (std.ascii.eqlIgnoreCase(value[index .. index + needle.len], needle)) return true;
    }
    return false;
}

fn collectExactEvidence(entries: []const zip.Entry, values: []const std.json.Value, output: *std.ArrayList([]const u8), allocator: Allocator) void {
    for (entries) |entry| for (values) |value| if (value == .string and std.mem.eql(u8, entry.name, value.string)) {
        appendEvidence(output, allocator, entry.name);
    };
}

fn collectSonameEvidence(entries: []const zip.Entry, values: []const std.json.Value, output: *std.ArrayList([]const u8), allocator: Allocator) void {
    for (entries) |entry| {
        const slash = std.mem.lastIndexOfScalar(u8, entry.name, '/') orelse 0;
        const leaf = entry.name[if (slash == 0) 0 else slash + 1..];
        for (values) |value| if (value == .string and std.mem.eql(u8, leaf, value.string)) {
            appendEvidence(output, allocator, entry.name);
        };
    }
}

fn collectRegexEvidence(entries: []const zip.Entry, values: []const std.json.Value, output: *std.ArrayList([]const u8), allocator: Allocator) void {
    for (entries) |entry| for (values) |value| if (value == .string and simpleRegexMatch(entry.name, value.string)) {
        appendEvidence(output, allocator, entry.name);
    };
}

fn collectClassEvidence(entries: []const zip.Entry, components: []const model.Component, values: []const std.json.Value, output: *std.ArrayList([]const u8), allocator: Allocator) void {
    for (components) |component| for (values) |value| if (value == .string and
        (std.mem.indexOf(u8, component.name, value.string) != null or
            std.mem.indexOf(u8, value.string, component.name) != null))
    {
        appendEvidence(output, allocator, component.name);
    };
    for (entries) |entry| if (std.mem.endsWith(u8, entry.name, ".dex")) for (values) |value| if (value == .string and
        std.mem.indexOf(u8, entry.name, value.string) != null)
    {
        appendEvidence(output, allocator, entry.name);
    };
}

fn simpleRegexMatch(value: []const u8, pattern: []const u8) bool {
    var clean: [512]u8 = undefined;
    var used: usize = 0;
    var index: usize = 0;
    while (index < pattern.len and used < clean.len) : (index += 1) {
        if (pattern[index] == '\\' and index + 1 < pattern.len) index += 1;
        if (index + 2 < pattern.len and pattern[index] == '.' and pattern[index + 1] == '.' and pattern[index + 2] == '.') {
            clean[used] = '*';
            used += 1;
            index += 2;
        } else {
            clean[used] = pattern[index];
            used += 1;
        }
    }
    return wildcardMatch(value, clean[0..used]);
}

fn wildcardMatch(value: []const u8, pattern: []const u8) bool {
    var vi: usize = 0;
    var pi: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (vi < value.len) {
        if (pi < pattern.len and (pattern[pi] == '?' or pattern[pi] == value[vi])) {
            vi += 1;
            pi += 1;
            continue;
        }
        if (pi < pattern.len and pattern[pi] == '*') {
            star = pi;
            pi += 1;
            mark = vi;
            continue;
        }
        if (star) |position| {
            pi = position + 1;
            mark += 1;
            vi = mark;
            continue;
        }
        return false;
    }
    while (pi < pattern.len and pattern[pi] == '*') pi += 1;
    return pi == pattern.len;
}

fn arrayFor(object: std.json.ObjectMap, key: []const u8) []const std.json.Value {
    if (object.get(key)) |value| if (value == .array) return value.array.items;
    return &.{};
}

fn containsString(values: []const std.json.Value, target: []const u8) bool {
    for (values) |value| if (value == .string and std.mem.eql(u8, value.string, target)) return true;
    return false;
}

fn appendUnique(list: *std.ArrayList([]const u8), allocator: Allocator, value: []const u8) !void {
    for (list.items) |existing| if (std.mem.eql(u8, existing, value)) return;
    try list.append(allocator, value);
}

fn appendEvidence(list: *std.ArrayList([]const u8), allocator: Allocator, value: []const u8) void {
    appendUnique(list, allocator, value) catch |err| {
        log.warn(@src(), "detection evidence omitted value={s} error={s}", .{ value, @errorName(err) });
    };
}

fn copyStrings(allocator: Allocator, values: []const []const u8) ![]const []const u8 {
    const output = try allocator.alloc([]const u8, values.len);
    for (values, 0..) |value, index| output[index] = try allocator.dupe(u8, value);
    return output;
}
