const std = @import("std");
const string_pool = @import("../string_pool.zig");
const typed_value = @import("../typed_value.zig");
const config_mod = @import("config.zig");
const table_mod = @import("table.zig");
const logging = @import("../../../utils/logging.zig");

pub const max_reference_depth: usize = 64;

pub const Error = table_mod.NameError || string_pool.LookupError || error{
    InvalidResourceId,
    PackageNotFound,
    TypeNotFound,
    EntryNotFound,
    NoMatchingConfiguration,
    ReferenceCycle,
    ReferenceDepthExceeded,
};

pub const Selection = struct {
    /// Null means no locale was requested and therefore the default locale is
    /// preferred. An explicit locale gets priority over all density/sdk ties.
    locale: ?config_mod.Locale = null,
    /// Null prefers an unqualified density. A value selects the exact or
    /// nearest deterministic density candidate.
    density: ?u16 = null,
    /// Version-qualified resources newer than this value are incompatible.
    sdk_version: u16 = std.math.maxInt(u16),
};

pub const Match = struct {
    resource_id: u32,
    package: *const table_mod.Package,
    type_value: *const table_mod.Type,
    entry: *const table_mod.Entry,
    type_name: []const u8,
    key_name: []const u8,
};

pub const Resolution = struct {
    requested_id: u32,
    resolved_id: u32,
    match: Match,
    /// Null for a complex/bag entry.
    value: ?typed_value.Value,
    /// Set when the terminal simple value is an index into the table's global
    /// string pool.
    string_value: ?[]const u8,
    reference_hops: usize,

    pub fn isComplex(self: Resolution) bool {
        return self.value == null;
    }
};

pub const ResolveOptions = struct {
    selection: Selection = .{},
    max_depth: usize = max_reference_depth,
};

pub fn lookup(
    resources: *const table_mod.Table,
    resource_id: u32,
    request: Selection,
) Error!Match {
    const decoded = table_mod.ResourceId.fromInt(resource_id);
    if (!decoded.isValid()) return error.InvalidResourceId;

    const package = resources.findPackage(decoded.package_id) orelse {
        return error.PackageNotFound;
    };
    const local_type_id = package.localTypeId(decoded.type_id) orelse {
        return error.TypeNotFound;
    };

    var best_type: ?*const table_mod.Type = null;
    var best_entry: ?*const table_mod.Entry = null;
    var best_rank: Rank = undefined;
    var saw_type = false;
    var saw_entry = false;
    const entry_index: usize = decoded.entry_id;

    for (package.types, 0..) |type_value, type_index| {
        if (type_value.id != local_type_id) continue;
        saw_type = true;
        if (entry_index >= type_value.entries.len) continue;
        const entry_value = type_value.entries[entry_index] orelse continue;
        saw_entry = true;
        const rank = rankConfig(type_value.config, request) orelse continue;

        if (best_type == null or rank.betterThan(best_rank)) {
            best_type = &package.types[type_index];
            best_entry = &package.types[type_index].entries[entry_index].?;
            best_rank = rank;
            _ = entry_value;
        }
    }

    if (!saw_type) return error.TypeNotFound;
    if (!saw_entry) return error.EntryNotFound;
    const selected_type = best_type orelse return error.NoMatchingConfiguration;
    const selected_entry = best_entry.?;
    return .{
        .resource_id = resource_id,
        .package = package,
        .type_value = selected_type,
        .entry = selected_entry,
        .type_name = try package.typeName(local_type_id),
        .key_name = try package.keyName(selected_entry),
    };
}

pub fn resolve(
    resources: *const table_mod.Table,
    resource_id: u32,
    selection: Selection,
) Error!Resolution {
    logging.debug(.apk_android_resolver, @src(), "resource resolution started id=0x{x:0>8}", .{resource_id});
    const resolution = resolveWithOptions(resources, resource_id, .{ .selection = selection }) catch |err| {
        logging.warn(.apk_android_resolver, @src(), "resource resolution failed id=0x{x:0>8} error={s}", .{
            resource_id,
            @errorName(err),
        });
        return err;
    };
    logging.debug(.apk_android_resolver, @src(), "resource resolution completed requested=0x{x:0>8} resolved=0x{x:0>8} type={s} name={s} hops={d}", .{
        resolution.requested_id,
        resolution.resolved_id,
        resolution.match.type_name,
        resolution.match.key_name,
        resolution.reference_hops,
    });
    return resolution;
}

pub fn resolveWithOptions(
    resources: *const table_mod.Table,
    resource_id: u32,
    options: ResolveOptions,
) Error!Resolution {
    const depth_limit = @min(options.max_depth, max_reference_depth);
    var visited: [max_reference_depth + 1]u32 = undefined;
    var visited_len: usize = 0;
    var current_id = resource_id;
    var hops: usize = 0;

    while (true) {
        for (visited[0..visited_len]) |seen| {
            if (seen == current_id) return error.ReferenceCycle;
        }
        if (visited_len >= visited.len) return error.ReferenceDepthExceeded;
        visited[visited_len] = current_id;
        visited_len += 1;

        const match = try lookup(resources, current_id, options.selection);
        switch (match.entry.value) {
            .complex => {
                return .{
                    .requested_id = resource_id,
                    .resolved_id = current_id,
                    .match = match,
                    .value = null,
                    .string_value = null,
                    .reference_hops = hops,
                };
            },
            .simple => |value| {
                if (value.referenceId()) |next_id| {
                    if (next_id != 0) {
                        if (hops >= depth_limit) return error.ReferenceDepthExceeded;
                        hops += 1;
                        current_id = next_id;
                        continue;
                    }
                }

                const resolved_string = if (value.stringIndex()) |index|
                    try resources.global_strings.get(index)
                else
                    null;
                return .{
                    .requested_id = resource_id,
                    .resolved_id = current_id,
                    .match = match,
                    .value = value,
                    .string_value = resolved_string,
                    .reference_hops = hops,
                };
            },
        }
    }
}

const Rank = struct {
    locale: u8,
    default_qualifiers: u8,
    density_class: u8,
    density_distance: u16,
    sdk_version: u16,

    fn betterThan(self: Rank, other: Rank) bool {
        if (self.locale != other.locale) return self.locale > other.locale;
        if (self.default_qualifiers != other.default_qualifiers) {
            return self.default_qualifiers > other.default_qualifiers;
        }
        if (self.density_class != other.density_class) {
            return self.density_class > other.density_class;
        }
        if (self.density_distance != other.density_distance) {
            return self.density_distance < other.density_distance;
        }
        return self.sdk_version > other.sdk_version;
    }
};

fn rankConfig(config: config_mod.Config, request: Selection) ?Rank {
    if (config.sdk_version > request.sdk_version) return null;
    return .{
        .locale = localeRank(config.locale, request.locale) orelse return null,
        .default_qualifiers = defaultQualifierRank(config),
        .density_class = densityRank(config.density, request.density).class,
        .density_distance = densityRank(config.density, request.density).distance,
        .sdk_version = config.sdk_version,
    };
}

fn localeRank(candidate: config_mod.Locale, requested: ?config_mod.Locale) ?u8 {
    const request = requested orelse return if (candidate.isDefault()) 2 else 1;
    if (candidate.isDefault()) return 1;
    if (!candidate.sameLanguage(request)) return null;

    var rank: u8 = 4;
    rank += qualifierMatch(candidate.regionSlice(), request.regionSlice()) orelse return null;
    rank += qualifierMatch(candidate.scriptSlice(), request.scriptSlice()) orelse return null;
    rank += qualifierMatch(candidate.variantSlice(), request.variantSlice()) orelse return null;
    rank += qualifierMatch(
        candidate.numberingSystemSlice(),
        request.numberingSystemSlice(),
    ) orelse return null;
    return rank;
}

fn qualifierMatch(candidate: []const u8, requested: []const u8) ?u8 {
    if (candidate.len == 0) return 0;
    if (requested.len == 0 or !std.mem.eql(u8, candidate, requested)) return null;
    return 1;
}

const DensityRank = struct {
    class: u8,
    distance: u16,
};

fn densityRank(candidate: u16, requested: ?u16) DensityRank {
    const any_dpi: u16 = 0xfffe;
    const no_dpi: u16 = 0xffff;
    if (requested == null) {
        if (candidate == 0) return .{ .class = 4, .distance = 0 };
        if (candidate == any_dpi) return .{ .class = 3, .distance = 0 };
        if (candidate == no_dpi) return .{ .class = 2, .distance = 0 };
        return .{ .class = 1, .distance = absoluteDifference(candidate, 160) };
    }

    const target = requested.?;
    if (candidate == target) return .{ .class = 5, .distance = 0 };
    if (candidate == any_dpi) return .{ .class = 4, .distance = 0 };
    if (candidate == no_dpi) return .{ .class = 3, .distance = 0 };
    const effective = if (candidate == 0) @as(u16, 160) else candidate;
    return .{ .class = 2, .distance = absoluteDifference(effective, target) };
}

fn absoluteDifference(a: u16, b: u16) u16 {
    return if (a >= b) a - b else b - a;
}

/// Higher means fewer unsupported qualifiers were present. The resolver does
/// not guess orientation/input/screen qualifiers that were never requested.
fn defaultQualifierRank(config: config_mod.Config) u8 {
    var count: u8 = 0;
    if (config.mcc == 0) count += 1;
    if (config.mnc == 0) count += 1;
    if (config.orientation == 0) count += 1;
    if (config.touchscreen == 0) count += 1;
    if (config.keyboard == 0) count += 1;
    if (config.navigation == 0) count += 1;
    if (config.input_flags == 0) count += 1;
    if (config.screen_width == 0 and config.screen_height == 0) count += 1;
    if (config.screen_layout == 0) count += 1;
    if (config.ui_mode == 0) count += 1;
    if (config.smallest_screen_width_dp == 0) count += 1;
    if (config.screen_width_dp == 0 and config.screen_height_dp == 0) count += 1;
    if (config.screen_layout2 == 0) count += 1;
    if (config.color_mode == 0) count += 1;
    return count;
}

fn testPool(strings: []const []const u8) string_pool.StringPool {
    return .{ .flags = 0, .strings = strings, .style_offsets = &.{} };
}

test "selection prefers explicit locale and otherwise the default" {
    const global_values = [_][]const u8{ "Default", "English" };
    const type_names = [_][]const u8{"string"};
    const key_names = [_][]const u8{"app_name"};
    const default_entries = [_]?table_mod.Entry{.{
        .size = 8,
        .flags = 0,
        .key_index = 0,
        .value = .{ .simple = .{ .size = 8, .data_type = .string, .data = 0 } },
    }};
    const english_entries = [_]?table_mod.Entry{.{
        .size = 8,
        .flags = 0,
        .key_index = 0,
        .value = .{ .simple = .{ .size = 8, .data_type = .string, .data = 1 } },
    }};
    const types = [_]table_mod.Type{
        .{ .id = 1, .flags = 0, .config = .{}, .entries = @constCast(&default_entries) },
        .{
            .id = 1,
            .flags = 0,
            .config = .{ .locale = try config_mod.Locale.parse("en") },
            .entries = @constCast(&english_entries),
        },
    };
    const packages = [_]table_mod.Package{.{
        .id = 0x7f,
        .name = "test",
        .type_id_offset = 0,
        .last_public_type = 0,
        .last_public_key = 0,
        .type_strings = testPool(&type_names),
        .key_strings = testPool(&key_names),
        .type_specs = @constCast(&[_]table_mod.TypeSpec{}),
        .types = @constCast(&types),
    }};
    const resources: table_mod.Table = .{
        .allocator = std.testing.allocator,
        .global_strings = testPool(&global_values),
        .packages = @constCast(&packages),
    };

    const default_result = try resolve(&resources, 0x7f01_0000, .{});
    try std.testing.expectEqualStrings("Default", default_result.string_value.?);
    const english_result = try resolve(&resources, 0x7f01_0000, .{
        .locale = try config_mod.Locale.parse("en-US"),
    });
    try std.testing.expectEqualStrings("English", english_result.string_value.?);
}

test "type id offset is applied and reference cycles are detected" {
    const type_names = [_][]const u8{"string"};
    const key_names = [_][]const u8{ "first", "second" };
    const global_values = [_][]const u8{};
    const entries = [_]?table_mod.Entry{
        .{
            .size = 8,
            .flags = 0,
            .key_index = 0,
            .value = .{ .simple = .{
                .size = 8,
                .data_type = .reference,
                .data = 0x7f02_0001,
            } },
        },
        .{
            .size = 8,
            .flags = 0,
            .key_index = 1,
            .value = .{ .simple = .{
                .size = 8,
                .data_type = .reference,
                .data = 0x7f02_0000,
            } },
        },
    };
    const types = [_]table_mod.Type{.{
        .id = 1,
        .flags = 0,
        .config = .{},
        .entries = @constCast(&entries),
    }};
    const packages = [_]table_mod.Package{.{
        .id = 0x7f,
        .name = "test",
        .type_id_offset = 1,
        .last_public_type = 0,
        .last_public_key = 0,
        .type_strings = testPool(&type_names),
        .key_strings = testPool(&key_names),
        .type_specs = @constCast(&[_]table_mod.TypeSpec{}),
        .types = @constCast(&types),
    }};
    const resources: table_mod.Table = .{
        .allocator = std.testing.allocator,
        .global_strings = testPool(&global_values),
        .packages = @constCast(&packages),
    };

    try std.testing.expectError(
        error.ReferenceCycle,
        resolve(&resources, 0x7f02_0000, .{}),
    );
}
