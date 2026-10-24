const std = @import("std");
const axml = @import("axml_zig");
const typed_value = axml.typed_value;
const model = @import("../../model.zig");
const logging = @import("../../../utils/logging.zig");

const android_namespace = "http://schemas.android.com/apk/res/android";
const action_main = "android.intent.action.MAIN";
const category_launcher = "android.intent.category.LAUNCHER";
const category_leanback_launcher = "android.intent.category.LEANBACK_LAUNCHER";

pub const Error = std.mem.Allocator.Error || error{
    MissingManifestElement,
    DuplicateManifestElement,
    MissingPackageName,
    MissingRequiredAttribute,
    InvalidIntegerAttribute,
    InvalidBooleanAttribute,
    MalformedElementNesting,
    NestedComponent,
    NestedIntentFilter,
    IntentFilterOutsideComponent,
    UnterminatedComponent,
    UnterminatedIntentFilter,
};

/// Applies manifest semantics to `info`. Every returned slice is allocated
/// from `allocator`; the caller owns that allocator's lifetime.
pub fn apply(
    allocator: std.mem.Allocator,
    document: *const axml.Document,
    info: *model.ApkInfo,
) Error!void {
    logging.info(.apk_android_manifest, @src(), "manifest semantics started events={d}", .{document.events.len});
    applyImpl(allocator, document, info) catch |err| {
        logging.err(.apk_android_manifest, @src(), "manifest semantics failed error={s}", .{@errorName(err)});
        return err;
    };
    logging.info(.apk_android_manifest, @src(), "manifest semantics completed package={s} permissions={d} features={d} components={d} metadata={d}", .{
        info.package_name orelse "",
        info.permissions.len,
        info.features.len,
        info.components.len,
        info.application_meta_data.len,
    });
}

fn applyImpl(
    allocator: std.mem.Allocator,
    document: *const axml.Document,
    info: *model.ApkInfo,
) Error!void {
    var components: std.ArrayList(model.Component) = .empty;
    defer components.deinit(allocator);
    var permissions: std.ArrayList(model.Permission) = .empty;
    defer permissions.deinit(allocator);
    var features: std.ArrayList(model.Feature) = .empty;
    defer features.deinit(allocator);
    var application_meta_data: std.ArrayList(model.MetaData) = .empty;
    defer application_meta_data.deinit(allocator);
    var element_stack: std.ArrayList([]const u8) = .empty;
    defer element_stack.deinit(allocator);

    var manifest_seen = false;
    var application_depth: ?usize = null;
    var component_builder: ?ComponentBuilder = null;
    var filter_builder: ?FilterBuilder = null;
    var version_code_low: ?u32 = null;
    var version_code_high: u32 = 0;

    for (document.events) |event| switch (event) {
        .start_element => |element| {
            const depth = element_stack.items.len;
            try element_stack.append(allocator, element.name);

            if (std.mem.eql(u8, element.name, "manifest")) {
                if (depth != 0) return error.MalformedElementNesting;
                if (manifest_seen) return error.DuplicateManifestElement;
                manifest_seen = true;

                const package_attr = findUnnamespacedAttribute(element, "package") orelse
                    return error.MissingPackageName;
                const package_name = attributeString(package_attr) orelse return error.MissingPackageName;
                info.package_name = try allocator.dupe(u8, package_name);

                if (findAndroidAttribute(element, "versionCode")) |attribute| {
                    version_code_low = try attributeU32(attribute);
                }
                if (findAndroidAttribute(element, "versionCodeMajor")) |attribute| {
                    version_code_high = try attributeU32(attribute);
                }
                if (findAndroidAttribute(element, "versionName")) |attribute| {
                    info.version_name = try copyValue(allocator, attribute);
                }
                if (findAttributeByName(element, "compileSdkVersion")) |attribute| {
                    info.sdk.compile = optionalAttributeU32(@src(), attribute, "compileSdkVersion");
                } else if (findAttributeByName(element, "platformBuildVersionCode")) |attribute| {
                    info.sdk.compile = optionalAttributeU32(@src(), attribute, "platformBuildVersionCode");
                }
                continue;
            }

            if (!manifest_seen) return error.MissingManifestElement;

            if (std.mem.eql(u8, element.name, "uses-sdk")) {
                if (findAndroidAttribute(element, "minSdkVersion")) |attribute| {
                    info.sdk.min = optionalAttributeU32(@src(), attribute, "minSdkVersion");
                }
                if (findAndroidAttribute(element, "targetSdkVersion")) |attribute| {
                    info.sdk.target = optionalAttributeU32(@src(), attribute, "targetSdkVersion");
                }
                continue;
            }

            if (std.mem.eql(u8, element.name, "uses-permission") or
                std.mem.eql(u8, element.name, "uses-permission-sdk-23") or
                std.mem.eql(u8, element.name, "uses-permission-sdk-m"))
            {
                const name = try requiredAndroidAttributeString(element, "name");
                try permissions.append(allocator, .{
                    .name = try allocator.dupe(u8, name),
                    .max_sdk_version = if (findAndroidAttribute(element, "maxSdkVersion")) |attribute|
                        optionalAttributeU32(@src(), attribute, "maxSdkVersion")
                    else
                        null,
                    .uses_permission_flags = if (findAndroidAttribute(element, "usesPermissionFlags")) |attribute|
                        optionalAttributeU32(@src(), attribute, "usesPermissionFlags")
                    else
                        null,
                });
                continue;
            }

            if (std.mem.eql(u8, element.name, "uses-feature")) {
                const name = if (findAndroidAttribute(element, "name")) |attribute|
                    if (attributeString(attribute)) |value| try allocator.dupe(u8, value) else null
                else
                    null;
                try features.append(allocator, .{
                    .name = name,
                    .gl_es_version = if (findAndroidAttribute(element, "glEsVersion")) |attribute|
                        optionalAttributeU32(@src(), attribute, "glEsVersion")
                    else
                        null,
                    .required = if (findAndroidAttribute(element, "required")) |attribute|
                        try attributeBool(attribute)
                    else
                        true,
                });
                continue;
            }

            if (std.mem.eql(u8, element.name, "application")) {
                if (application_depth != null) return error.MalformedElementNesting;
                application_depth = depth;
                if (findAndroidAttribute(element, "label")) |attribute| {
                    info.application_label = try copyValue(allocator, attribute);
                }
                if (findAndroidAttribute(element, "icon")) |attribute| {
                    info.application_icon = try copyValue(allocator, attribute);
                }
                if (findAndroidAttribute(element, "roundIcon")) |attribute| {
                    info.application_round_icon = try copyValue(allocator, attribute);
                }
                if (findAndroidAttribute(element, "debuggable")) |attribute| {
                    info.debuggable = try attributeBool(attribute);
                }
                if (findAndroidAttribute(element, "allowBackup")) |attribute| {
                    info.allow_backup = try attributeBool(attribute);
                }
                continue;
            }

            if (componentKind(element.name)) |kind| {
                if (application_depth == null or depth != application_depth.? + 1) continue;
                if (component_builder != null) return error.NestedComponent;
                const package_name = info.package_name orelse return error.MissingPackageName;
                component_builder = try ComponentBuilder.init(allocator, package_name, kind, element);
                continue;
            }

            if (std.mem.eql(u8, element.name, "intent-filter")) {
                if (component_builder == null) return error.IntentFilterOutsideComponent;
                if (filter_builder != null) return error.NestedIntentFilter;
                filter_builder = .{};
                continue;
            }

            if (std.mem.eql(u8, element.name, "action")) {
                if (filter_builder) |*filter| {
                    const name = try requiredAndroidAttributeString(element, "name");
                    try filter.actions.append(allocator, try allocator.dupe(u8, name));
                }
                continue;
            }

            if (std.mem.eql(u8, element.name, "category")) {
                if (filter_builder) |*filter| {
                    const name = try requiredAndroidAttributeString(element, "name");
                    try filter.categories.append(allocator, try allocator.dupe(u8, name));
                }
                continue;
            }

            if (std.mem.eql(u8, element.name, "data")) {
                if (filter_builder) |*filter| {
                    try filter.data.append(allocator, try parseIntentData(allocator, element));
                }
                continue;
            }

            if (std.mem.eql(u8, element.name, "meta-data")) {
                const item = try parseMetaData(allocator, element);
                if (component_builder) |*component| {
                    try component.meta_data.append(allocator, item);
                } else if (application_depth != null) {
                    try application_meta_data.append(allocator, item);
                }
            }
        },
        .end_element => |element| {
            const started = element_stack.pop() orelse return error.MalformedElementNesting;
            if (!std.mem.eql(u8, started, element.name)) return error.MalformedElementNesting;

            if (std.mem.eql(u8, element.name, "intent-filter")) {
                var filter = filter_builder orelse return error.IntentFilterOutsideComponent;
                filter_builder = null;
                const completed = try filter.finish(allocator);
                try component_builder.?.intent_filters.append(allocator, completed);
                continue;
            }

            if (componentKind(element.name) != null and application_depth != null and element_stack.items.len == application_depth.? + 1) {
                if (filter_builder != null) return error.UnterminatedIntentFilter;
                var component = component_builder orelse return error.MalformedElementNesting;
                component_builder = null;
                const completed = try component.finish(allocator);
                if (info.launcher_activity == null and isLauncherComponent(completed)) {
                    info.launcher_activity = try allocator.dupe(u8, completed.name);
                }
                try components.append(allocator, completed);
                continue;
            }

            if (std.mem.eql(u8, element.name, "application")) {
                application_depth = null;
            }
        },
        else => {},
    };

    if (!manifest_seen) return error.MissingManifestElement;
    if (element_stack.items.len != 0) return error.MalformedElementNesting;
    if (component_builder != null) return error.UnterminatedComponent;
    if (filter_builder != null) return error.UnterminatedIntentFilter;

    if (version_code_low) |low| {
        info.version_code = (@as(u64, version_code_high) << 32) | low;
    }
    info.permissions = try permissions.toOwnedSlice(allocator);
    info.features = try features.toOwnedSlice(allocator);
    info.application_meta_data = try application_meta_data.toOwnedSlice(allocator);
    info.components = try components.toOwnedSlice(allocator);
}

const ComponentBuilder = struct {
    value: model.Component,
    meta_data: std.ArrayList(model.MetaData) = .empty,
    intent_filters: std.ArrayList(model.IntentFilter) = .empty,

    fn init(
        allocator: std.mem.Allocator,
        package_name: []const u8,
        kind: model.ComponentKind,
        element: axml.StartElement,
    ) Error!ComponentBuilder {
        const short_name = try requiredAndroidAttributeString(element, "name");
        const name = try normalizeClassName(allocator, package_name, short_name);

        return .{
            .value = .{
                .kind = kind,
                .name = name,
                .target_activity = if (findAndroidAttribute(element, "targetActivity")) |attribute|
                    if (attributeString(attribute)) |target|
                        try normalizeClassName(allocator, package_name, target)
                    else
                        null
                else
                    null,
                .exported = if (findAndroidAttribute(element, "exported")) |attribute|
                    try attributeBool(attribute)
                else
                    null,
                .enabled = if (findAndroidAttribute(element, "enabled")) |attribute|
                    try attributeBool(attribute)
                else
                    null,
                .permission = try copyOptionalAttributeString(allocator, element, "permission"),
                .process = try copyOptionalAttributeString(allocator, element, "process"),
                .authorities = try copyOptionalAttributeString(allocator, element, "authorities"),
                .label = if (findAndroidAttribute(element, "label")) |attribute|
                    try copyValue(allocator, attribute)
                else
                    .{},
                .icon = if (findAndroidAttribute(element, "icon")) |attribute|
                    try copyValue(allocator, attribute)
                else
                    .{},
            },
        };
    }

    fn finish(self: *ComponentBuilder, allocator: std.mem.Allocator) Error!model.Component {
        self.value.meta_data = try self.meta_data.toOwnedSlice(allocator);
        self.value.intent_filters = try self.intent_filters.toOwnedSlice(allocator);
        return self.value;
    }
};

const FilterBuilder = struct {
    actions: std.ArrayList([]const u8) = .empty,
    categories: std.ArrayList([]const u8) = .empty,
    data: std.ArrayList(model.IntentData) = .empty,

    fn finish(self: *FilterBuilder, allocator: std.mem.Allocator) Error!model.IntentFilter {
        return .{
            .actions = try self.actions.toOwnedSlice(allocator),
            .categories = try self.categories.toOwnedSlice(allocator),
            .data = try self.data.toOwnedSlice(allocator),
        };
    }
};

fn parseMetaData(allocator: std.mem.Allocator, element: axml.StartElement) Error!model.MetaData {
    const name = try requiredAndroidAttributeString(element, "name");
    const value_attribute = findAndroidAttribute(element, "value") orelse
        findAndroidAttribute(element, "resource") orelse
        return missingRequiredAndroidAttribute(element, "value/resource");
    return .{
        .name = try allocator.dupe(u8, name),
        .value = try copyValue(allocator, value_attribute),
    };
}

fn parseIntentData(allocator: std.mem.Allocator, element: axml.StartElement) Error!model.IntentData {
    return .{
        .scheme = try copyOptionalAttributeString(allocator, element, "scheme"),
        .host = try copyOptionalAttributeString(allocator, element, "host"),
        .port = try copyOptionalAttributeString(allocator, element, "port"),
        .path = try copyOptionalAttributeString(allocator, element, "path"),
        .path_prefix = try copyOptionalAttributeString(allocator, element, "pathPrefix"),
        .path_pattern = try copyOptionalAttributeString(allocator, element, "pathPattern"),
        .mime_type = try copyOptionalAttributeString(allocator, element, "mimeType"),
    };
}

fn componentKind(name: []const u8) ?model.ComponentKind {
    if (std.mem.eql(u8, name, "activity")) return .activity;
    if (std.mem.eql(u8, name, "activity-alias")) return .activity_alias;
    if (std.mem.eql(u8, name, "service")) return .service;
    if (std.mem.eql(u8, name, "receiver")) return .receiver;
    if (std.mem.eql(u8, name, "provider")) return .provider;
    return null;
}

fn normalizeClassName(
    allocator: std.mem.Allocator,
    package_name: []const u8,
    class_name: []const u8,
) std.mem.Allocator.Error![]const u8 {
    if (class_name.len == 0) return allocator.dupe(u8, class_name);
    if (class_name[0] == '.') return std.fmt.allocPrint(allocator, "{s}{s}", .{ package_name, class_name });
    if (std.mem.indexOfScalar(u8, class_name, '.') == null) {
        return std.fmt.allocPrint(allocator, "{s}.{s}", .{ package_name, class_name });
    }
    return allocator.dupe(u8, class_name);
}

fn isLauncherComponent(component: model.Component) bool {
    if (component.kind != .activity and component.kind != .activity_alias) return false;
    for (component.intent_filters) |filter| {
        var has_main = false;
        var has_launcher = false;
        for (filter.actions) |action| {
            if (std.mem.eql(u8, action, action_main)) has_main = true;
        }
        for (filter.categories) |category| {
            if (std.mem.eql(u8, category, category_launcher) or
                std.mem.eql(u8, category, category_leanback_launcher))
            {
                has_launcher = true;
            }
        }
        if (has_main and has_launcher) return true;
    }
    return false;
}

fn findAndroidAttribute(element: axml.StartElement, name: []const u8) ?*const axml.Attribute {
    for (element.attributes, 0..) |attribute, index| {
        if (!std.mem.eql(u8, attribute.name, name)) continue;
        const android_resource = if (attribute.resource_id) |resource_id|
            (resource_id >> 24) == 0x01
        else
            false;
        const android_uri = if (attribute.namespace_uri) |uri|
            std.mem.eql(u8, uri, android_namespace)
        else
            false;
        if (android_uri or android_resource) return &element.attributes[index];
    }
    return null;
}

fn findUnnamespacedAttribute(element: axml.StartElement, name: []const u8) ?*const axml.Attribute {
    for (element.attributes, 0..) |attribute, index| {
        if (attribute.namespace_uri == null and std.mem.eql(u8, attribute.name, name)) {
            return &element.attributes[index];
        }
    }
    return null;
}

fn findAttributeByName(element: axml.StartElement, name: []const u8) ?*const axml.Attribute {
    for (element.attributes, 0..) |attribute, index| {
        if (std.mem.eql(u8, attribute.name, name)) return &element.attributes[index];
    }
    return null;
}

fn attributeString(attribute: *const axml.Attribute) ?[]const u8 {
    return attribute.value_string orelse attribute.raw_value;
}

fn requiredAndroidAttributeString(element: axml.StartElement, name: []const u8) Error![]const u8 {
    const attribute = findAndroidAttribute(element, name) orelse return missingRequiredAndroidAttribute(element, name);
    return attributeString(attribute) orelse missingRequiredAndroidAttribute(element, name);
}

fn missingRequiredAndroidAttribute(element: axml.StartElement, name: []const u8) Error {
    logging.warn(.apk_android_manifest, @src(), "manifest required attribute missing element={s} attribute={s}", .{ element.name, name });
    return error.MissingRequiredAttribute;
}

fn attributeU32(attribute: *const axml.Attribute) Error!u32 {
    return switch (attribute.value.data_type) {
        .int_decimal, .int_hexadecimal, .int_boolean => attribute.value.data,
        .string => parseU32(attribute.value_string orelse return error.InvalidIntegerAttribute),
        else => if (attribute.raw_value) |raw| parseU32(raw) else error.InvalidIntegerAttribute,
    };
}

fn optionalAttributeU32(
    comptime source: std.builtin.SourceLocation,
    attribute: *const axml.Attribute,
    field: []const u8,
) ?u32 {
    return attributeU32(attribute) catch |err| {
        logging.warn(.apk_android_manifest, source, "manifest integer attribute ignored field={s} error={s}", .{ field, @errorName(err) });
        return null;
    };
}

fn parseU32(value: []const u8) Error!u32 {
    if (std.mem.startsWith(u8, value, "0x") or std.mem.startsWith(u8, value, "0X")) {
        return std.fmt.parseInt(u32, value[2..], 16) catch error.InvalidIntegerAttribute;
    }
    return std.fmt.parseInt(u32, value, 10) catch error.InvalidIntegerAttribute;
}

fn attributeBool(attribute: *const axml.Attribute) Error!?bool {
    if (attribute.value.boolValue()) |value| return value;
    switch (attribute.value.data_type) {
        .reference, .dynamic_reference, .attribute, .dynamic_attribute => return null,
        .int_decimal, .int_hexadecimal => return attribute.value.data != 0,
        else => {},
    }
    const string_value = attributeString(attribute) orelse return error.InvalidBooleanAttribute;
    if (std.ascii.eqlIgnoreCase(string_value, "true") or std.mem.eql(u8, string_value, "1")) return true;
    if (std.ascii.eqlIgnoreCase(string_value, "false") or std.mem.eql(u8, string_value, "0")) return false;
    return error.InvalidBooleanAttribute;
}

fn copyOptionalAttributeString(
    allocator: std.mem.Allocator,
    element: axml.StartElement,
    name: []const u8,
) Error!?[]const u8 {
    const attribute = findAndroidAttribute(element, name) orelse return null;
    const value = attributeString(attribute) orelse return null;
    return try allocator.dupe(u8, value);
}

fn copyValue(allocator: std.mem.Allocator, attribute: *const axml.Attribute) Error!model.Value {
    return .{
        .kind = valueKind(attribute.value.data_type),
        .raw = if (attribute.raw_value) |value| try allocator.dupe(u8, value) else null,
        .resolved = if (attribute.value_string) |value| try allocator.dupe(u8, value) else null,
        .data = attribute.value.data,
    };
}

fn valueKind(data_type: typed_value.DataType) model.ValueKind {
    return switch (data_type) {
        .null_value => .null_value,
        .string => .string,
        .reference, .dynamic_reference => .reference,
        .attribute, .dynamic_attribute => .attribute,
        .int_decimal, .int_hexadecimal => .integer,
        .int_boolean => .boolean,
        .color_argb8, .color_rgb8, .color_argb4, .color_rgb4 => .color,
        .float_value => .float,
        .dimension => .dimension,
        .fraction => .fraction,
        else => .unknown,
    };
}

test "normalizes Android component class names" {
    const allocator = std.testing.allocator;
    const relative = try normalizeClassName(allocator, "dev.example", ".MainActivity");
    defer allocator.free(relative);
    try std.testing.expectEqualStrings("dev.example.MainActivity", relative);

    const short = try normalizeClassName(allocator, "dev.example", "MainActivity");
    defer allocator.free(short);
    try std.testing.expectEqualStrings("dev.example.MainActivity", short);

    const qualified = try normalizeClassName(allocator, "dev.example", "other.app.MainActivity");
    defer allocator.free(qualified);
    try std.testing.expectEqualStrings("other.app.MainActivity", qualified);
}

test "launcher detection requires MAIN and a launcher category" {
    const component: model.Component = .{
        .kind = .activity,
        .name = "dev.example.MainActivity",
        .intent_filters = &.{.{
            .actions = &.{action_main},
            .categories = &.{category_launcher},
        }},
    };
    try std.testing.expect(isLauncherComponent(component));
}

test "ignores queries provider without component name" {
    const allocator = std.testing.allocator;
    const android_name = [_]axml.Attribute{.{
        .namespace_uri = android_namespace,
        .name = "name",
        .raw_value = "dev.example",
        .value = .{ .size = 8, .data_type = .string, .data = 0 },
        .value_string = "dev.example",
        .resource_id = 0x01010003,
        .namespace_index = 0,
        .name_index = 0,
        .raw_value_index = 0,
    }};
    const query_provider_attributes = [_]axml.Attribute{.{
        .namespace_uri = android_namespace,
        .name = "authorities",
        .raw_value = "com.example.provider",
        .value = .{ .size = 8, .data_type = .string, .data = 0 },
        .value_string = "com.example.provider",
        .resource_id = 0x01010018,
        .namespace_index = 0,
        .name_index = 0,
        .raw_value_index = 0,
    }};
    const node: axml.Node = .{ .line_number = 1, .comment = null };
    const events = [_]axml.Event{
        .{ .start_element = .{ .node = node, .namespace_uri = null, .name = "manifest", .attributes = &.{.{ .namespace_uri = null, .name = "package", .raw_value = "dev.example", .value = .{ .size = 8, .data_type = .string, .data = 0 }, .value_string = "dev.example", .resource_id = null, .namespace_index = 0, .name_index = 0, .raw_value_index = 0 }}, .namespace_index = 0, .name_index = 0, .id_attribute = null, .class_attribute = null, .style_attribute = null } },
        .{ .start_element = .{ .node = node, .namespace_uri = null, .name = "queries", .attributes = &.{}, .namespace_index = 0, .name_index = 0, .id_attribute = null, .class_attribute = null, .style_attribute = null } },
        .{ .start_element = .{ .node = node, .namespace_uri = null, .name = "provider", .attributes = &query_provider_attributes, .namespace_index = 0, .name_index = 0, .id_attribute = null, .class_attribute = null, .style_attribute = null } },
        .{ .end_element = .{ .node = node, .namespace_uri = null, .name = "provider", .namespace_index = 0, .name_index = 0 } },
        .{ .end_element = .{ .node = node, .namespace_uri = null, .name = "queries", .namespace_index = 0, .name_index = 0 } },
        .{ .start_element = .{ .node = node, .namespace_uri = null, .name = "application", .attributes = &.{}, .namespace_index = 0, .name_index = 0, .id_attribute = null, .class_attribute = null, .style_attribute = null } },
        .{ .start_element = .{ .node = node, .namespace_uri = null, .name = "activity", .attributes = &android_name, .namespace_index = 0, .name_index = 0, .id_attribute = null, .class_attribute = null, .style_attribute = null } },
        .{ .end_element = .{ .node = node, .namespace_uri = null, .name = "activity", .namespace_index = 0, .name_index = 0 } },
        .{ .end_element = .{ .node = node, .namespace_uri = null, .name = "application", .namespace_index = 0, .name_index = 0 } },
        .{ .end_element = .{ .node = node, .namespace_uri = null, .name = "manifest", .namespace_index = 0, .name_index = 0 } },
    };
    var document: axml.Document = undefined;
    document.events = &events;
    var info: model.ApkInfo = .{};
    try apply(allocator, &document, &info);
    defer allocator.free(info.components);
    defer allocator.free(info.components[0].name);
    defer allocator.free(info.package_name.?);
    try std.testing.expectEqual(@as(usize, 1), info.components.len);
    try std.testing.expectEqual(model.ComponentKind.activity, info.components[0].kind);
}
