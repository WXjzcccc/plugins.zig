const std = @import("std");
const axml = @import("axml_zig");
const chunk = axml.chunk;
const string_pool = axml.string_pool;
const typed_value = axml.typed_value;
const config_mod = @import("config.zig");
const cursor_mod = axml.cursor;
const logging = @import("../../../utils/logging.zig");

const Allocator = std.mem.Allocator;
const Cursor = cursor_mod.Cursor;

pub const table_package_type: u16 = 0x0200;
pub const table_type_type: u16 = 0x0201;
pub const table_type_spec_type: u16 = 0x0202;

pub const no_entry: u32 = 0xffff_ffff;
pub const type_flag_sparse: u8 = 0x01;
pub const type_flag_offset16: u8 = 0x02;
pub const entry_flag_complex: u16 = 0x0001;
pub const entry_flag_public: u16 = 0x0002;
pub const entry_flag_weak: u16 = 0x0004;
pub const entry_flag_compact: u16 = 0x0008;

const table_header_size = 12;
const package_header_size_without_type_offset = 284;
const package_header_size_with_type_offset = 288;
const type_spec_header_size = 16;
const type_header_prefix_size = 20;
const entry_header_size = 8;
const map_entry_header_size = 16;

pub const Error = Allocator.Error ||
    chunk.Error ||
    string_pool.Error ||
    string_pool.LookupError ||
    typed_value.Error ||
    config_mod.Error ||
    error{
        WrongChunkType,
        InvalidTableHeader,
        MissingGlobalStringPool,
        UnexpectedTableChunk,
        PackageCountMismatch,
        InvalidPackageHeader,
        InvalidPackageId,
        DuplicatePackageId,
        InvalidPackageName,
        InvalidUtf16,
        InvalidStringPoolOffset,
        MissingTypeStringPool,
        MissingKeyStringPool,
        InvalidTypeSpecHeader,
        InvalidTypeSpecSize,
        DuplicateTypeSpec,
        InvalidTypeHeader,
        InvalidTypeId,
        InvalidTypeIdOffset,
        InvalidTypeConfig,
        MissingTypeSpec,
        TypeSpecEntryCountMismatch,
        UnsupportedSparseEncoding,
        UnsupportedOffset16Encoding,
        UnsupportedTypeEncoding,
        InvalidEntryOffset,
        InvalidEntryData,
        InvalidEntryHeader,
        InvalidComplexEntry,
        UnsupportedCompactEntry,
        InvalidKeyIndex,
    };

pub const NameError = string_pool.LookupError || error{InvalidTypeId};

pub const ResourceId = struct {
    package_id: u8,
    type_id: u8,
    entry_id: u16,

    pub fn fromInt(value: u32) ResourceId {
        return .{
            .package_id = @truncate(value >> 24),
            .type_id = @truncate(value >> 16),
            .entry_id = @truncate(value),
        };
    }

    pub fn toInt(self: ResourceId) u32 {
        return (@as(u32, self.package_id) << 24) |
            (@as(u32, self.type_id) << 16) |
            self.entry_id;
    }

    pub fn isValid(self: ResourceId) bool {
        return self.package_id != 0 and self.type_id != 0;
    }
};

pub const Map = struct {
    name: u32,
    value: typed_value.Value,
};

pub const ComplexValue = struct {
    parent: u32,
    maps: []Map,
};

pub const EntryValue = union(enum) {
    simple: typed_value.Value,
    complex: ComplexValue,
};

pub const Entry = struct {
    size: u16,
    flags: u16,
    key_index: u32,
    value: EntryValue,

    pub fn isComplex(self: Entry) bool {
        return self.flags & entry_flag_complex != 0;
    }

    pub fn isPublic(self: Entry) bool {
        return self.flags & entry_flag_public != 0;
    }

    fn deinit(self: Entry, allocator: Allocator) void {
        switch (self.value) {
            .simple => {},
            .complex => |complex| allocator.free(complex.maps),
        }
    }
};

pub const TypeSpec = struct {
    id: u8,
    entry_flags: []u32,

    pub fn deinit(self: *TypeSpec, allocator: Allocator) void {
        allocator.free(self.entry_flags);
        self.* = undefined;
    }
};

pub const Type = struct {
    id: u8,
    flags: u8,
    config: config_mod.Config,
    entries: []?Entry,

    pub fn entry(self: *const Type, entry_id: u16) ?*const Entry {
        const index: usize = entry_id;
        if (index >= self.entries.len) return null;
        return if (self.entries[index]) |_| &self.entries[index].? else null;
    }

    pub fn deinit(self: *Type, allocator: Allocator) void {
        for (self.entries) |maybe_entry| {
            if (maybe_entry) |entry_value| entry_value.deinit(allocator);
        }
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const Package = struct {
    id: u8,
    name: []const u8,
    type_id_offset: u32,
    last_public_type: u32,
    last_public_key: u32,
    type_strings: string_pool.StringPool,
    key_strings: string_pool.StringPool,
    type_specs: []TypeSpec,
    types: []Type,

    pub fn localTypeId(self: *const Package, public_type_id: u8) ?u8 {
        if (@as(u32, public_type_id) <= self.type_id_offset) return null;
        const local = @as(u32, public_type_id) - self.type_id_offset;
        if (local == 0 or local > std.math.maxInt(u8)) return null;
        return @intCast(local);
    }

    pub fn publicTypeId(self: *const Package, local_type_id: u8) ?u8 {
        if (local_type_id == 0) return null;
        const public = @as(u32, local_type_id) + self.type_id_offset;
        if (public > std.math.maxInt(u8)) return null;
        return @intCast(public);
    }

    pub fn typeName(self: *const Package, local_type_id: u8) NameError![]const u8 {
        if (local_type_id == 0) return error.InvalidTypeId;
        return self.type_strings.get(local_type_id - 1);
    }

    pub fn keyName(self: *const Package, entry_value: *const Entry) string_pool.LookupError![]const u8 {
        return self.key_strings.get(entry_value.key_index);
    }

    pub fn findTypeSpec(self: *const Package, local_type_id: u8) ?*const TypeSpec {
        for (self.type_specs, 0..) |spec, index| {
            if (spec.id == local_type_id) return &self.type_specs[index];
        }
        return null;
    }

    pub fn deinit(self: *Package, allocator: Allocator) void {
        allocator.free(self.name);
        self.type_strings.deinit(allocator);
        self.key_strings.deinit(allocator);
        for (self.type_specs) |*spec| spec.deinit(allocator);
        allocator.free(self.type_specs);
        for (self.types) |*type_value| type_value.deinit(allocator);
        allocator.free(self.types);
        self.* = undefined;
    }
};

/// Fully owned representation of a compiled Android resource table. Parsed
/// strings and entries do not borrow the input bytes.
pub const Table = struct {
    allocator: Allocator,
    global_strings: string_pool.StringPool,
    packages: []Package,

    pub fn parse(allocator: Allocator, data: []const u8) Error!Table {
        logging.info(.apk_android_resources, @src(), "resource table parsing started bytes={d}", .{data.len});
        const table = parseImpl(allocator, data) catch |err| {
            logging.err(.apk_android_resources, @src(), "resource table parsing failed bytes={d} error={s}", .{
                data.len,
                @errorName(err),
            });
            return err;
        };
        logging.info(.apk_android_resources, @src(), "resource table parsed global_strings={d} packages={d}", .{
            table.global_strings.strings.len,
            table.packages.len,
        });
        return table;
    }

    fn parseImpl(allocator: Allocator, data: []const u8) Error!Table {
        const root = try chunk.parse(data);
        if (root.header.type_id != chunk.Type.table) return error.WrongChunkType;
        if (root.header.header_bytes < table_header_size) return error.InvalidTableHeader;

        const package_count_u32 = try Cursor.init(root.bytes).intAt(u32, chunk.header_size, .little);
        const package_count = try u32ToUsize(package_count_u32);

        var children = root.childIterator();
        var global_chunk: ?chunk.Chunk = null;
        while (try children.next()) |candidate| {
            // Some APK tools leave a RES_NULL_TYPE padding chunk before the
            // global pool. It carries no resource data and is safe to skip.
            if (candidate.header.type_id == chunk.Type.null_type) continue;
            global_chunk = candidate;
            break;
        }
        const global = global_chunk orelse return error.MissingGlobalStringPool;
        if (global.header.type_id != chunk.Type.string_pool) {
            return error.MissingGlobalStringPool;
        }
        var global_strings = try string_pool.StringPool.parse(allocator, global);
        errdefer global_strings.deinit(allocator);

        var packages: std.ArrayList(Package) = .empty;
        errdefer {
            for (packages.items) |*package| package.deinit(allocator);
            packages.deinit(allocator);
        }

        while (try children.next()) |child| {
            if (child.header.type_id != table_package_type) return error.UnexpectedTableChunk;
            var package = try parsePackage(allocator, child);
            errdefer package.deinit(allocator);
            for (packages.items) |existing| {
                if (existing.id == package.id) return error.DuplicatePackageId;
            }
            try packages.append(allocator, package);
        }

        if (packages.items.len != package_count) return error.PackageCountMismatch;
        return .{
            .allocator = allocator,
            .global_strings = global_strings,
            .packages = try packages.toOwnedSlice(allocator),
        };
    }

    pub fn deinit(self: *Table) void {
        self.global_strings.deinit(self.allocator);
        for (self.packages) |*package| package.deinit(self.allocator);
        self.allocator.free(self.packages);
        self.* = undefined;
    }

    pub fn findPackage(self: *const Table, package_id: u8) ?*const Package {
        for (self.packages, 0..) |package, index| {
            if (package.id == package_id) return &self.packages[index];
        }
        return null;
    }
};

pub fn parse(allocator: Allocator, data: []const u8) Error!Table {
    return Table.parse(allocator, data);
}

fn parsePackage(allocator: Allocator, source: chunk.Chunk) Error!Package {
    if (source.header.header_bytes < package_header_size_without_type_offset) {
        return error.InvalidPackageHeader;
    }
    const header = source.extraHeader();
    const package_id_u32 = try Cursor.init(header).intAt(u32, 0, .little);
    if (package_id_u32 > std.math.maxInt(u8)) return error.InvalidPackageId;
    const package_id: u8 = @intCast(package_id_u32);
    const name = try decodePackageName(allocator, header[4..260]);
    errdefer allocator.free(name);

    const type_strings_offset = try Cursor.init(header).intAt(u32, 260, .little);
    const last_public_type = try Cursor.init(header).intAt(u32, 264, .little);
    const key_strings_offset = try Cursor.init(header).intAt(u32, 268, .little);
    const last_public_key = try Cursor.init(header).intAt(u32, 272, .little);
    const type_id_offset = if (source.header.header_bytes >= package_header_size_with_type_offset)
        try Cursor.init(header).intAt(u32, 276, .little)
    else
        0;

    if (type_strings_offset == key_strings_offset or
        type_strings_offset < source.header.header_bytes or
        key_strings_offset < source.header.header_bytes or
        type_strings_offset >= source.header.size or
        key_strings_offset >= source.header.size)
    {
        return error.InvalidStringPoolOffset;
    }

    var type_strings: ?string_pool.StringPool = null;
    errdefer if (type_strings) |*pool| pool.deinit(allocator);
    var key_strings: ?string_pool.StringPool = null;
    errdefer if (key_strings) |*pool| pool.deinit(allocator);
    var specs: std.ArrayList(TypeSpec) = .empty;
    errdefer {
        for (specs.items) |*spec| spec.deinit(allocator);
        specs.deinit(allocator);
    }
    var types: std.ArrayList(Type) = .empty;
    errdefer {
        for (types.items) |*type_value| type_value.deinit(allocator);
        types.deinit(allocator);
    }

    var children = source.childIterator();
    while (try children.next()) |child| {
        const relative_offset = try checkedAdd(source.header.header_bytes, child.offset);
        const is_type_pool = relative_offset == type_strings_offset;
        const is_key_pool = relative_offset == key_strings_offset;

        if (is_type_pool or is_key_pool) {
            if (child.header.type_id != chunk.Type.string_pool) return error.InvalidStringPoolOffset;
            if (is_type_pool) {
                if (type_strings != null) return error.InvalidStringPoolOffset;
                type_strings = try string_pool.StringPool.parse(allocator, child);
            } else {
                if (key_strings != null) return error.InvalidStringPoolOffset;
                key_strings = try string_pool.StringPool.parse(allocator, child);
            }
            continue;
        }

        switch (child.header.type_id) {
            table_type_spec_type => {
                var spec = try parseTypeSpec(allocator, child);
                errdefer spec.deinit(allocator);
                for (specs.items) |existing| {
                    if (existing.id == spec.id) return error.DuplicateTypeSpec;
                }
                try specs.append(allocator, spec);
            },
            table_type_type => {
                var type_value = try parseType(allocator, child);
                errdefer type_value.deinit(allocator);
                try types.append(allocator, type_value);
            },
            else => {},
        }
    }

    if (type_strings == null) return error.MissingTypeStringPool;
    if (key_strings == null) return error.MissingKeyStringPool;
    try validatePackage(type_id_offset, type_strings.?, key_strings.?, specs.items, types.items);

    const owned_specs = try specs.toOwnedSlice(allocator);
    errdefer {
        for (owned_specs) |*spec| spec.deinit(allocator);
        allocator.free(owned_specs);
    }
    const owned_types = try types.toOwnedSlice(allocator);
    errdefer {
        for (owned_types) |*type_value| type_value.deinit(allocator);
        allocator.free(owned_types);
    }

    const package = Package{
        .id = package_id,
        .name = name,
        .type_id_offset = type_id_offset,
        .last_public_type = last_public_type,
        .last_public_key = last_public_key,
        .type_strings = type_strings.?,
        .key_strings = key_strings.?,
        .type_specs = owned_specs,
        .types = owned_types,
    };
    logging.debug(.apk_android_resources, @src(), "resource package parsed id=0x{x:0>2} name={s} type_specs={d} type_configs={d}", .{
        package.id,
        package.name,
        package.type_specs.len,
        package.types.len,
    });
    return package;
}

fn parseTypeSpec(allocator: Allocator, source: chunk.Chunk) Error!TypeSpec {
    if (source.header.header_bytes < type_spec_header_size) return error.InvalidTypeSpecHeader;
    const header = source.extraHeader();
    const id = header[0];
    if (id == 0) return error.InvalidTypeId;
    // Newer aapt2 versions use the reserved bytes for type-spec flags. They
    // do not change the entry-count or flag-array layout consumed below.

    const entry_count = try u32ToUsize(try Cursor.init(header).intAt(u32, 4, .little));
    const expected_size = try checkedMul(entry_count, @sizeOf(u32));
    if (source.body().len != expected_size) return error.InvalidTypeSpecSize;

    const flags = try allocator.alloc(u32, entry_count);
    errdefer allocator.free(flags);
    var body = Cursor.init(source.body());
    for (flags) |*flag| flag.* = try body.readInt(u32, .little);
    return .{ .id = id, .entry_flags = flags };
}

fn parseType(allocator: Allocator, source: chunk.Chunk) Error!Type {
    if (source.header.header_bytes < type_header_prefix_size + config_mod.minimum_size) {
        return error.InvalidTypeHeader;
    }
    const header = source.extraHeader();
    const id = header[0];
    const flags = header[1];
    if (id == 0) return error.InvalidTypeId;
    if (try Cursor.init(header).intAt(u16, 2, .little) != 0) return error.InvalidTypeHeader;
    if (flags & type_flag_sparse != 0) return error.UnsupportedSparseEncoding;
    if (flags & type_flag_offset16 != 0) return error.UnsupportedOffset16Encoding;
    if (flags != 0) return error.UnsupportedTypeEncoding;

    const entry_count = try u32ToUsize(try Cursor.init(header).intAt(u32, 4, .little));
    const entries_start = try u32ToUsize(try Cursor.init(header).intAt(u32, 8, .little));
    const parsed_config = try config_mod.Config.parse(header[12..]);
    const expected_header_size = try checkedAdd(type_header_prefix_size, parsed_config.size);
    if (expected_header_size != source.header.header_bytes) return error.InvalidTypeConfig;

    const offset_bytes = try checkedMul(entry_count, @sizeOf(u32));
    const expected_entries_start = try checkedAdd(source.header.header_bytes, offset_bytes);
    if (entries_start != expected_entries_start or entries_start > source.bytes.len) {
        return error.InvalidEntryOffset;
    }

    const offsets = try allocator.alloc(u32, entry_count);
    defer allocator.free(offsets);
    var offsets_cursor = Cursor.init(source.bytes[source.header.header_bytes..entries_start]);
    for (offsets) |*offset| offset.* = try offsets_cursor.readInt(u32, .little);

    const entry_data = source.bytes[entries_start..];
    var previous: ?u32 = null;
    for (offsets) |offset| {
        if (offset == no_entry) continue;
        if (offset >= entry_data.len) return error.InvalidEntryOffset;
        if (previous) |last| {
            if (offset <= last) return error.InvalidEntryOffset;
        } else if (offset != 0) {
            return error.InvalidEntryOffset;
        }
        previous = offset;
    }
    if (previous == null and entry_data.len != 0) return error.InvalidEntryData;

    const entries = try allocator.alloc(?Entry, entry_count);
    for (entries) |*entry_value| entry_value.* = null;
    errdefer {
        for (entries) |maybe_entry| {
            if (maybe_entry) |entry_value| entry_value.deinit(allocator);
        }
        allocator.free(entries);
    }

    var segment_end = entry_data.len;
    var index = offsets.len;
    while (index > 0) {
        index -= 1;
        const offset = offsets[index];
        if (offset == no_entry) continue;
        const start: usize = @intCast(offset);
        if (start >= segment_end) return error.InvalidEntryOffset;
        entries[index] = try parseEntry(allocator, entry_data[start..segment_end]);
        segment_end = start;
    }

    return .{
        .id = id,
        .flags = flags,
        .config = parsed_config,
        .entries = entries,
    };
}

fn parseEntry(allocator: Allocator, data: []const u8) Error!Entry {
    var cursor = Cursor.init(data);
    const size = try cursor.readInt(u16, .little);
    const flags = try cursor.readInt(u16, .little);
    const key_index = try cursor.readInt(u32, .little);
    if (flags & entry_flag_compact != 0) return error.UnsupportedCompactEntry;
    if (size < entry_header_size) return error.InvalidEntryHeader;

    if (flags & entry_flag_complex != 0) {
        if (size < map_entry_header_size) return error.InvalidComplexEntry;
        const parent = try cursor.readInt(u32, .little);
        const count = try u32ToUsize(try cursor.readInt(u32, .little));
        try cursor.skip(size - map_entry_header_size);
        if (count > cursor.remaining() / (4 + typed_value.minimum_size)) {
            return error.InvalidComplexEntry;
        }

        const maps = try allocator.alloc(Map, count);
        errdefer allocator.free(maps);
        for (maps) |*map| {
            map.name = try cursor.readInt(u32, .little);
            map.value = try typed_value.read(&cursor);
        }
        if (!cursor.atEnd()) return error.InvalidEntryData;
        return .{
            .size = size,
            .flags = flags,
            .key_index = key_index,
            .value = .{ .complex = .{ .parent = parent, .maps = maps } },
        };
    }

    try cursor.skip(size - entry_header_size);
    const value = try typed_value.read(&cursor);
    if (!cursor.atEnd()) return error.InvalidEntryData;
    return .{
        .size = size,
        .flags = flags,
        .key_index = key_index,
        .value = .{ .simple = value },
    };
}

fn validatePackage(
    type_id_offset: u32,
    type_strings: string_pool.StringPool,
    key_strings: string_pool.StringPool,
    specs: []const TypeSpec,
    types: []const Type,
) Error!void {
    for (specs) |spec| {
        const public_id = @as(u32, spec.id) + type_id_offset;
        if (public_id == 0 or public_id > std.math.maxInt(u8)) return error.InvalidTypeIdOffset;
        _ = try type_strings.get(spec.id - 1);
    }

    for (types) |type_value| {
        const public_id = @as(u32, type_value.id) + type_id_offset;
        if (public_id == 0 or public_id > std.math.maxInt(u8)) return error.InvalidTypeIdOffset;
        _ = try type_strings.get(type_value.id - 1);
        const spec = findSpec(specs, type_value.id) orelse return error.MissingTypeSpec;
        if (spec.entry_flags.len != type_value.entries.len) {
            return error.TypeSpecEntryCountMismatch;
        }
        for (type_value.entries) |maybe_entry| {
            if (maybe_entry) |entry_value| {
                if (entry_value.key_index >= key_strings.strings.len) return error.InvalidKeyIndex;
            }
        }
    }
}

fn findSpec(specs: []const TypeSpec, id: u8) ?*const TypeSpec {
    for (specs, 0..) |spec, index| {
        if (spec.id == id) return &specs[index];
    }
    return null;
}

fn decodePackageName(allocator: Allocator, encoded: []const u8) Error![]const u8 {
    if (encoded.len != 256) return error.InvalidPackageHeader;
    var unit_count: usize = 0;
    while (unit_count < 128) : (unit_count += 1) {
        const unit = try Cursor.init(encoded).intAt(u16, unit_count * 2, .little);
        if (unit == 0) break;
    }
    if (unit_count == 0) return error.InvalidPackageName;

    const data = encoded[0 .. unit_count * 2];
    var scan: usize = 0;
    var output_len: usize = 0;
    while (scan < unit_count) {
        const codepoint = try nextUtf16Codepoint(data, unit_count, &scan);
        output_len = try checkedAdd(
            output_len,
            std.unicode.utf8CodepointSequenceLength(codepoint) catch return error.InvalidUtf16,
        );
    }

    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);
    scan = 0;
    var output_offset: usize = 0;
    while (scan < unit_count) {
        const codepoint = try nextUtf16Codepoint(data, unit_count, &scan);
        output_offset += std.unicode.utf8Encode(codepoint, output[output_offset..]) catch {
            return error.InvalidUtf16;
        };
    }
    return output;
}

fn nextUtf16Codepoint(data: []const u8, unit_count: usize, index: *usize) Error!u21 {
    const first = try Cursor.init(data).intAt(u16, index.* * 2, .little);
    index.* += 1;
    if (first >= 0xd800 and first <= 0xdbff) {
        if (index.* >= unit_count) return error.InvalidUtf16;
        const second = try Cursor.init(data).intAt(u16, index.* * 2, .little);
        if (second < 0xdc00 or second > 0xdfff) return error.InvalidUtf16;
        index.* += 1;
        return 0x10000 + (@as(u21, first - 0xd800) << 10) + @as(u21, second - 0xdc00);
    }
    if (first >= 0xdc00 and first <= 0xdfff) return error.InvalidUtf16;
    return @intCast(first);
}

fn checkedAdd(a: anytype, b: anytype) Cursor.Error!usize {
    return cursor_mod.checkedAdd(@intCast(a), @intCast(b));
}

fn checkedMul(a: usize, b: usize) Cursor.Error!usize {
    const result = @mulWithOverflow(a, b);
    if (result[1] != 0) return error.IntegerOverflow;
    return result[0];
}

fn u32ToUsize(value: u32) Cursor.Error!usize {
    if (value > std.math.maxInt(usize)) return error.IntegerOverflow;
    return @intCast(value);
}

test "resource id fields round trip" {
    const decoded = ResourceId.fromInt(0x7f02_1234);
    try std.testing.expectEqual(@as(u8, 0x7f), decoded.package_id);
    try std.testing.expectEqual(@as(u8, 0x02), decoded.type_id);
    try std.testing.expectEqual(@as(u16, 0x1234), decoded.entry_id);
    try std.testing.expectEqual(@as(u32, 0x7f02_1234), decoded.toInt());
}

test "resource table ignores leading null padding" {
    const base = try buildTestTable(std.testing.allocator, 0, 0);
    defer std.testing.allocator.free(base);

    const padded = try std.testing.allocator.alloc(u8, base.len + 8);
    defer std.testing.allocator.free(padded);
    @memcpy(padded[0..12], base[0..12]);
    @memset(padded[12..20], 0);
    testPatchInt(u16, padded, 14, 8);
    testPatchInt(u32, padded, 16, 8);
    @memcpy(padded[20..], base[12..]);
    testPatchInt(u32, padded, 4, @intCast(padded.len));

    var resources = try Table.parse(std.testing.allocator, padded);
    defer resources.deinit();
    try std.testing.expectEqual(@as(usize, 2), resources.packages.len);
}

test "constructive table parses multiple packages simple and complex entries" {
    const bytes = try buildTestTable(std.testing.allocator, 0, 0);
    defer std.testing.allocator.free(bytes);

    var resources = try Table.parse(std.testing.allocator, bytes);
    defer resources.deinit();
    try std.testing.expectEqual(@as(usize, 2), resources.packages.len);
    try std.testing.expectEqualStrings("hello", try resources.global_strings.get(0));

    const app = resources.findPackage(0x7f) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("app", app.name);
    try std.testing.expectEqual(@as(u32, 1), app.type_id_offset);
    try std.testing.expectEqual(@as(?u8, 2), app.publicTypeId(1));
    try std.testing.expectEqualStrings("string", try app.typeName(1));
    try std.testing.expectEqual(@as(usize, 1), app.type_specs.len);
    try std.testing.expectEqual(@as(usize, 1), app.types.len);

    const simple = app.types[0].entry(0) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("title", try app.keyName(simple));
    switch (simple.value) {
        .simple => |value| {
            try std.testing.expectEqual(typed_value.DataType.string, value.data_type);
            try std.testing.expectEqual(@as(u32, 0), value.data);
        },
        .complex => return error.TestExpectedEqual,
    }

    const complex = app.types[0].entry(1) orelse return error.TestExpectedEqual;
    switch (complex.value) {
        .simple => return error.TestExpectedEqual,
        .complex => |bag| {
            try std.testing.expectEqual(@as(u32, 0), bag.parent);
            try std.testing.expectEqual(@as(usize, 1), bag.maps.len);
            try std.testing.expectEqual(@as(u32, 0x0101_0000), bag.maps[0].name);
            try std.testing.expectEqual(@as(i32, 42), bag.maps[0].value.intValue().?);
        },
    }

    const framework = resources.findPackage(0x01) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("android", framework.name);
}

test "unsupported resource encodings are explicit" {
    const sparse = try buildTestTable(std.testing.allocator, type_flag_sparse, 0);
    defer std.testing.allocator.free(sparse);
    try std.testing.expectError(
        error.UnsupportedSparseEncoding,
        Table.parse(std.testing.allocator, sparse),
    );

    const offset16 = try buildTestTable(std.testing.allocator, type_flag_offset16, 0);
    defer std.testing.allocator.free(offset16);
    try std.testing.expectError(
        error.UnsupportedOffset16Encoding,
        Table.parse(std.testing.allocator, offset16),
    );

    const compact = try buildTestTable(std.testing.allocator, 0, entry_flag_compact);
    defer std.testing.allocator.free(compact);
    try std.testing.expectError(
        error.UnsupportedCompactEntry,
        Table.parse(std.testing.allocator, compact),
    );
}

fn buildTestTable(
    allocator: Allocator,
    first_type_flags: u8,
    first_entry_flags: u16,
) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    const table_start = try testBeginChunk(&bytes, allocator, chunk.Type.table, table_header_size);
    try testAppendInt(&bytes, allocator, u32, 2);
    try testAppendStringPool(&bytes, allocator, &.{ "hello", "world" });
    try testAppendPackage(
        &bytes,
        allocator,
        0x7f,
        "app",
        1,
        first_type_flags,
        first_entry_flags,
    );
    try testAppendPackage(&bytes, allocator, 0x01, "android", 0, 0, 0);
    try testFinishChunk(&bytes, allocator, table_start);
    return bytes.toOwnedSlice(allocator);
}

fn testAppendPackage(
    bytes: *std.ArrayList(u8),
    allocator: Allocator,
    package_id: u32,
    name: []const u8,
    type_id_offset: u32,
    type_flags: u8,
    first_entry_flags: u16,
) !void {
    const start = try testBeginChunk(
        bytes,
        allocator,
        table_package_type,
        package_header_size_with_type_offset,
    );
    try testAppendInt(bytes, allocator, u32, package_id);
    for (0..128) |index| {
        const unit: u16 = if (index < name.len) name[index] else 0;
        try testAppendInt(bytes, allocator, u16, unit);
    }
    const type_strings_position = bytes.items.len;
    try testAppendInt(bytes, allocator, u32, 0);
    try testAppendInt(bytes, allocator, u32, 1);
    const key_strings_position = bytes.items.len;
    try testAppendInt(bytes, allocator, u32, 0);
    try testAppendInt(bytes, allocator, u32, 2);
    try testAppendInt(bytes, allocator, u32, type_id_offset);

    testPatchInt(u32, bytes.items, type_strings_position, @intCast(bytes.items.len - start));
    try testAppendStringPool(bytes, allocator, &.{"string"});
    testPatchInt(u32, bytes.items, key_strings_position, @intCast(bytes.items.len - start));
    try testAppendStringPool(bytes, allocator, &.{ "title", "style" });
    try testAppendTypeSpec(bytes, allocator);
    try testAppendType(bytes, allocator, type_flags, first_entry_flags);
    try testFinishChunk(bytes, allocator, start);
}

fn testAppendTypeSpec(bytes: *std.ArrayList(u8), allocator: Allocator) !void {
    const start = try testBeginChunk(
        bytes,
        allocator,
        table_type_spec_type,
        type_spec_header_size,
    );
    try bytes.append(allocator, 1);
    try bytes.append(allocator, 0);
    try testAppendInt(bytes, allocator, u16, 0);
    try testAppendInt(bytes, allocator, u32, 2);
    try testAppendInt(bytes, allocator, u32, 0);
    try testAppendInt(bytes, allocator, u32, 0);
    try testFinishChunk(bytes, allocator, start);
}

fn testAppendType(
    bytes: *std.ArrayList(u8),
    allocator: Allocator,
    encoding_flags: u8,
    first_entry_flags: u16,
) !void {
    const header_bytes: u16 = type_header_prefix_size + config_mod.minimum_size;
    const start = try testBeginChunk(bytes, allocator, table_type_type, header_bytes);
    try bytes.append(allocator, 1);
    try bytes.append(allocator, encoding_flags);
    try testAppendInt(bytes, allocator, u16, 0);
    try testAppendInt(bytes, allocator, u32, 2);
    try testAppendInt(bytes, allocator, u32, header_bytes + 8);

    try testAppendInt(bytes, allocator, u32, config_mod.minimum_size);
    try bytes.appendNTimes(allocator, 0, config_mod.minimum_size - 4);
    try testAppendInt(bytes, allocator, u32, 0);
    try testAppendInt(bytes, allocator, u32, 16);

    try testAppendInt(bytes, allocator, u16, entry_header_size);
    try testAppendInt(bytes, allocator, u16, first_entry_flags);
    try testAppendInt(bytes, allocator, u32, 0);
    try testAppendValue(bytes, allocator, .string, 0);

    try testAppendInt(bytes, allocator, u16, map_entry_header_size);
    try testAppendInt(bytes, allocator, u16, entry_flag_complex);
    try testAppendInt(bytes, allocator, u32, 1);
    try testAppendInt(bytes, allocator, u32, 0);
    try testAppendInt(bytes, allocator, u32, 1);
    try testAppendInt(bytes, allocator, u32, 0x0101_0000);
    try testAppendValue(bytes, allocator, .int_decimal, 42);
    try testFinishChunk(bytes, allocator, start);
}

fn testAppendValue(
    bytes: *std.ArrayList(u8),
    allocator: Allocator,
    data_type: typed_value.DataType,
    data: u32,
) !void {
    try testAppendInt(bytes, allocator, u16, typed_value.minimum_size);
    try bytes.append(allocator, 0);
    try bytes.append(allocator, @backingInt(data_type));
    try testAppendInt(bytes, allocator, u32, data);
}

fn testAppendStringPool(
    bytes: *std.ArrayList(u8),
    allocator: Allocator,
    strings: []const []const u8,
) !void {
    const start = try testBeginChunk(bytes, allocator, chunk.Type.string_pool, 28);
    try testAppendInt(bytes, allocator, u32, @intCast(strings.len));
    try testAppendInt(bytes, allocator, u32, 0);
    try testAppendInt(bytes, allocator, u32, string_pool.utf8_flag);
    const strings_start: u32 = @intCast(28 + strings.len * 4);
    try testAppendInt(bytes, allocator, u32, strings_start);
    try testAppendInt(bytes, allocator, u32, 0);

    var relative_offset: u32 = 0;
    for (strings) |string| {
        try testAppendInt(bytes, allocator, u32, relative_offset);
        relative_offset += @intCast(2 + string.len + 1);
    }
    for (strings) |string| {
        std.debug.assert(string.len < 0x80);
        try bytes.append(allocator, @intCast(string.len));
        try bytes.append(allocator, @intCast(string.len));
        try bytes.appendSlice(allocator, string);
        try bytes.append(allocator, 0);
    }
    try testFinishChunk(bytes, allocator, start);
}

fn testBeginChunk(
    bytes: *std.ArrayList(u8),
    allocator: Allocator,
    type_id: u16,
    header_bytes: u16,
) !usize {
    const start = bytes.items.len;
    try testAppendInt(bytes, allocator, u16, type_id);
    try testAppendInt(bytes, allocator, u16, header_bytes);
    try testAppendInt(bytes, allocator, u32, 0);
    return start;
}

fn testFinishChunk(bytes: *std.ArrayList(u8), allocator: Allocator, start: usize) !void {
    while ((bytes.items.len - start) % 4 != 0) try bytes.append(allocator, 0);
    testPatchInt(u32, bytes.items, start + 4, @intCast(bytes.items.len - start));
}

fn testAppendInt(
    bytes: *std.ArrayList(u8),
    allocator: Allocator,
    comptime T: type,
    value: T,
) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try bytes.appendSlice(allocator, &encoded);
}

fn testPatchInt(
    comptime T: type,
    bytes: []u8,
    offset: usize,
    value: T,
) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}
