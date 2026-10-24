const std = @import("std");
const Cursor = @import("axml_zig").cursor.Cursor;

pub const minimum_size: u32 = 28;

pub const Error = Cursor.Error || error{
    InvalidConfigSize,
    InvalidLocale,
};

/// Locale qualifiers carried by `ResTable_config`.
///
/// Android stores the language and region in either a two-byte literal form or
/// a packed three-character form. The remaining locale qualifiers were added
/// in later config revisions. Fixed-size buffers keep parsing allocation-free.
pub const Locale = struct {
    language: [3]u8 = @splat(0),
    language_len: u8 = 0,
    region: [3]u8 = @splat(0),
    region_len: u8 = 0,
    script: [4]u8 = @splat(0),
    script_len: u8 = 0,
    variant: [8]u8 = @splat(0),
    variant_len: u8 = 0,
    numbering_system: [8]u8 = @splat(0),
    numbering_system_len: u8 = 0,

    pub fn isDefault(self: Locale) bool {
        return self.language_len == 0 and
            self.region_len == 0 and
            self.script_len == 0 and
            self.variant_len == 0 and
            self.numbering_system_len == 0;
    }

    pub fn languageSlice(self: *const Locale) []const u8 {
        return self.language[0..self.language_len];
    }

    pub fn regionSlice(self: *const Locale) []const u8 {
        return self.region[0..self.region_len];
    }

    pub fn scriptSlice(self: *const Locale) []const u8 {
        return self.script[0..self.script_len];
    }

    pub fn variantSlice(self: *const Locale) []const u8 {
        return self.variant[0..self.variant_len];
    }

    pub fn numberingSystemSlice(self: *const Locale) []const u8 {
        return self.numbering_system[0..self.numbering_system_len];
    }

    pub fn eql(a: Locale, b: Locale) bool {
        return std.mem.eql(u8, a.languageSlice(), b.languageSlice()) and
            std.mem.eql(u8, a.regionSlice(), b.regionSlice()) and
            std.mem.eql(u8, a.scriptSlice(), b.scriptSlice()) and
            std.mem.eql(u8, a.variantSlice(), b.variantSlice()) and
            std.mem.eql(u8, a.numberingSystemSlice(), b.numberingSystemSlice());
    }

    pub fn sameLanguage(a: Locale, b: Locale) bool {
        return a.language_len != 0 and
            std.mem.eql(u8, a.languageSlice(), b.languageSlice());
    }

    /// Parses the common `ll`, `ll-RR`, `ll_Script_RR`, and Android `ll-rRR`
    /// forms. It is intended for resolver requests, not as a full BCP-47
    /// implementation.
    pub fn parse(tag: []const u8) Error!Locale {
        if (tag.len == 0) return .{};

        var result: Locale = .{};
        var parts = std.mem.tokenizeAny(u8, tag, "-_");
        const language = parts.next() orelse return error.InvalidLocale;
        try setLanguage(&result, language);

        while (parts.next()) |raw_part| {
            var part = raw_part;
            if (part.len == 3 and (part[0] == 'r' or part[0] == 'R')) {
                part = part[1..];
            }

            if (part.len == 4 and result.script_len == 0) {
                try setScript(&result, part);
            } else if ((part.len == 2 or part.len == 3) and result.region_len == 0) {
                try setRegion(&result, part);
            } else if (part.len <= result.variant.len and result.variant_len == 0) {
                try setVariant(&result, part);
            } else {
                return error.InvalidLocale;
            }
        }

        return result;
    }

    fn setLanguage(self: *Locale, value: []const u8) Error!void {
        if (value.len != 2 and value.len != 3) return error.InvalidLocale;
        for (value, 0..) |byte, index| {
            if (!std.ascii.isAlphabetic(byte)) return error.InvalidLocale;
            self.language[index] = std.ascii.toLower(byte);
        }
        self.language_len = @intCast(value.len);
    }

    fn setRegion(self: *Locale, value: []const u8) Error!void {
        if (value.len != 2 and value.len != 3) return error.InvalidLocale;
        for (value, 0..) |byte, index| {
            const valid = if (value.len == 2)
                std.ascii.isAlphabetic(byte)
            else
                std.ascii.isDigit(byte);
            if (!valid) return error.InvalidLocale;
            self.region[index] = if (std.ascii.isAlphabetic(byte))
                std.ascii.toUpper(byte)
            else
                byte;
        }
        self.region_len = @intCast(value.len);
    }

    fn setScript(self: *Locale, value: []const u8) Error!void {
        if (value.len != 4) return error.InvalidLocale;
        for (value, 0..) |byte, index| {
            if (!std.ascii.isAlphabetic(byte)) return error.InvalidLocale;
            self.script[index] = if (index == 0)
                std.ascii.toUpper(byte)
            else
                std.ascii.toLower(byte);
        }
        self.script_len = 4;
    }

    fn setVariant(self: *Locale, value: []const u8) Error!void {
        if (value.len == 0 or value.len > self.variant.len) return error.InvalidLocale;
        for (value, 0..) |byte, index| {
            if (!std.ascii.isAlphanumeric(byte)) return error.InvalidLocale;
            self.variant[index] = byte;
        }
        self.variant_len = @intCast(value.len);
    }
};

/// Parsed subset of `ResTable_config`, plus the most useful adjacent fields.
/// Unknown trailing fields remain safely ignored according to the declared
/// config size.
pub const Config = struct {
    size: u32 = minimum_size,
    mcc: u16 = 0,
    mnc: u16 = 0,
    locale: Locale = .{},
    orientation: u8 = 0,
    touchscreen: u8 = 0,
    density: u16 = 0,
    keyboard: u8 = 0,
    navigation: u8 = 0,
    input_flags: u8 = 0,
    screen_width: u16 = 0,
    screen_height: u16 = 0,
    sdk_version: u16 = 0,
    minor_version: u16 = 0,
    screen_layout: u8 = 0,
    ui_mode: u8 = 0,
    smallest_screen_width_dp: u16 = 0,
    screen_width_dp: u16 = 0,
    screen_height_dp: u16 = 0,
    screen_layout2: u8 = 0,
    color_mode: u8 = 0,

    pub fn isDefault(self: Config) bool {
        return self.mcc == 0 and
            self.mnc == 0 and
            self.locale.isDefault() and
            self.orientation == 0 and
            self.touchscreen == 0 and
            self.density == 0 and
            self.keyboard == 0 and
            self.navigation == 0 and
            self.input_flags == 0 and
            self.screen_width == 0 and
            self.screen_height == 0 and
            self.sdk_version == 0 and
            self.minor_version == 0 and
            self.screen_layout == 0 and
            self.ui_mode == 0 and
            self.smallest_screen_width_dp == 0 and
            self.screen_width_dp == 0 and
            self.screen_height_dp == 0 and
            self.screen_layout2 == 0 and
            self.color_mode == 0;
    }

    /// Parses one config from the beginning of `data`. Additional bytes after
    /// the declared config are allowed because callers commonly pass a complete
    /// type-chunk header view.
    pub fn parse(data: []const u8) Error!Config {
        var cursor = Cursor.init(data);
        const declared_size = try cursor.readInt(u32, .little);
        if (declared_size < minimum_size) return error.InvalidConfigSize;
        if (declared_size > data.len) return error.EndOfInput;

        const bytes = data[0..declared_size];
        var result: Config = .{ .size = declared_size };
        result.mcc = try intAt(u16, bytes, 4);
        result.mnc = try intAt(u16, bytes, 6);
        result.locale.language_len = decodeLanguageOrRegion(
            bytes[8..10],
            'a',
            &result.locale.language,
        );
        result.locale.region_len = decodeLanguageOrRegion(
            bytes[10..12],
            '0',
            &result.locale.region,
        );
        result.orientation = bytes[12];
        result.touchscreen = bytes[13];
        result.density = try intAt(u16, bytes, 14);
        result.keyboard = bytes[16];
        result.navigation = bytes[17];
        result.input_flags = bytes[18];
        result.screen_width = try intAt(u16, bytes, 20);
        result.screen_height = try intAt(u16, bytes, 22);
        result.sdk_version = try intAt(u16, bytes, 24);
        result.minor_version = try intAt(u16, bytes, 26);

        if (bytes.len >= 32) {
            result.screen_layout = bytes[28];
            result.ui_mode = bytes[29];
            result.smallest_screen_width_dp = try intAt(u16, bytes, 30);
        }
        if (bytes.len >= 36) {
            result.screen_width_dp = try intAt(u16, bytes, 32);
            result.screen_height_dp = try intAt(u16, bytes, 34);
        }
        if (bytes.len >= 40) {
            result.locale.script_len = copyZeroTerminated(
                result.locale.script[0..],
                bytes[36..40],
            );
        }
        if (bytes.len >= 48) {
            result.locale.variant_len = copyZeroTerminated(
                result.locale.variant[0..],
                bytes[40..48],
            );
        }
        if (bytes.len >= 52) {
            result.screen_layout2 = bytes[48];
            result.color_mode = bytes[49];
        }
        if (bytes.len >= 60) {
            result.locale.numbering_system_len = copyZeroTerminated(
                result.locale.numbering_system[0..],
                bytes[52..60],
            );
        }

        return result;
    }
};

fn intAt(comptime T: type, data: []const u8, offset: usize) Cursor.Error!T {
    return Cursor.init(data).intAt(T, offset, .little);
}

fn decodeLanguageOrRegion(
    encoded: *const [2]u8,
    base: u8,
    output: *[3]u8,
) u8 {
    if (encoded[0] == 0 and encoded[1] == 0) return 0;

    if ((encoded[0] & 0x80) != 0) {
        output[0] = base + (encoded[1] & 0x1f);
        output[1] = base + ((encoded[1] & 0xe0) >> 5) + ((encoded[0] & 0x03) << 3);
        output[2] = base + ((encoded[0] & 0x7c) >> 2);
        return 3;
    }

    output[0] = if (base == 'a') std.ascii.toLower(encoded[0]) else std.ascii.toUpper(encoded[0]);
    if (encoded[1] == 0) return 1;
    output[1] = if (base == 'a') std.ascii.toLower(encoded[1]) else std.ascii.toUpper(encoded[1]);
    return 2;
}

fn copyZeroTerminated(destination: []u8, source: []const u8) u8 {
    var length: usize = 0;
    while (length < source.len and source[length] != 0) : (length += 1) {
        destination[length] = source[length];
    }
    return @intCast(length);
}

test "config parses locale density sdk and modern locale fields" {
    var bytes: [60]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], 60, .little);
    bytes[8] = 'e';
    bytes[9] = 'n';
    bytes[10] = 'U';
    bytes[11] = 'S';
    std.mem.writeInt(u16, bytes[14..16], 480, .little);
    std.mem.writeInt(u16, bytes[24..26], 33, .little);
    @memcpy(bytes[36..40], "Latn");
    @memcpy(bytes[40..47], "POSIX42");
    @memcpy(bytes[52..56], "latn");

    const parsed = try Config.parse(&bytes);
    try std.testing.expectEqualStrings("en", parsed.locale.languageSlice());
    try std.testing.expectEqualStrings("US", parsed.locale.regionSlice());
    try std.testing.expectEqualStrings("Latn", parsed.locale.scriptSlice());
    try std.testing.expectEqualStrings("POSIX42", parsed.locale.variantSlice());
    try std.testing.expectEqualStrings("latn", parsed.locale.numberingSystemSlice());
    try std.testing.expectEqual(@as(u16, 480), parsed.density);
    try std.testing.expectEqual(@as(u16, 33), parsed.sdk_version);
}

test "locale request parsing is normalized and rejects malformed tags" {
    const locale = try Locale.parse("EN-latn-us");
    try std.testing.expectEqualStrings("en", locale.languageSlice());
    try std.testing.expectEqualStrings("Latn", locale.scriptSlice());
    try std.testing.expectEqualStrings("US", locale.regionSlice());
    try std.testing.expectError(error.InvalidLocale, Locale.parse("english-US"));
}

test "config rejects short and truncated declarations" {
    var short: [28]u8 = @splat(0);
    std.mem.writeInt(u32, short[0..4], 24, .little);
    try std.testing.expectError(error.InvalidConfigSize, Config.parse(&short));

    std.mem.writeInt(u32, short[0..4], 32, .little);
    try std.testing.expectError(error.EndOfInput, Config.parse(&short));
}
