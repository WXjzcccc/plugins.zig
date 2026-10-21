//! Key-name comparison and hashing following Windows rules.
//!
//! Registry key names are **case-insensitive**. Windows orders subkey lists
//! (`lf`/`lh`) by case-folded name and binary-searches them: a mis-ordered
//! list makes keys unfindable on the Windows side. This module provides the
//! reference ordering and hashing.
//!
//! Case folding is applied per UTF-16 code unit. For the ASCII plane (which
//! covers every standard registry name, BCD included) it exactly matches
//! `RtlUpcaseUnicodeString`. Beyond that, non-ASCII code units are compared
//! as-is; this is a documented, accepted limitation.
//!
//! Comparison and hashing both walk the UTF-16 code-unit sequence of the
//! name, as the REGF specification requires. For pure-ASCII names this is
//! identical to walking the UTF-8 bytes.

const std = @import("std");

/// Folds a UTF-16 code unit to uppercase (ASCII plane).
pub inline fn upcase(u: u16) u16 {
    return if (u >= 'a' and u <= 'z') u - 0x20 else u;
}

/// Lazily decodes a UTF-8 string into its UTF-16 code units, replacing
/// malformed sequences with U+FFFD so comparison never fails.
pub const Utf16Units = struct {
    s: []const u8,
    i: usize = 0,
    /// Pending low surrogate of a previously decoded astral code point.
    lo: ?u16 = null,

    pub fn next(self: *Utf16Units) ?u16 {
        if (self.lo) |lo| {
            self.lo = null;
            return lo;
        }
        if (self.i >= self.s.len) return null;
        const cp = self.nextCodepoint();
        if (cp < 0x10000) return @intCast(cp);
        const c = cp - 0x10000;
        self.lo = @intCast(0xDC00 + (c & 0x3FF));
        return @intCast(0xD800 + (c >> 10));
    }

    fn nextCodepoint(self: *Utf16Units) u21 {
        const first = self.s[self.i];
        const len = std.unicode.utf8ByteSequenceLength(first) catch {
            self.i += 1;
            return 0xFFFD;
        };
        if (self.i + len > self.s.len) {
            self.i += 1;
            return 0xFFFD;
        }
        const cp = std.unicode.utf8Decode(self.s[self.i..][0..len]) catch {
            self.i += 1;
            return 0xFFFD;
        };
        self.i += len;
        return cp;
    }
};

/// Compares two names the way Windows does: UTF-16 code unit by code unit,
/// after case folding.
pub fn cmpStr(a: []const u8, b: []const u8) std.math.Order {
    var ai: Utf16Units = .{ .s = a };
    var bi: Utf16Units = .{ .s = b };
    while (true) {
        const x = ai.next();
        const y = bi.next();
        if (x == null and y == null) return .eq;
        if (x == null) return .lt;
        if (y == null) return .gt;
        const xu = upcase(x.?);
        const yu = upcase(y.?);
        if (xu != yu) return std.math.order(xu, yu);
    }
}

/// Case-insensitive equality under the same rule.
pub fn eqName(a: []const u8, b: []const u8) bool {
    return cmpStr(a, b) == .eq;
}

/// `lh` hash of a name: `H = 37 * H + upcase(unit)` over the name's UTF-16
/// code units. This is the hash stored in `lh` entries, which Windows
/// compares before the name during binary search; it must therefore be exact.
pub fn lhHash(name: []const u8) u32 {
    var hash: u32 = 0;
    var it: Utf16Units = .{ .s = name };
    while (it.next()) |u| {
        hash = hash *% 37 +% @as(u32, upcase(u));
    }
    return hash;
}

test "case-insensitive equality" {
    try std.testing.expect(eqName("Elements", "elements"));
    try std.testing.expect(eqName("24000002", "24000002"));
    try std.testing.expect(!eqName("Foo", "Bar"));
    try std.testing.expect(eqName("", ""));
    try std.testing.expect(!eqName("", "a"));
}

test "ordering matches ascii upcase" {
    try std.testing.expectEqual(std.math.Order.lt, cmpStr("A", "b"));
    try std.testing.expectEqual(std.math.Order.lt, cmpStr("a", "B"));
    try std.testing.expectEqual(std.math.Order.eq, cmpStr("aBc", "AbC"));
    // A shorter prefix sorts first.
    try std.testing.expectEqual(std.math.Order.lt, cmpStr("ab", "abc"));
    try std.testing.expectEqual(std.math.Order.gt, cmpStr("abc", "ab"));
}

test "sorting a list of numeric names" {
    var names = [_][]const u8{ "24000010", "23000003", "24000001", "24000002" };
    std.mem.sort([]const u8, &names, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return cmpStr(a, b) == .lt;
        }
    }.lessThan);
    try std.testing.expectEqualStrings("23000003", names[0]);
    try std.testing.expectEqualStrings("24000001", names[1]);
    try std.testing.expectEqualStrings("24000002", names[2]);
    try std.testing.expectEqualStrings("24000010", names[3]);
}

test "hash is case-insensitive and type-distinct" {
    try std.testing.expectEqual(lhHash("abc"), lhHash("ABC"));
    try std.testing.expect(lhHash("abc") != lhHash("abd"));
    try std.testing.expect(lhHash("Element") != 0);
    try std.testing.expectEqual(@as(u32, 0), lhHash(""));
    // Known value: "A" -> 0x41.
    try std.testing.expectEqual(@as(u32, 0x41), lhHash("A"));
    // "AB" -> 0x41 * 37 + 0x42.
    try std.testing.expectEqual(@as(u32, 0x41 * 37 + 0x42), lhHash("AB"));
}

test "non-ascii names compare by utf-16 code unit" {
    // U+00E9 (e-acute) is 0xE9, which sorts above ASCII 'z' (0x7A).
    try std.testing.expectEqual(std.math.Order.gt, cmpStr("\u{e9}", "z"));
    // Astral code point: surrogate pair starts with 0xD83D.
    try std.testing.expectEqual(std.math.Order.gt, cmpStr("\u{1F600}", "z"));
    // Round-trip equality of identical non-ASCII names.
    try std.testing.expect(eqName("ключ", "ключ"));
    try std.testing.expect(!eqName("ключ", "ключ2"));
}

test "utf16 units of an astral code point" {
    var it: Utf16Units = .{ .s = "\u{1F600}" };
    try std.testing.expectEqual(@as(u16, 0xD83D), it.next().?);
    try std.testing.expectEqual(@as(u16, 0xDE00), it.next().?);
    try std.testing.expectEqual(@as(?u16, null), it.next());
}

test "malformed utf-8 degrades to replacement characters" {
    var it: Utf16Units = .{ .s = "\xFF\xFE" };
    try std.testing.expectEqual(@as(u16, 0xFFFD), it.next().?);
    try std.testing.expectEqual(@as(u16, 0xFFFD), it.next().?);
    try std.testing.expectEqual(@as(?u16, null), it.next());
}
