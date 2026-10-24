//! Minimal JWT payload reader.
//!
//! `user_info.ini` stores the login token as a JWT. Only the payload's
//! claims matter for the analysis (user id, device id, login ip, issue
//! time); the signature is not verified — a forensic reader treats the
//! token as recorded data, not as a trust anchor. Decoding base64url is
//! standard parsing, not cryptography.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Claim = struct {
    /// `sub` — the account's user id.
    sub: ?[]const u8 = null,
    /// `device_id` — the internal device identifier of the issuing machine.
    device_id: ?[]const u8 = null,
    /// `client_id` — the install uuid (matches `config.ini`).
    client_id: ?[]const u8 = null,
    /// `system_id` — the OS installation identifier.
    system_id: ?[]const u8 = null,
    /// `ip` — the login ip as seen by the issuing server.
    ip: ?[]const u8 = null,
    /// `jti` — the token instance id.
    jti: ?[]const u8 = null,
    /// `iat` — issued-at, Unix seconds.
    issued_at: ?i64 = null,
};

pub const Error = error{OutOfMemory};

/// Decodes the JWT payload of `token` into `Claim`s. Every decoded value is
/// duped into `alloc`. Returns null when the token is not a decodable JWT
/// (three dot-separated parts, base64url payload, JSON object).
pub fn decodePayload(alloc: Allocator, token: []const u8) Error!?Claim {
    const first = std.mem.indexOfScalar(u8, token, '.') orelse return null;
    const second = std.mem.lastIndexOfScalar(u8, token, '.') orelse return null;
    if (second <= first) return null;
    const payload_b64 = token[first + 1 .. second];

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const padded_len = decoder.calcSizeForSlice(payload_b64) catch return null;
    const json_bytes = try alloc.alloc(u8, padded_len);
    defer alloc.free(json_bytes);
    decoder.decode(json_bytes, payload_b64) catch return null;

    // The payload is a small flat JSON object; std.json's `Value` keeps the
    // parse tolerant (unknown fields ignored, non-object payloads rejected).
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, json_bytes, .{}) catch return null;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |map| map,
        else => return null,
    };

    var claim = Claim{};
    claim.sub = try dupeString(alloc, object.get("sub"));
    claim.device_id = try dupeString(alloc, object.get("device_id"));
    claim.client_id = try dupeString(alloc, object.get("client_id"));
    claim.system_id = try dupeString(alloc, object.get("system_id"));
    claim.ip = try dupeString(alloc, object.get("ip"));
    claim.jti = try dupeString(alloc, object.get("jti"));
    if (object.get("iat")) |value| {
        claim.issued_at = switch (value) {
            .integer => |number| number,
            .float => |number| @intFromFloat(number),
            else => null,
        };
    }
    return claim;
}

fn dupeString(alloc: Allocator, value: ?std.json.Value) Error!?[]const u8 {
    const text = switch (value orelse return null) {
        .string => |text| text,
        else => return null,
    };
    return try alloc.dupe(u8, text);
}

const testing = std.testing;

test "decodes the claims of a real-shaped token" {
    // A syntactically valid JWT (header.payload.signature, HS256 header);
    // the payload claims are the ones user_info.ini carries.
    const token = "eyJhbGciOiJIUzI1NiIsImtpZCI6InYyIiwidHlwIjoiSldUIn0." ++
        "eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzg0Mjc0Mjk4LCJqdGkiOiJkMGUxMTkwOS0wMDAwIiwiZGV2aWNlX2lkIjoiZGV2YWJjIiwiY2xpZW50X2lkIjoiY2xpZW50LXV1aWQiLCJzeXN0ZW1faWQiOiJzeXMtMTIzIiwiaXAiOiIxMTQuMjMzLjE1My41OCJ9" ++
        ".c2lnbmF0dXJl";
    const claim = (try decodePayload(testing.allocator, token)).?;
    defer {
        if (claim.sub) |v| testing.allocator.free(v);
        if (claim.device_id) |v| testing.allocator.free(v);
        if (claim.client_id) |v| testing.allocator.free(v);
        if (claim.system_id) |v| testing.allocator.free(v);
        if (claim.ip) |v| testing.allocator.free(v);
        if (claim.jti) |v| testing.allocator.free(v);
    }
    try testing.expectEqualStrings("user123", claim.sub.?);
    try testing.expectEqualStrings("devabc", claim.device_id.?);
    try testing.expectEqualStrings("client-uuid", claim.client_id.?);
    try testing.expectEqualStrings("sys-123", claim.system_id.?);
    try testing.expectEqualStrings("114.233.153.58", claim.ip.?);
    try testing.expectEqual(@as(i64, 1784274298), claim.issued_at.?);
}

test "rejects non-JWT text" {
    try testing.expect(try decodePayload(testing.allocator, "") == null);
    try testing.expect(try decodePayload(testing.allocator, "not a token") == null);
    try testing.expect(try decodePayload(testing.allocator, "a.b") == null);
    try testing.expect(try decodePayload(testing.allocator, "!!.!!.!!") == null);
}
