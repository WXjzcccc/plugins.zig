//! Record schemas of the MobaXterm analyzer.

const std = @import("std");
const lc = @import("lovelycarve");

/// Record-type namespace; every type a plugin emits lives in its own.
pub const NS = "mobaxterm";

pub const PASSWORD_TYPE = NS ++ ".password";
pub const CREDENTIAL_TYPE = NS ++ ".credential";

/// One saved session password from a `P` value.
pub const PASSWORD = lc.RecordSchema.new(PASSWORD_TYPE, "MobaXterm 密码", &.{
    lc.Field.new("hive", "用户配置单元", .path).asKey(),
    lc.Field.new("account_host", "连接账户与地址", .text).asKey(),
    lc.Field.new("protocol", "协议", .text),
    lc.Field.new("password", "保存的密码", .text),
}).withTitle("{account_host}");

/// One named credential from a `C` value.
pub const CREDENTIAL = lc.RecordSchema.new(CREDENTIAL_TYPE, "MobaXterm 凭据", &.{
    lc.Field.new("hive", "用户配置单元", .path).asKey(),
    lc.Field.new("name", "凭据名", .text).asKey(),
    lc.Field.new("username", "用户名", .text),
    lc.Field.new("password", "保存的密码", .text),
}).withTitle("{name}");

/// Every record type the analyzers emit, in registration order.
pub const all = [_]lc.RecordSchema{
    PASSWORD,
    CREDENTIAL,
};

const testing = std.testing;

test "every record schema is valid and unique" {
    for (all, 0..) |schema, index| {
        try schema.validate();
        for (all[0..index]) |earlier| {
            try testing.expect(!std.mem.eql(u8, earlier.record_type, schema.record_type));
        }
    }
    try testing.expect(all.len < 256);
}
