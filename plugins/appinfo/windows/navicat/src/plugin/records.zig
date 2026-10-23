//! Record schema of the Navicat analyzer: one row per connection profile.

const std = @import("std");
const lc = @import("lovelycarve");

/// Record-type namespace; every type a plugin emits lives in its own.
pub const NS = "navicat";

pub const CONNECTION_TYPE = NS ++ ".connection";

/// One Navicat connection profile from an NTUSER hive.
pub const CONNECTION = lc.RecordSchema.new(CONNECTION_TYPE, "Navicat 连接", &.{
    lc.Field.new("source", "来源配置单元", .path).asKey(),
    lc.Field.new("name", "连接名", .text).asKey(),
    lc.Field.new("conn_type", "连接类型", .enumeration).withChoices(&.{
        .{ .id = "mysql", .label = "MySQL" },
        .{ .id = "mariadb", .label = "MariaDB" },
        .{ .id = "mongodb", .label = "MongoDB" },
        .{ .id = "oracle", .label = "Oracle" },
        .{ .id = "postgresql", .label = "PostgreSQL" },
        .{ .id = "mssql", .label = "SQL Server" },
        .{ .id = "sqlite", .label = "SQLite" },
    }),
    lc.Field.new("host", "地址", .text),
    lc.Field.new("port", "端口", .int),
    lc.Field.new("username", "用户名", .text),
    lc.Field.new("password", "密码", .text),
    lc.Field.new("cache_path", "缓存路径", .path),
    lc.Field.new("database", "默认数据库", .text),
    lc.Field.new("auth_mode", "认证模式", .text),
    lc.Field.new("encrypted", "是否加密", .boolean),
    lc.Field.new("saved_password", "是否保存密码", .boolean),
}).withTitle("{name}");

/// Every record type the analyzers emit, in registration order.
pub const all = [_]lc.RecordSchema{
    CONNECTION,
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
