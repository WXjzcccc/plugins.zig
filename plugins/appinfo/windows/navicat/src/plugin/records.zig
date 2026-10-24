//! Record schemas of the Navicat analyzer: one table per connection family
//! (MySQL, MariaDB, MongoDB, Oracle, PostgreSQL, SQL Server, SQLite), so the
//! results group by database type. Where a row came from is the record's
//! system source (`.from(&file)`), not a column (spec: no source columns).

const std = @import("std");
const lc = @import("lovelycarve");

/// Record-type namespace; every type a plugin emits lives in its own.
pub const NS = "navicat";

pub const MYSQL_TYPE = NS ++ ".mysql";
pub const MARIADB_TYPE = NS ++ ".mariadb";
pub const MONGODB_TYPE = NS ++ ".mongodb";
pub const ORACLE_TYPE = NS ++ ".oracle";
pub const POSTGRESQL_TYPE = NS ++ ".postgresql";
pub const MSSQL_TYPE = NS ++ ".mssql";
pub const SQLITE_TYPE = NS ++ ".sqlite";

/// The fields every connection family shares.
const base_fields = [_]lc.Field{
    lc.Field.new("name", "连接名", .text).asKey(),
    lc.Field.new("host", "地址", .text),
    lc.Field.new("port", "端口", .int),
    lc.Field.new("username", "用户名", .text),
    lc.Field.new("password", "密码", .text),
    lc.Field.new("cache_path", "缓存路径", .path),
};

/// One row per connection profile of the family: the shared fields, plus the
/// family's extras on SQL Server (initial database, authentication mode) and
/// SQLite (initial database, encryption flags).
pub const MYSQL = lc.RecordSchema.new(MYSQL_TYPE, "MySQL连接信息", &base_fields).withTitle("{name}");

pub const MARIADB = lc.RecordSchema.new(MARIADB_TYPE, "MariaDB连接信息", &base_fields).withTitle("{name}");

pub const MONGODB = lc.RecordSchema.new(MONGODB_TYPE, "MongoDB连接信息", &base_fields).withTitle("{name}");

pub const ORACLE = lc.RecordSchema.new(ORACLE_TYPE, "Oracle连接信息", &base_fields).withTitle("{name}");

pub const POSTGRESQL = lc.RecordSchema.new(POSTGRESQL_TYPE, "PostgreSQL连接信息", &base_fields).withTitle("{name}");

pub const MSSQL = lc.RecordSchema.new(MSSQL_TYPE, "SQLServer连接信息", &(base_fields ++ [_]lc.Field{
    lc.Field.new("database", "默认数据库", .text),
    lc.Field.new("auth_mode", "认证模式", .text),
})).withTitle("{name}");

pub const SQLITE = lc.RecordSchema.new(SQLITE_TYPE, "SQLite连接信息", &(base_fields ++ [_]lc.Field{
    lc.Field.new("database", "默认数据库", .text),
    lc.Field.new("encrypted", "是否加密", .boolean),
    lc.Field.new("saved_password", "是否保存密码", .boolean),
})).withTitle("{name}");

/// Every record type the analyzers emit, in registration order.
pub const all = [_]lc.RecordSchema{
    MYSQL,
    MARIADB,
    MONGODB,
    ORACLE,
    POSTGRESQL,
    MSSQL,
    SQLITE,
};

const testing = std.testing;

test "every record schema is valid and unique" {
    for (all, 0..) |schema, index| {
        try schema.validate();
        for (all[0..index]) |earlier| {
            try testing.expect(!std.mem.eql(u8, earlier.record_type, schema.record_type));
        }
    }
    // The host keeps 256 record types per plugin; stay far below that.
    try testing.expect(all.len < 256);
}
