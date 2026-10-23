//! Record schemas of the Windows registry analyzer.
//!
//! Four tables, one per analyzer section. The first field of every table is
//! the evidence path of the hive a row came from, so one run over several
//! hives (and several user hives) keeps its rows distinguishable.

const std = @import("std");
const lc = @import("lovelycarve");

/// Record-type namespace; every type a plugin emits lives in its own.
pub const NS = "winsysteminfo";

pub const SYSTEM_TYPE = NS ++ ".system";
pub const NETWORK_TYPE = NS ++ ".network";
pub const USER_TYPE = NS ++ ".user";
pub const BROWSER_TYPE = NS ++ ".browser";

/// One row per system information item (Build, owner, install date, …).
pub const SYSTEM = lc.RecordSchema.new(SYSTEM_TYPE, "系统信息", &.{
    lc.Field.new("source", "来源配置单元", .path).asKey(),
    lc.Field.new("item", "条目", .text).asKey(),
    lc.Field.new("field_value", "值", .text),
}).withTitle("{item}");

/// One row per TCP/IP interface of the current control set.
pub const NETWORK = lc.RecordSchema.new(NETWORK_TYPE, "网卡信息", &.{
    lc.Field.new("source", "来源配置单元", .path).asKey(),
    lc.Field.new("interface", "接口", .text).asKey(),
    lc.Field.new("name", "名称", .text),
    lc.Field.new("ip", "IP地址", .text),
    lc.Field.new("netmask", "子网掩码", .text),
    lc.Field.new("gateway", "网关", .text),
    lc.Field.new("mac_current", "当前MAC地址", .text),
    lc.Field.new("mac_permanent", "物理MAC地址", .text),
    lc.Field.new("dhcp_ip", "DHCP网络地址", .text),
    lc.Field.new("dhcp_gateway", "DHCP网关", .text),
    lc.Field.new("dhcp_server", "DHCP服务地址", .text),
    lc.Field.new("lease_obtained", "租赁时间", .timestamp),
    lc.Field.new("lease_expires", "过期时间", .timestamp),
});

/// One row per SAM user account.
pub const USER = lc.RecordSchema.new(USER_TYPE, "用户信息", &.{
    lc.Field.new("source", "来源配置单元", .path).asKey(),
    lc.Field.new("username", "用户名", .text).asKey(),
    lc.Field.new("sid", "SID", .text),
    lc.Field.new("nt_hash", "密码哈希", .hash),
    lc.Field.new("full_name", "用户全名", .text),
    lc.Field.new("comment", "描述信息", .text),
    lc.Field.new("last_login", "上次登录时间", .timestamp),
    lc.Field.new("last_pwd_change", "上次密码修改时间", .timestamp),
    lc.Field.new("last_failed_login", "上次登录失败时间", .timestamp),
    lc.Field.new("logon_count", "登录次数", .int),
    lc.Field.new("failed_logon_count", "登录失败次数", .int),
    lc.Field.new("user_attribute", "用户属性", .int),
    lc.Field.new("rid", "RID", .text),
});

/// One row per user hive with an HTTP association.
pub const BROWSER = lc.RecordSchema.new(BROWSER_TYPE, "默认浏览器", &.{
    lc.Field.new("source", "来源配置单元", .path).asKey(),
    lc.Field.new("progid", "ProgId", .text),
}).withTitle("{progid}");

/// Every record type the analyzer emits, in registration order.
pub const all = [_]lc.RecordSchema{
    SYSTEM,
    NETWORK,
    USER,
    BROWSER,
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
