//! Record schemas of the Android system analyzer.
//!
//! Fourteen tables across the four analyzers. Where a row came from is the
//! record's system source (`.from(&file)`), not a column — no table carries
//! a source column. The two exceptions, both part of the record identity,
//! are `LOG.line` (a line number identifies the row inside one boot log) and
//! `ADBKEY.digest` (the key content is the identity); both are explained in
//! the README.

const std = @import("std");
const lc = @import("lovelycarve");

/// Record-type namespace; every type a plugin emits lives in its own.
pub const NS = "androidsysteminfo";

// baseinfo
pub const DEVICE_TYPE = NS ++ ".device";
pub const BOOT_TYPE = NS ++ ".boot";
pub const USER_TYPE = NS ++ ".user";
// syslog
pub const LOG_TYPE = NS ++ ".log";
pub const ENTRY_TYPE = NS ++ ".entry";
// applist
pub const APP_TYPE = NS ++ ".app";
pub const PERMISSION_TYPE = NS ++ ".permission";
// netrecords
pub const WIFI_TYPE = NS ++ ".wifi";
pub const SOFTAP_TYPE = NS ++ ".softap";
pub const BLUETOOTH_TYPE = NS ++ ".bluetooth";
pub const ADBKEY_TYPE = NS ++ ".adbkey";
pub const BSSID_TYPE = NS ++ ".bssid";
pub const ACCOUNT_TYPE = NS ++ ".account";
pub const GNSS_TYPE = NS ++ ".gnss";

/// One system attribute of the device (Build, Kernel, 基带, SDK 版本, …).
/// Keyed by the attribute name; identical values across boots collapse.
pub const DEVICE = lc.RecordSchema.new(DEVICE_TYPE, "系统属性", &.{
    lc.Field.new("item", "属性", .text).asKey(),
    lc.Field.new("field_value", "值", .text),
}).withTitle("{item}").withProperties(lc.schema.PropertyLayout.new("field_value").withLabel("item"));

/// One recorded boot. Keyed by the dropbox entry's timestamp (boot
/// completion); the last-header fallback has no time and only appears when
/// no SYSTEM_BOOT entry exists.
pub const BOOT = lc.RecordSchema.new(BOOT_TYPE, "开机记录", &.{
    lc.Field.new("boot_time", "开机时间", .timestamp).asKey(),
    lc.Field.new("build", "系统版本", .text),
    lc.Field.new("kernel", "内核版本", .text),
    lc.Field.new("previous", "历史开机", .boolean),
});

/// One Android user of the device (`/data/system/users/*.xml`).
pub const USER = lc.RecordSchema.new(USER_TYPE, "设备用户", &.{
    lc.Field.new("serial_number", "序列号", .int).asKey(),
    lc.Field.new("user_id", "用户 ID", .int),
    lc.Field.new("user_type", "用户类型", .text),
    lc.Field.new("flags", "标志位", .int),
    lc.Field.new("created", "创建时间", .timestamp),
    lc.Field.new("last_logged_in", "最后登录时间", .timestamp),
}).withTitle("用户 {serial_number}");

/// One logcat line of the boot log. Keyed by the line number inside the
/// file: one run covers one file, and the system source points at it. The
/// record's position (`at`) jumps to the exact line.
pub const LOG = lc.RecordSchema.new(LOG_TYPE, "运行日志", &.{
    lc.Field.new("line", "行号", .int).asKey(),
    lc.Field.new("time", "时间", .timestamp),
    lc.Field.new("buffer", "缓冲区", .text),
    lc.Field.new("level", "级别", .enumeration).withChoices(&.{
        .{ .id = "v", .label = "V (Verbose)" },
        .{ .id = "d", .label = "D (Debug)" },
        .{ .id = "i", .label = "I (Info)" },
        .{ .id = "w", .label = "W (Warn)" },
        .{ .id = "e", .label = "E (Error)" },
        .{ .id = "f", .label = "F (Fatal)" },
        .{ .id = "other", .label = "未知" },
    }),
    lc.Field.new("pid", "进程 ID", .int),
    lc.Field.new("tid", "线程 ID", .int),
    lc.Field.new("tag", "标签", .text),
    lc.Field.new("message", "内容", .text),
}).withTitle("{tag}: {message}");

/// One system event file: a DropBox entry (wtf/恢复日志等) or an ANR trace.
/// Keyed by the file path: the file is the event.
pub const ENTRY = lc.RecordSchema.new(ENTRY_TYPE, "系统事件", &.{
    lc.Field.new("file", "文件", .path).asKey(),
    lc.Field.new("kind", "类型", .text),
    lc.Field.new("time", "时间", .timestamp),
    lc.Field.new("process", "进程", .text),
    lc.Field.new("subject", "主题", .text),
    lc.Field.new("abi", "ABI", .text),
}).withTitle("{kind} {process}");

/// One installed package (from packages.xml, enriched by packages.list).
pub const APP = lc.RecordSchema.new(APP_TYPE, "应用列表", &.{
    lc.Field.new("package", "包名", .text).asKey(),
    lc.Field.new("uid", "UID", .int),
    lc.Field.new("version_code", "版本号", .int),
    lc.Field.new("code_path", "安装路径", .path),
    lc.Field.new("data_dir", "数据目录", .path),
    lc.Field.new("seinfo", "seinfo", .text),
    lc.Field.new("installer", "安装来源", .text),
    lc.Field.new("install_initiator", "安装发起者", .text),
    lc.Field.new("primary_abi", "主 ABI", .text),
    lc.Field.new("shared_user", "共享 UID", .text),
    lc.Field.new("system", "系统应用", .boolean),
    lc.Field.new("privileged", "特权应用", .boolean),
    lc.Field.new("debuggable", "可调试", .boolean),
    lc.Field.new("orphaned", "残留记录", .boolean),
    lc.Field.new("first_install", "首次安装时间", .timestamp),
    lc.Field.new("last_update", "最后更新时间", .timestamp),
}).withTitle("{package}");

/// One runtime permission granted to a package (packages.xml `<perms>`).
pub const PERMISSION = lc.RecordSchema.new(PERMISSION_TYPE, "授权权限", &.{
    lc.Field.new("package", "包名", .text).asKey(),
    lc.Field.new("permission", "权限", .text).asKey(),
    lc.Field.new("granted", "已授权", .boolean),
}).withTitle("{package} {permission}");

/// One saved Wi-Fi network. The preshared key is stored in clear text by
/// Android; it lands in this table like every other field.
pub const WIFI = lc.RecordSchema.new(WIFI_TYPE, "Wi-Fi 网络", &.{
    lc.Field.new("config_key", "配置键", .text).asKey(),
    lc.Field.new("ssid", "SSID", .text),
    lc.Field.new("security", "安全类型", .text),
    lc.Field.new("preshared_key", "预共享密钥", .text),
    lc.Field.new("hidden", "隐藏网络", .boolean),
    lc.Field.new("shared", "共享", .boolean),
    lc.Field.new("status", "状态", .text),
    lc.Field.new("last_connected", "最后连接时间", .timestamp),
    lc.Field.new("last_disconnected", "最后断开时间", .timestamp),
    lc.Field.new("creator", "创建者", .text),
    lc.Field.new("gateway_mac", "网关 MAC", .text),
}).withTitle("{ssid}");

/// The hotspot (SoftAp) configuration of the device.
pub const SOFTAP = lc.RecordSchema.new(SOFTAP_TYPE, "热点配置", &.{
    lc.Field.new("ssid", "SSID", .text).asKey(),
    lc.Field.new("security", "安全类型", .text),
    lc.Field.new("passphrase", "热点密码", .text),
    lc.Field.new("hidden", "隐藏网络", .boolean),
    lc.Field.new("auto_shutdown", "空闲自动关闭", .boolean),
}).withTitle("{ssid}");

/// The local Bluetooth adapter or one paired remote device.
pub const BLUETOOTH = lc.RecordSchema.new(BLUETOOTH_TYPE, "蓝牙记录", &.{
    lc.Field.new("address", "MAC 地址", .text).asKey(),
    lc.Field.new("kind", "类别", .text),
    lc.Field.new("name", "名称", .text),
    lc.Field.new("scan_mode", "扫描模式", .int),
    lc.Field.new("discovery_timeout", "可发现超时", .int),
    lc.Field.new("time_created", "记录时间", .text),
    lc.Field.new("irk", "IRK", .hash),
    lc.Field.new("ir", "IR", .hash),
    lc.Field.new("dhk", "DHK", .hash),
    lc.Field.new("er", "ER", .hash),
    lc.Field.new("link_key", "链路密钥", .hash),
}).withTitle("{name} ({address})");

/// One ADB authorization key (permanent or temporary). Keyed by the SHA-256
/// of the key text: the key content is the identity, and the digest is far
/// more readable than 700 base64 characters.
pub const ADBKEY = lc.RecordSchema.new(ADBKEY_TYPE, "ADB 授权密钥", &.{
    lc.Field.new("digest", "SHA-256", .hash).asKey(),
    lc.Field.new("user_host", "授权来源", .text),
    lc.Field.new("kind", "类型", .enumeration).withChoices(&.{
        .{ .id = "permanent", .label = "永久授权" },
        .{ .id = "temporary", .label = "临时授权" },
    }),
    lc.Field.new("last_connection", "最后连接时间", .timestamp),
}).withTitle("{user_host}");

/// One tethered-AP BSSID recorded by the ADB temp key store.
pub const BSSID_RECORD = lc.RecordSchema.new(BSSID_TYPE, "连接热点 MAC", &.{
    lc.Field.new("bssid", "BSSID", .text).asKey(),
    lc.Field.new("source", "来源", .text),
}).withTitle("{bssid}");

/// One system account of the AccountManager (accounts_ce.db). The password
/// column is part of the evidence and stored as-is.
pub const ACCOUNT = lc.RecordSchema.new(ACCOUNT_TYPE, "系统账号", &.{
    lc.Field.new("name", "账号", .text).asKey(),
    lc.Field.new("type", "账号类型", .text).asKey(),
    lc.Field.new("password", "口令", .text),
}).withTitle("{name}");

/// One GNSS positioning session (gnssCollectData.db).
pub const GNSS = lc.RecordSchema.new(GNSS_TYPE, "GNSS 记录", &.{
    lc.Field.new("session_id", "会话 ID", .int).asKey(),
    lc.Field.new("start_time", "开始时间", .timestamp),
    lc.Field.new("start_time_raw", "开始时间(原始值)", .int),
    lc.Field.new("ttff", "首次定位耗时(ms)", .int),
    lc.Field.new("run_time", "运行时长", .int),
    lc.Field.new("lose_times", "失锁次数", .int),
    lc.Field.new("sap_number", "SAP 数", .int),
    lc.Field.new("pdr_number", "PDR 数", .int),
    lc.Field.new("total_number", "总数", .int),
    lc.Field.new("l1_cn0", "L1 载噪比", .float),
    lc.Field.new("l5_cn0", "L5 载噪比", .float),
    lc.Field.new("b1_cn0", "B1 载噪比", .float),
}).withTitle("GNSS 会话 {session_id}");

/// Every record type the analyzer emits, in registration order.
pub const all = [_]lc.RecordSchema{
    DEVICE,
    BOOT,
    USER,
    LOG,
    ENTRY,
    APP,
    PERMISSION,
    WIFI,
    SOFTAP,
    BLUETOOTH,
    ADBKEY,
    BSSID_RECORD,
    ACCOUNT,
    GNSS,
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
