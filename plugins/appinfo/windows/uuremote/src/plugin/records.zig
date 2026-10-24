//! Record schemas of the UU远程 analyzer. One table per evidence family:
//! account identity, devices, remote sessions, component run logs,
//! telemetry sessions, remote file traces, upgrades and registry logins.
//! Where a row came from is the record's system source (`.from(&file)`),
//! not a column (spec: no source columns).

const std = @import("std");
const lc = @import("lovelycarve");

/// Record-type namespace; every type a plugin emits lives in its own.
pub const NS = "uuremote";

pub const ACCOUNT_TYPE = NS ++ ".account";
pub const DEVICE_TYPE = NS ++ ".device";
pub const SESSION_TYPE = NS ++ ".session";
pub const RUN_LOG_TYPE = NS ++ ".run_log";
pub const TELEMETRY_TYPE = NS ++ ".telemetry";
pub const FILE_TRACE_TYPE = NS ++ ".file_trace";
pub const UPGRADE_TYPE = NS ++ ".upgrade";
pub const LOGIN_TYPE = NS ++ ".login";

const device_role_choices = [_]lc.schema.Choice{
    .{ .id = "local", .label = "本机" },
    .{ .id = "remote", .label = "远端" },
};

const session_role_choices = [_]lc.schema.Choice{
    .{ .id = "controller", .label = "主控" },
    .{ .id = "controlled", .label = "被控" },
};

const component_choices = [_]lc.schema.Choice{
    .{ .id = "client", .label = "客户端" },
    .{ .id = "server", .label = "服务端" },
    .{ .id = "service", .label = "服务" },
    .{ .id = "launcher", .label = "启动器" },
    .{ .id = "healthd", .label = "健康监测" },
    .{ .id = "upgrade", .label = "升级" },
    .{ .id = "mumu", .label = "MuMu模拟器" },
    .{ .id = "other", .label = "其他" },
};

/// 账号身份：user_info.ini 及其 JWT 凭据载荷。
pub const ACCOUNT = lc.RecordSchema.new(ACCOUNT_TYPE, "账号身份", &.{
    lc.Field.new("user_id", "用户ID", .text).asKey(),
    lc.Field.new("device_id", "本机设备标识", .text),
    lc.Field.new("client_id", "客户端UUID", .text),
    lc.Field.new("system_id", "系统标识", .text),
    lc.Field.new("login_ip", "登录IP", .ip),
    lc.Field.new("issued_at", "凭据签发时间", .timestamp).withTimeline("login"),
    lc.Field.new("credential_id", "凭据ID", .text),
}).withTitle("{user_id}");

/// 关联设备：从最近连接、隐私屏提醒、协助验证码与文件传输缓存等来源合并。
pub const DEVICE = lc.RecordSchema.new(DEVICE_TYPE, "关联设备", &.{
    lc.Field.new("device_id", "设备标识", .text).asKey(),
    lc.Field.new("role", "角色", .enumeration).withChoices(&device_role_choices),
    lc.Field.new("last_connect", "最近连接时间", .timestamp).withTimeline("access"),
    lc.Field.new("assist_configured", "已配置协助验证", .boolean),
    lc.Field.new("assist_refreshed_at", "验证码最近刷新", .timestamp).withTimeline("modified"),
    lc.Field.new("privacy_seen", "有过受控连接提示", .boolean),
    lc.Field.new("server_config", "存在远端显示配置", .boolean),
    lc.Field.new("transfer_cached", "缓存过远端文件列表", .boolean),
}).withTitle("{device_id}");

/// 远程会话：一条主控/被控连接。内容日志是 SLOG 加密格式，记录只含
/// 文件名与文件系统可证明的事实（开始时间、进程、大小、分段）。
pub const SESSION = lc.RecordSchema.new(SESSION_TYPE, "远程会话", &.{
    lc.Field.new("role", "会话角色", .enumeration).withChoices(&session_role_choices).asKey(),
    lc.Field.new("start", "开始时间", .timestamp).withTimeline("session").asKey(),
    lc.Field.new("last_activity", "最后活动时间", .timestamp).withTimeline("session"),
    lc.Field.new("pid", "进程ID", .int),
    lc.Field.new("size", "日志大小", .size),
    lc.Field.new("segments", "日志分段数", .int),
    lc.Field.new("encrypted", "日志已加密", .boolean),
}).withTitle("{role}会话 {start}");

/// 运行日志：一个组件进程的一次运行（同样只有文件名级事实）。
pub const RUN_LOG = lc.RecordSchema.new(RUN_LOG_TYPE, "运行日志", &.{
    lc.Field.new("component", "组件", .enumeration).withChoices(&component_choices).asKey(),
    lc.Field.new("start", "启动时间", .timestamp).withTimeline("session").asKey(),
    lc.Field.new("pid", "进程ID", .int).asKey(),
    lc.Field.new("size", "文件大小", .size),
    lc.Field.new("segments", "文件分段数", .int),
    lc.Field.new("encrypted", "已加密", .boolean),
}).withTitle("{component} {start}");

/// 遥测会话：Sentry session.json，证明应用版本与运行时间。
pub const TELEMETRY = lc.RecordSchema.new(TELEMETRY_TYPE, "遥测会话", &.{
    lc.Field.new("component", "组件", .text),
    lc.Field.new("release", "应用版本", .text),
    lc.Field.new("user_id", "遥测用户标识", .text),
    lc.Field.new("session_id", "会话ID", .text),
    lc.Field.new("started", "开始时间", .timestamp).withTimeline("session"),
    lc.Field.new("status", "状态", .text),
    lc.Field.new("errors", "错误数", .int),
}).withTitle("{component} {release}");

/// 远程文件浏览痕迹：file_transfer/<device>.json 缓存的远端文件列表。
pub const FILE_TRACE = lc.RecordSchema.new(FILE_TRACE_TYPE, "远程文件浏览痕迹", &.{
    lc.Field.new("device_id", "远端设备标识", .text).asKey(),
    lc.Field.new("path", "远端路径", .path).asKey(),
    lc.Field.new("name", "名称", .text),
    lc.Field.new("kind", "类型", .text),
    lc.Field.new("modified", "远端修改时间", .timestamp).withTimeline("modified"),
}).withTitle("{path}");

/// 升级记录：upgrade.ini 里每个被发现的版本及其安装结果。
pub const UPGRADE = lc.RecordSchema.new(UPGRADE_TYPE, "升级记录", &.{
    lc.Field.new("version", "目标版本", .text).asKey(),
    lc.Field.new("discovered_at", "发现时间", .timestamp).withTimeline("modified"),
    lc.Field.new("status", "状态码", .int),
    lc.Field.new("previous_version", "先前版本", .text),
    lc.Field.new("update_type", "更新方式", .text),
    lc.Field.new("subtitle", "更新说明", .text),
    lc.Field.new("install_path", "安装包路径", .path),
    lc.Field.new("download_url", "下载地址", .text),
    lc.Field.new("md5", "安装包MD5", .hash),
    lc.Field.new("error", "错误信息", .text),
}).withTitle("{version}");

/// 登录与安装信息：NTUSER.DAT 注册表键（版本、目录、手机号登录时间）。
pub const LOGIN = lc.RecordSchema.new(LOGIN_TYPE, "登录与安装信息", &.{
    lc.Field.new("phone", "登录手机号", .text).asKey(),
    lc.Field.new("login_time", "登录时间", .timestamp).withTimeline("login"),
    lc.Field.new("app_version", "应用版本", .text),
    lc.Field.new("install_dir", "安装目录", .path),
    lc.Field.new("cache_path", "缓存目录", .path),
    lc.Field.new("installed", "已安装", .boolean),
    lc.Field.new("ever_run", "曾运行", .boolean),
}).withTitle("{phone}");

/// Every record type the analyzers emit, in registration order.
pub const all = [_]lc.RecordSchema{
    ACCOUNT,
    DEVICE,
    SESSION,
    RUN_LOG,
    TELEMETRY,
    FILE_TRACE,
    UPGRADE,
    LOGIN,
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
