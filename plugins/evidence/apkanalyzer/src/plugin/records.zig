//! Record schemas of the APK analyzers.
//!
//! Every table answers one question an examiner asks about a package: what the
//! application is, what it declares (components, permissions, features,
//! metadata), how it is signed, what it protects itself with, and what the
//! parser had to report. Every table's first field is the package name — the
//! record identity across a run over many APKs, together with each table's
//! row name (component/permission/scheme/...). There is no file column: the
//! record's system source (`.from`) already locates the APK it came from.

const std = @import("std");
const lc = @import("lovelycarve");

/// Record-type namespace; every type a plugin emits lives in its own.
pub const NS = "apk";

pub const INFO_TYPE = NS ++ ".info";
pub const COMPONENT_TYPE = NS ++ ".component";
pub const PERMISSION_TYPE = NS ++ ".permission";
pub const FEATURE_TYPE = NS ++ ".feature";
pub const METADATA_TYPE = NS ++ ".metadata";
pub const SIGNER_TYPE = NS ++ ".signer";
pub const CERTIFICATE_TYPE = NS ++ ".certificate";
pub const DETECTION_TYPE = NS ++ ".detection";
pub const ENTRY_TYPE = NS ++ ".entry";
pub const DIAGNOSTIC_TYPE = NS ++ ".diagnostic";
pub const ICON_TYPE = NS ++ ".icon";

/// The signature-scheme choices shared by the signer and certificate tables.
const SCHEME_CHOICES = [_]lc.schema.Choice{
    .{ .id = "jar_v1", .label = "JAR v1" },
    .{ .id = "apk_v2", .label = "APK v2" },
    .{ .id = "apk_v3", .label = "APK v3" },
    .{ .id = "apk_v31", .label = "APK v3.1" },
    .{ .id = "source_stamp", .label = "来源戳" },
};

/// One row per analyzed package: identity, versions, SDK levels, sizes and the
/// aggregate results of the other tables. The package name is the row's
/// identity; the file it came from stays reachable through the record's
/// system source.
pub const INFO = lc.RecordSchema.new(INFO_TYPE, "APK 信息", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("application_label", "应用名称", .text),
    lc.Field.new("version_name", "版本名", .text),
    lc.Field.new("version_code", "版本号", .int),
    lc.Field.new("min_sdk", "最低 SDK", .int),
    lc.Field.new("target_sdk", "目标 SDK", .int),
    lc.Field.new("compile_sdk", "编译 SDK", .int),
    lc.Field.new("launcher_activity", "启动 Activity", .text),
    lc.Field.new("debuggable", "可调试", .boolean),
    lc.Field.new("allow_backup", "允许备份", .boolean),
    lc.Field.new("size", "文件大小", .size),
    lc.Field.new("sha256", "SHA-256", .hash),
    lc.Field.new("file_count", "条目数", .int),
    lc.Field.new("compressed_size", "压缩大小", .size),
    lc.Field.new("uncompressed_size", "解压大小", .size),
    lc.Field.new("resource_packages", "资源包", .list),
    lc.Field.new("resource_values", "资源值数", .int),
    lc.Field.new("references_resolved", "已解析引用", .int),
    lc.Field.new("references_unresolved", "未解析引用", .int),
    lc.Field.new("signature_schemes", "签名方案", .list),
    lc.Field.new("protections", "加固", .list),
    lc.Field.new("frameworks", "框架", .list),
    lc.Field.new("cryptographic_verification", "签名已验签", .boolean),
});

/// One row per manifest component.
pub const COMPONENT = lc.RecordSchema.new(COMPONENT_TYPE, "组件", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("kind", "类型", .enumeration).withChoices(&.{
        .{ .id = "activity", .label = "Activity" },
        .{ .id = "activity_alias", .label = "Activity 别名" },
        .{ .id = "service", .label = "Service" },
        .{ .id = "receiver", .label = "Receiver" },
        .{ .id = "provider", .label = "Provider" },
    }),
    lc.Field.new("name", "名称", .text).asKey(),
    lc.Field.new("target_activity", "目标 Activity", .text),
    lc.Field.new("exported", "导出", .boolean),
    lc.Field.new("enabled", "启用", .boolean),
    lc.Field.new("permission", "权限", .text),
    lc.Field.new("process", "进程", .text),
    lc.Field.new("authorities", "授权", .text),
    lc.Field.new("label", "标签", .text),
    lc.Field.new("intent_filters", "Intent 过滤器", .json).asHidden(),
    lc.Field.new("metadata", "元数据", .json).asHidden(),
});

/// One row per declared permission, with the catalog's risk classification.
pub const PERMISSION = lc.RecordSchema.new(PERMISSION_TYPE, "权限", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("name", "权限", .text).asKey(),
    lc.Field.new("risk", "风险", .enumeration).withChoices(&.{
        .{ .id = "normal", .label = "普通" },
        .{ .id = "sensitive", .label = "敏感" },
        .{ .id = "dangerous", .label = "危险" },
        .{ .id = "unknown", .label = "未知" },
    }),
    lc.Field.new("max_sdk_version", "最高 SDK", .int),
    lc.Field.new("uses_permission_flags", "权限标志", .int),
    lc.Field.new("display_name", "显示名称", .text),
    lc.Field.new("description", "说明", .text),
});

/// One row per uses-feature element.
pub const FEATURE = lc.RecordSchema.new(FEATURE_TYPE, "特性", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("name", "名称", .text).asKey(),
    lc.Field.new("gl_es_version", "OpenGL ES 版本", .int),
    lc.Field.new("required", "必需", .boolean),
});

/// One row per meta-data element of the application element.
pub const METADATA = lc.RecordSchema.new(METADATA_TYPE, "元数据", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("name", "名称", .text).asKey(),
    lc.Field.new("value", "值", .text),
    lc.Field.new("kind", "值类型", .text),
});

/// One row per signature scheme signer.
pub const SIGNER = lc.RecordSchema.new(SIGNER_TYPE, "签名方案", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("scheme", "方案", .enumeration).withChoices(&SCHEME_CHOICES),
    lc.Field.new("min_sdk", "最低 SDK", .int),
    lc.Field.new("max_sdk", "最高 SDK", .int),
    lc.Field.new("signature_algorithms", "签名算法", .list),
    lc.Field.new("digest_algorithms", "摘要算法", .list),
    lc.Field.new("certificates", "证书数", .int),
});

/// One row per signing certificate.
pub const CERTIFICATE = lc.RecordSchema.new(CERTIFICATE_TYPE, "签名证书", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("scheme", "方案", .enumeration).withChoices(&SCHEME_CHOICES),
    lc.Field.new("serial_number", "序列号", .text).asKey(),
    lc.Field.new("sha256", "SHA-256", .hash),
    lc.Field.new("sha1", "SHA-1", .hash),
    lc.Field.new("md5", "MD5", .hash),
    lc.Field.new("subject", "主题", .text),
    lc.Field.new("issuer", "颁发者", .text),
    lc.Field.new("not_before", "生效时间", .timestamp),
    lc.Field.new("not_after", "失效时间", .timestamp),
    lc.Field.new("signature_algorithm", "签名算法", .text),
    lc.Field.new("public_key_algorithm", "公钥算法", .text),
    lc.Field.new("public_key_bits", "公钥位数", .int),
});

/// One row per packer / framework detection.
pub const DETECTION = lc.RecordSchema.new(DETECTION_TYPE, "加固与框架", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("category", "类别", .enumeration).withChoices(&.{
        .{ .id = "protection", .label = "加固" },
        .{ .id = "framework", .label = "框架" },
    }),
    lc.Field.new("name", "名称", .text).asKey(),
    lc.Field.new("evidence", "证据", .list),
});

/// One row per ZIP entry; emitted only when the run asks for them.
pub const ENTRY = lc.RecordSchema.new(ENTRY_TYPE, "归档条目", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("name", "条目", .path).asKey(),
    lc.Field.new("method", "压缩方式", .enumeration).withChoices(&.{
        .{ .id = "store", .label = "存储" },
        .{ .id = "deflate", .label = "Deflate" },
        .{ .id = "other", .label = "其他" },
    }),
    lc.Field.new("compressed_size", "压缩大小", .size),
    lc.Field.new("uncompressed_size", "原始大小", .size),
    lc.Field.new("crc32", "CRC32", .text),
    lc.Field.new("local_offset", "本地头偏移", .int),
});

/// One row per recoverable parser diagnostic.
pub const DIAGNOSTIC = lc.RecordSchema.new(DIAGNOSTIC_TYPE, "诊断", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("stage", "阶段", .enumeration).withChoices(&.{
        .{ .id = "input", .label = "输入" },
        .{ .id = "archive", .label = "归档" },
        .{ .id = "manifest", .label = "清单" },
        .{ .id = "resources", .label = "资源" },
        .{ .id = "signing", .label = "签名" },
    }),
    lc.Field.new("severity", "级别", .enumeration).withChoices(&.{
        .{ .id = "info", .label = "信息" },
        .{ .id = "warning", .label = "警告" },
        .{ .id = "error", .label = "错误" },
    }),
    lc.Field.new("code", "代码", .text).asKey(),
    lc.Field.new("message", "消息", .text),
    lc.Field.new("entry", "条目", .text),
    lc.Field.new("offset", "偏移", .int),
});

/// One row per extracted application icon.
pub const ICON = lc.RecordSchema.new(ICON_TYPE, "应用图标", &.{
    lc.Field.new("package_name", "包名", .text).asKey(),
    lc.Field.new("entry", "图标条目", .path),
    lc.Field.new("kind", "类型", .enumeration).withChoices(&.{
        .{ .id = "bitmap", .label = "位图" },
        .{ .id = "adaptive", .label = "自适应" },
        .{ .id = "svg", .label = "SVG" },
    }),
    lc.Field.new("size", "大小", .size),
    lc.Field.new("sha256", "SHA-256", .hash),
    lc.Field.new("background_size", "背景层大小", .size),
});

/// Every record type the analyzers emit, in registration order.
pub const all = [_]lc.RecordSchema{
    INFO,
    COMPONENT,
    PERMISSION,
    FEATURE,
    METADATA,
    SIGNER,
    CERTIFICATE,
    DETECTION,
    ENTRY,
    DIAGNOSTIC,
    ICON,
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
