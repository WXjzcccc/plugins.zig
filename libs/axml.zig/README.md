# axml.zig — Android binary XML (AXML) reader

从 LovelyCarve 的 APK 分析插件（apkanalyzer）抽取的共享解析库：APK 内资源编译的
二进制 XML（manifest、布局等）。只做解析、不解释语义。

## 模块

| 模块 | 内容 |
| --- | --- |
| `document` | 文档：字符串池、资源映射、解析事件（`Document`/`StartElement`/`Attribute`/`Event`/`Node` 由根模块再导出） |
| `chunk` | 块头与资源块类型（`ResourceTypes.h`） |
| `string_pool` | UTF-8/UTF-16 字符串池 |
| `typed_value` | 属性值（int/float/string/引用等） |
| `cursor` | 越界检查的大端读取器（apkanalyzer 的 zip 读取器也复用它） |
| `logging` | 可插拔解析日志：宿主用 `logging.bind(handler)` 绑定接收器，未绑定时丢弃 |

## 使用

```zig
const axml = @import("axml_zig");

// 插件侧：把共享库日志转发进 SDK 日志
const axml_logging = axml.logging;
fn forward(level: axml_logging.Level, message: []const u8) void { /* … */ }
axml_logging.bind(forward);

var document = try axml.Document.parse(arena, manifest_bytes);
for (document.events) |event| { /* … */ }
```

## 变更说明

- 代码自 apkanalyzer `src/core/android/{chunk,string_pool,typed_value}.zig`、
  `src/core/android/axml/document.zig` 与 `src/utils/io/cursor.zig` 原样迁移；
  仅改动：相对导入路径、日志 scope 更名（`apk_android_*` → `axml_*`）、
  日志后端由 SDK 直连改为可插拔 handler（本库不依赖 SDK）。
- apkanalyzer 现以 `@import("axml_zig")` 使用本库；其 `utils/io/cursor.zig`
  保留为转发层（zip 读取器共用同一 Cursor 类型）。
- 注意：Android 12+ `/data/system` 的 **ABX**（`BinaryXmlSerializer`，`ABX\0` 魔数）
  是另一种格式，不在本库范围（见 androidsysteminfo 插件 `core/abx.zig`）。

## 构建与测试

```sh
zig build test
```
