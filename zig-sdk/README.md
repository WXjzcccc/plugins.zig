# LovelyCarve Zig 插件 SDK

`plugins/zig-sdk/` 是 LovelyCarve 插件的 **Zig 版 SDK**，对应 Rust 版的 `plugins/sdk/`（crate `lovelycarve-plugin`）。
写一个 Zig 插件只要 `@import("lovelycarve")` 一个模块，不必再复制 ABI、wire 编解码和入口胶水代码。

- 目标 Zig 版本：**0.17.0**（见 `build.zig.zon` 的 `minimum_zig_version`）
- 协议：**LPP v2**（`PROTOCOL_VERSION = 2`），C ABI v1（导出符号 `lovelycarve_plugin_v1`）
- 对外只暴露一个模块：`lovelycarve`

0.2.0 是不兼容升级：0.1.0 的 `Evidence` / `AnalysisResult` 接口已删除，分析器改为在
`run.start` 里通过 `Run` 输出**带记录结构校验的类型化记录**，并可用 `View` / `FileRef`
按运行的只读视图读取检材。宿主只加载 LPP v2 插件包。

---

## 一、最小插件

### 1.1 声明依赖

`build.zig.zon`：

```zig
.{
    .name = .my_plugin,
    .version = "0.1.0",
    // Zig 0.17 起必填，而且不能随便编：它是包名加依赖路径的哈希。第一次
    // `zig build` 会报 `invalid fingerprint: ...; use this value: 0x...`，
    // 把提示的值填进来即可。之后改包名或改依赖，要重新取一次。
    .fingerprint = 0x750be78f69e48fb3,
    .minimum_zig_version = "0.17.0",
    .dependencies = .{
        // 指向 plugins/zig-sdk
        .lovelycarve = .{ .path = "../../zig-sdk" },
    },
    .paths = .{ "build.zig", "build.zig.zon", "src", "plugin.toml", "README.md" },
}
```

### 1.2 build.zig

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sdk = b.dependency("lovelycarve", .{ .target = target, .optimize = optimize });

    const module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        // ABI 两侧互传缓冲区，必须链 libc（SDK 用 std.heap.c_allocator）。
        .link_libc = true,
    });
    module.addImport("lovelycarve", sdk.module("lovelycarve"));

    const library = b.addLibrary(.{
        .name = "myplugin",
        .root_module = module,
        .linkage = .dynamic,
    });

    // Windows 上 Zig 默认把 DLL 放进 zig-out/bin，而宿主要的是 lib/。
    b.getInstallStep().dependOn(&b.addInstallArtifact(library, .{
        .dest_dir = .{ .override = .lib },
    }).step);

    // 测试模块也要 import SDK，别忘了这一行。
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .link_libc = true,
    });
    test_module.addImport("lovelycarve", sdk.module("lovelycarve"));

    const tests = b.addTest(.{
        .name = "myplugin-test",
        .root_module = test_module,
    });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
```

### 1.3 src/root.zig

```zig
const std = @import("std");
const lc = @import("lovelycarve");

/// 记录类型：分析结果里每一行都按这份结构校验、存储与显示。
pub const RELEASE_SCHEMA = lc.RecordSchema.new("myplugin.release", "系统信息", &.{
    lc.Field.new("key", "英文名称", .text).asKey(),
    lc.Field.new("field_value", "值", .text),
    lc.Field.new("source", "源文件", .path),
});

fn analyze(run: *const lc.Run) lc.Error!void {
    const view = try run.requireView();
    const file = (try view.open("etc/os-release")) orelse return;
    const text = try file.readText(1 << 20);
    try run.record("myplugin.release", &.{
        lc.wire.str("PRETTY_NAME"),
        lc.wire.str(text),
        lc.wire.str("etc/os-release"),
    }).from(&file).emit();
    run.setSummary("扫描完成");
}

pub const plugin = lc.Plugin{
    .id = "com.example.myplugin",            // 必须与 plugin.toml 的 id 一致
    .records = &.{RELEASE_SCHEMA},           // 会发出的每一种记录类型
    .analyzers = &.{lc.analyzer("osrelease", analyze)},
};

// 导出 C ABI 入口符号，一个插件库写一次。
comptime {
    lc.exportPlugin(@This());
}
```

`lc.Plugin` 的硬约束（宿主会因此拒绝加载）：`id` 必须与 `plugin.toml` 一致；
`plugin.toml` 里声明的每个 `[[analyzer]]` 必须在这里注册；发出的每种记录类型必须在
`records` 里声明，且编码结果要与包内的 `schema.json` 一致（按 `schema_hash` 比对）。

---

## 二、模块地图

| 模块 | 内容 |
| --- | --- |
| `lc.abi` | C ABI v1 结构体与回调类型，对应 `plugins/sdk/include/lovelycarve_plugin.h` |
| `lc.wire` | LPP 用的 MessagePack 子集（`Value` / `Entry`、`encode` / `decode`、`mapOf` / `arrayOf`） |
| `lc.json` | `schema.json` 用的 JSON 输出（`write` / `writePretty`） |
| `lc.value` | 载荷辅助：取字段、可选值、`Range`、字节回复校验 |
| `lc.errorcodes` | LPP 错误码与承载错误消息的 fault 槽（`Error` / `Fault`） |
| `lc.text` | `splitLines` / `decodeLossy`（与 Rust 的 `str::splitlines`、`String::from_utf8_lossy` 对齐） |
| `lc.protocol` | LPP v2 方法名、上限与载荷类型（`RunStart` / `FileInfo` / `ViewInfo` / `NodeInfo` …） |
| `lc.schema` | 记录结构：`RecordSchema` / `Field` / `FieldKind` / `PropertyLayout` / `schemaHash` |
| `lc.record` | 记录值：`Timestamp`、`Severity`、`SourceRef`、`DynamicRecord`、`profile.fact` |
| `lc.glob` | 输入路径模式与 `view.find` 的 glob 校验 |
| `lc.host` | `Context`（取消、日志、`callHost`）、`HostConnection`、`LogLevel` |
| `lc.source` | 只读镜像源 `Source`（`source.info` / `read` / `readv`，含 64 KiB 块缓存） |
| `lc.filesystem` | `FileSystemParser` / `Volume` 及 `fs.*` 的 `FsNode` / `FsStat` / `NodePage` / `Probe` |
| `lc.file` | 单个逻辑文件 `FileRef`（`readAt` / `readAll` / `readText` / `readLines` / `readv` / `materialize`） |
| `lc.view` | 按运行的只读视图 `View`（`stat` / `list` / `open` / `find` / `readText`） |
| `lc.run` | `Run`（记录流、进度、告警、画像事实）、`Emit`、`Options`、`Profile` |
| `lc.plugin_mod` | `Plugin`（身份 + 记录结构 + 分析器注册 + `plugin.hello`） |
| `lc.runtime` | C ABI 入口、方法分发、取消（`entry` / `exportPlugin`） |
| `lc.testing` | 测试替身：假宿主 `Stub` 与驱动 `call` / `callOk` / `describe` / `entry` |

`lc.Plugin` 通过三个字段注册能力，写几个都行：

```zig
pub const plugin = lc.Plugin{
    .id = "...",
    .records = &.{A, B},                                    // 记录结构
    .analyzers = &.{lc.analyzer("base", analyze)},          // 分析器
    .parsers = &.{lc.parserOf(MyFs, &my_fs)},               // 文件系统（可选）
};
```

宿主会分发这些方法（`runtime.zig` 里 `Method.parse` 的表，其余一律 `METHOD_NOT_FOUND`）：

| 方法 | 触发者 |
| --- | --- |
| `plugin.shutdown` | 宿主关闭实例 |
| `run.start` | 调度器开始一次分析 |
| `fs.probe` / `fs.open` / `fs.close` / `fs.children` / `fs.children_page` / `fs.stat` / `fs.read_range` | 注册了文件系统能力 |

---

## 三、记录结构

分析结果是带类型的记录：每种记录类型一份 `RecordSchema`，宿主按字段类型建表、排序、检索，
并把结构随结果一起保存。字段类型（`FieldKind`）有 `text`、`int`、`float`、`bool`、
`timestamp`、`size`、`duration`、`path`、`hash`、`ip`、`enum`（Zig 里叫 `.enumeration`）、
`list`、`json`。

```zig
pub const LOGIN_SCHEMA = lc.RecordSchema.new("linux.login", "登录记录", &.{
    lc.Field.new("user", "用户", .text).asKey(),
    lc.Field.new("terminal", "终端", .text),
    lc.Field.new("time", "登录时间", .timestamp).withTimeline("login"),
    lc.Field.new("outcome", "结果", .enumeration).withChoices(&.{
        .{ .id = "success", .label = "成功" },
        .{ .id = "failure", .label = "失败" },
    }),
    lc.Field.new("raw", "原始记录", .json).asHidden(),
}).withTitle("{user} @ {terminal}");
```

- `asKey()` 的字段组成记录身份与缺省标题；`withTitle()` 用字段 id 写标题模板。
- `asHidden()` 的字段只在详情里显示，不占表格列。
- `withTimeline(role)` 只对 `.timestamp` 有效：带时区偏移的时间按角色投影到案件时间线；
  时区未知的本地时间照常存储与排序，但不进全局时间线。
- 纵向属性视图用 `withProperties(PropertyLayout.new("value").withLabel("name"))`，
  每个可见字段必须且只能分配一个角色。
- 上限：一个插件最多 256 种记录类型，每种最多 128 个字段；文本 256 KiB，`list` 4096 项。

记录值按字段顺序**位置传参**：

```zig
try run.record("linux.login", &.{
    lc.wire.str("root"),
    lc.wire.str("pts/0"),
    lc.wire.str(login_time.asStr()),
    lc.wire.str("success"),
    .nil,                       // hidden 字段可以不填
}).emit();
```

`Timestamp` 用固定缓冲区，不占分配器：`Timestamp.fromUnix(sec)`、`fromUnixMillis`、
`fromUnixNanos`、`withOffset(y, m, d, h, min, s, offset_minutes)`、`local(...)`（时区未知）、
`parse(text)`。写进记录时用 `wire.str(ts.asStr())`。

---

## 四、写一个分析器

分析器就是一个函数 `fn (run: *const lc.Run) lc.Error!void`，在宿主工作线程上运行、可以阻塞。

```zig
fn analyze(run: *const lc.Run) lc.Error!void {
    const view = try run.requireView();
    ctx_log(run, "scanning");
    try run.progress(0, 2, "reading os-release");
    const file = (try view.open("etc/os-release")) orelse {
        run.setSummary("没有找到 os-release");
        return;
    };
    const text = try file.readText(1 << 20);
    try run.progress(1, 2, "parsing");
    try run.record("myplugin.release", &.{
        lc.wire.str("PRETTY_NAME"),
        lc.wire.str(text),
        lc.wire.str("etc/os-release"),
    }).from(&file).note("第 1 行").emit();
    run.setSummary("完成");
}
```

`Run` 上可用的东西：

| 成员 | 说明 |
| --- | --- |
| `requireView()` / `viewOrNull()` | 系统视图或检材视图；文件作用域的分析器没有视图 |
| `system()` | 系统作用域时的 `SystemInfo`（id / family / product / version / root） |
| `inputsOf()` | 宿主按清单 `inputs` 解析出的输入文件（`[]const FileRef`） |
| `optionValues()` / `profileFacts()` | 运行选项与画像事实（`Options` / `Profile`） |
| `uiLocale()` | 界面语言（`zh-CN` / `en`） |
| `record()` / `emit()` / `dynamic()` / `recordValues()` | 输出记录 |
| `provide(key, value)` | 发布画像事实（时区、主机名、用户等） |
| `warn(code, message)` / `warnFile(file, code, message)` | 记一条运行告警，不使运行失败 |
| `progress(current, total, message)` | 任务进度 |
| `setSummary(text)` | 运行摘要（记录数与告警数由宿主统计） |
| `checkCancelled()` / `isCancelled()` | 协作取消 |
| `log(level, message)` | 写一行 LovelyCarve 日志 |

`Emit` 可以链式补充来源与展示信息：`.from(&file)`、`.source(source_ref)`、
`.at(offset, length)`、`.note("第 12 行")`、`.title("...")`、`.severity(.medium)`。

记录按批发送（1000 条或 2 MiB 一批），每条在发出前就按结构校验：类型没注册是
`UNKNOWN_RECORD_TYPE`，值与字段类型不符是 `INVALID_RECORD`。运行失败会丢弃整次运行的结果。

### 4.1 视图

`View` 是一棵只读路径树，路径是 POSIX 风格、相对视图根：`etc/passwd`、`home/kali/.bash_history`。
系统视图把该系统的各个卷按挂载点拼成一棵树；检材视图的每个顶层目录是一个卷键（`part:2/etc/passwd`）。
`stat` / `open` 跟随符号链接，`list` 不跟随；`..` 只在链接目标里生效，不能离开视图。

- `stat(path)` → `?Node`（`name` / `kind` / `size` / `deleted` / `link_target` / `timestamps`）
- `exists` / `isFile` / `isDir`
- `list(path)` / `listOrEmpty(path)` → 目录项（自动翻页）
- `open(path)` → `?FileRef`；`read` / `readText` / `readLines` 是它的便捷写法
- `find(patterns)` → 匹配的路径（`**` 跨目录，`*` / `?` 限于一级名称，ASCII 大小写不敏感）
- `source(path)` → 记录的 `SourceRef`（卷键 + 卷内路径），用于「定位源文件」

### 4.2 文件句柄

`FileRef` 是宿主发给这次运行的不透明只读文件，拿不到检材路径：`readAt(offset, length)`、
`readAll(cap)`（超过 cap 是 `RESOURCE_LIMIT`，短读是 `SHORT_READ`）、`readText(cap)`、
`readLines(cap)`、`readv(ranges)`、`materialize()`（需要 `file_materialize` 权限，
拿到宿主临时目录里的副本，用完 `release()`）。

---

## 五、写一个文件系统解析器

`lc.filesystem.FileSystemParser` 要三个方法，`lc.filesystem.Volume` 要六个。**方法必须是 `pub`**，
名字和参数由 vtable 生成器按名匹配，写错在编译期就会报错。

```zig
const MyFs = struct {
    pub fn filesystem(_: *MyFs) []const u8 {
        return "myfs";
    }

    /// 只读几个块，返回 0.0–1.0 的置信度。
    pub fn probe(
        _: *MyFs,
        ctx: lc.Context,
        source: *const lc.Source,
    ) lc.Error!lc.Probe {
        const magic = try source.read(ctx.arena, 0, 4);
        if (!std.mem.eql(u8, magic, "MYFS")) return lc.Probe.noMatch();
        return .{ .confidence = 1.0, .label = "MyFS" };
    }

    pub fn open(
        _: *MyFs,
        ctx: lc.Context,
        source: *const lc.Source,
        options: lc.wire.Value,
    ) lc.Error!lc.Volume {
        _ = options;
        const volume = try ctx.alloc.create(MyVolume);   // 生命周期由插件自己管
        volume.* = .{ .source = source.retain() };
        return lc.volumeOf(MyVolume, volume);
    }
};

const MyVolume = struct {
    source: lc.Source,

    pub fn rootNode(self: *MyVolume, alloc: std.mem.Allocator) lc.Error!lc.FsNode {
        _ = self;
        _ = alloc;
        return .{ .id = "/", .name = "/", .kind = .dir };
    }

    pub fn children(
        self: *MyVolume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
    ) lc.Error![]const lc.FsNode {
        _ = .{ self, node_id };
        // 必须用 alloc 复制，不能让栈上的 &.{...} 逃逸出函数。
        return lc.filesystem.slice(lc.FsNode, alloc, &.{
            .{ .id = "/a.txt", .name = "a.txt", .kind = .file, .size = 3 },
        });
    }

    /// 默认实现就是基于 children 的 offset 游标分页，可以直接转发。
    pub fn childrenPage(
        self: *MyVolume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
        limit: usize,
        cursor: ?[]const u8,
    ) lc.Error!lc.NodePage {
        return lc.filesystem.defaultChildrenPage(MyVolume, self, alloc, node_id, limit, cursor);
    }

    pub fn stat(self: *MyVolume, alloc: std.mem.Allocator, node_id: []const u8) lc.Error!lc.FsStat {
        _ = .{ self, alloc };
        return .{ .node_id = node_id, .size = 3, .mime = "text/plain" };
    }

    pub fn read(
        self: *MyVolume,
        alloc: std.mem.Allocator,
        node_id: []const u8,
        offset: u64,
        length: usize,
    ) lc.Error![]u8 {
        _ = node_id;
        return self.source.read(alloc, offset, length);
    }

    /// 宿主结束会话时调用；`alloc` 是 close 这次调用可用的分配器。
    pub fn close(self: *MyVolume, alloc: std.mem.Allocator) void {
        self.source.release();
        alloc.destroy(self);
    }
};
```

要点：

- **时间戳是 RFC 3339 字符串**（`?[]const u8`），不是毫秒整数：宿主用
  `chrono::DateTime::parse_from_rfc3339` 逐个校验，写 `"2023-11-14T22:13:20Z"` 这种格式。
- `FsStat.mime` 是普通字符串（缺省 `lc.filesystem.DEFAULT_MIME`），不能是 `nil`：宿主的
  DTO 是 `String`，空值会反序列化失败。
- `FsStat.mode` 是 `?u16`（宿主 DTO 就是 `Option<u16>`），别塞更宽的值。
- `children_page` 的 `limit` 上限由宿主约束，返回的 `items` 不能多于 `limit`。
- `Source` 是引用计数的：`open` 里 `source.retain()`，`close` 里 `source.release()`。
  `probe` 拿到的 `*const Source` 不需要 retain。
- 同一个实例的调用可能来自多个宿主线程，内部状态要自己加锁（`std.atomic.Mutex`）。

---

## 六、错误、取消与进度

插件返回 `lc.Error!T`。Zig 的 error 不能带载荷，所以**错误码和消息走线程本地的 fault 槽**：

```zig
return lc.errorcodes.fail("RESOURCE_LIMIT", "文件太大");
return lc.errorcodes.failf(ctx.arena, "INVALID_PARAMS", "不支持的编码 {s}", .{name});
return lc.errorcodes.pathNotFound(ctx.arena, "/etc/os-release");  // -> error.PathNotFound
return lc.errorcodes.cancelled();
```

SDK 自带一批具名错误，`runtime.zig` 会把它们翻译成 LPP 错误码：`error.InvalidParams` →
`INVALID_PARAMS`、`error.PathNotFound` → `VIEW_PATH_NOT_FOUND`、`error.ResourceLimit` →
`RESOURCE_LIMIT`、`error.MethodNotFound` → `METHOD_NOT_FOUND`、`error.InvalidSession` →
`INVALID_SESSION`、`error.NoParser` → `NO_PARSER`、`error.InvalidAnalyzer` →
`INVALID_ANALYZER`、`error.Cancelled` → `CANCELLED`、`error.ProtocolError` →
`PROTOCOL_ERROR`、`error.HostError` → `HOST_ERROR`、`error.Panic` → `PLUGIN_PANIC`、
`error.InvalidRecord` → `INVALID_RECORD`、`error.UnknownRecordType` → `UNKNOWN_RECORD_TYPE`。
宿主自己回的错误码会原样透传（`lc.errorcodes.codeOf` 读得到）。

取消是**协作式**的：宿主随时可能调用 `cancel`，长循环要自己查。

```zig
for (items, 0..) |item, index| {
    try run.checkCancelled();                       // 或 if (run.isCancelled()) ...
    try run.progress(index, items.len, "扫描中");
    _ = item;
}
```

`run.log(.info, "开始分析")` 写 LovelyCarve 日志（`LogLevel` 有 `.err` / `.warn` / `.info` / `.debug`）。

内存约定：`ctx.arena` 是**每次调用一个 arena**，回复里所有字符串、数组、map 都从这里分配，
调用返回时统一释放——**不要释放任何交还给宿主的切片**；`ctx.alloc` 活得更久（跨调用状态、
filesystem 会话用它）。

---

## 七、Zig 0.17 的坑（写插件会踩到的）

这些都是 0.17.0（x86_64-windows）上实测过的：

1. **`std.Thread.Mutex` 已被删除**；`std.Io.Mutex` 需要 `Io` 句柄，C ABI 插件拿不到。
   用 **`std.atomic.Mutex`**：`var m: std.atomic.Mutex = .unlocked; while (!m.tryLock()) std.atomic.spinLoopHint(); ... m.unlock();`。
2. **`std.Thread.sleep` 也没了**（睡眠需要 `Io`）。等一小会儿用 `std.Thread.yield() catch {}` 自旋。
3. **`&.{...}` 栈临时值会静默逃逸**。`wire.mapOf` / `wire.arrayOf` / `filesystem.slice` /
   `schema.schemaHash` 都会复制，所以**凡是跨函数返回的 map/数组，一律用这些构造**；
   直接 `return &.{...}` 编译通过但运行时会读到被覆盖的栈。
4. **互相递归的函数必须显式写 error set**，否则 `error: dependency loop with length 2`
   （单个自递归可以推断）。`wire.zig` 的 `read`/`readArray`/`readMap` 就是这个原因。
5. **`@min` 会收窄结果类型**：`@min(data.len, 32)` 的类型是 `u6`，`@min(data.len, 32) * 3` 会溢出。
   写成 `const n: usize = @min(data.len, 32);`。
6. **有语句的块不能以裸表达式收尾**，`catch |err| { ...; null }` 报 `expected ';' after statement`，
   要么加标签 `blk: { ...; break :blk null; }`，要么改成 `if`。
7. **局部名不能与同容器/文件作用域的同名声明重名**：`error: capture shadows declaration of 'entry'`。
   典型是 `|entry|`、`const source`、`const handle`。
8. **`callconv(.c)` 的函数不能返回 error union**，入口必须返回 `i32` 状态码；
   extern struct 里的函数指针字段也必须显式写 `callconv(.c)`。
9. **`build.zig.zon` 必须有 `fingerprint` 字段**（0.17 起必填），而且不能随便编，编错了报
   `invalid fingerprint: 0x...; if this is a new or forked package, use this value: 0x...`。
   它是包名加依赖路径的哈希，**加依赖或改包名之后要重新取一次**。
10. **Windows 上 DLL 默认装到 `zig-out/bin/`**，`addInstallArtifact(..., .{ .dest_dir = .{ .override = .lib } })`
    才能落到 `zig-out/lib/`。
11. **`std.ArrayList` 是无管理的**：`var list: std.ArrayList(u8) = .empty;`，每次 `append` 传分配器。
12. **独立可执行文件（例如打包工具）的文件 IO 要 `Io`**：`pub fn main(init: std.process.Init)`，
    `std.Io.Dir.cwd()` 的每个调用都带 `init.io`。

写 trait 实现时另外两条 Zig 规则：

- **方法必须是 `pub`**：vtable 生成器在另一个文件里调用它们，非 `pub` 会报
  `'analyze' is not marked 'pub'`。
- **`fn filesystem(...)` 会和模块名 `filesystem` 撞名**：在同一个容器里再写
  `filesystem.FsNode` 会报 `error: ambiguous reference`。在容器顶部加个别名即可，
  例如 `const fs = filesystem;`，之后统一用 `fs.`。

---

## 八、构建、测试与打包

```bash
cd plugins/zig-sdk
zig build test                    # SDK 自身的单元测试（含端到端 ABI 测试）
zig build test --summary all      # 看每个用例
zig fmt --check src/
```

插件侧：

```bash
zig build                         # 调试版
zig build -Doptimize=ReleaseSafe  # 发布版
zig build test                    # 插件自己的测试
```

产物在 `zig-out/lib/`：`<name>.dll`（Windows）/ `lib<name>.so`（Linux）。

### 生成 schema.json

宿主在加载前就要知道插件的记录结构与列，所以包内必须带 `schema.json`（库的
`plugin.hello`）。做法是构建一个调用 `Plugin.helloJson` 的小程序（模板里的
`src/describe.zig`），再用宿主加载器核对：

```bash
zig build schema
# 等价于：运行 describe 程序写出 schema.json
plugins/target/debug/lc-plugin-host.exe --describe --library zig-out/lib/myplugin.dll
```

两者应当给出同一份文档（`schema_hash` 相同）。库与 `schema.json` 不一致时宿主会拒绝启动
并提示重新构建插件包。

### 打包成 .lcpkg

`.lcpkg` 是插件包目录的 ZIP：`plugin.toml` 在压缩包根部。模板的 `build.zig` 提供
`package` 步骤，产出 `zig-out/<id>-<version>-<platform>.lcpkg` 与同名暂存目录，内含
`plugin.toml`、动态库、`schema.json`、`README.md`、可选的 `locales/`、`SHA256SUMS.txt`
与 `build.json`：

```bash
zig build package -Doptimize=ReleaseSafe
```

在 LovelyCarve「设置 → 插件」或 CLI `plugins create <包路径>` 安装。

`plugin.toml` 必须与 `lc.Plugin` 对得上（LPP v2 清单）：

```toml
id = "com.example.myplugin"
name = "MyPlugin"
version = "0.2.0"
protocol = 2
library = "myplugin"          # 对应 build.zig 里的 .name
memory = "512MiB"
permissions = []              # 需要 file.materialize 时加 "file_materialize"

[[analyzer]]
id = "osrelease"              # 必须等于 lc.analyzer("osrelease", ...)
name = "我的分析"
scope = "system"              # system / evidence / files
platforms = ["linux"]
trigger = "manual"
category = "baseinfo"
inputs = ["etc/os-release"]
```

### 用测试里的 stub 宿主

不需要真宿主：`lc.testing` 就是一套测试替身，SDK 自己的测试也用它。

```zig
const lc = @import("lovelycarve");

const State = struct {
    /// 宿主方法的应答。run.emit / run.progress / run.warn / file.release 由 Stub 自己接掉。
    fn handle(
        state: ?*anyopaque,
        alloc: std.mem.Allocator,
        method: []const u8,
        params: lc.wire.Value,
    ) lc.testing.Reply {
        _ = state;
        if (std.mem.eql(u8, method, "view.open")) {
            return .{ .value = lc.wire.mapOf(alloc, &.{
                lc.wire.entry("file_id", lc.wire.str("f1")),
                lc.wire.entry("name", lc.wire.str("os-release")),
                lc.wire.entry("size", lc.wire.uint(3)),
            }) catch return oom() };
        }
        return .{ .fault = .{ .code = "METHOD_NOT_FOUND", .message = method } };
    }
};

test "run.start emits one record" {
    var stub = lc.testing.Stub.init(std.testing.allocator, null, State.handle);
    defer stub.deinit();
    var api = stub.api();
    var table = try lc.testing.entry(&api, &plugin);
    defer table.destroy(table.instance);

    const reply = try lc.testing.callOk(std.testing.allocator, &table, 2, "run.start", params);
    try std.testing.expectEqualStrings("...", reply.?.getString("summary").?);
    try std.testing.expectEqual(@as(u64, 1), stub.emittedCount());
}
```

`Reply` 三选一：`.value`（成功，带载荷）、`.empty`（成功，无载荷）、`.fault`（失败，
`{code, message}`）。`call` 返回 `CallResult{ status, payload, fault }` 并保留原始状态码；
`callOk` 把非 `STATUS_OK` 变成 `lc.Error`。

两个坑：

- **`stub` 不能被移动。** 插件表里存的是它的地址（`context`），所以它必须是局部变量或堆上的，
  不能写在"按值返回的结构体"里初始化，否则第一次调用就段错误。
- **未知方法到不了 `handle`。** `runtime.zig` 先按 `Method.parse` 表拒绝，回 `STATUS_ERROR` +
  `METHOD_NOT_FOUND`，消息是 `plugin method fs.unknown is not available`，不是裸方法名。

---

## 九、和 Rust SDK 的差异

Zig 版按同样的协议和宿主方法实现，接口按 Zig 的习惯做了调整：

| Rust | Zig | 说明 |
| --- | --- | --- |
| `trait Analyzer`（`run(&Run)`） | `lc.analyzer(id, fn (run: *const Run) Error!void)` | 分析器就是一个函数 |
| `#[derive(Record)]` | `lc.RecordSchema.new(...)` + 位置值 | 没有宏；值按字段顺序传 |
| `Run::record(&T)` | `run.record(type, values)` | `Emit` 链式 API 相同 |
| `Result<T>` / `Error{code,message}` | `lc.Error` + 线程本地 fault 槽 | Zig 的 error 不能带载荷 |
| `Plugin::new(id).record::<T>().analyzer(id, f)` | `lc.Plugin{ .id, .records, .analyzers }` | 能力由字段推导 |
| `export_plugin!` 宏 | `comptime { lc.exportPlugin(@This()); }` | 导出同一个符号 |
| `Timestamp`（`String`） | `Timestamp`（`[40]u8`，无分配器） | `asStr()` 取字符串 |
| `view.read_text` 返回 `Option<String>` | `readText` 返回 `Error!?[]const u8` | 不存在时是 `null` |
| `find(patterns)` 返回 `Vec<String>` | `find(patterns)` 返回 `[]const []const u8` | 超过 4096 条是 `RESOURCE_LIMIT` |
| `loader` feature（宿主侧加载） | 无 | 宿主是 Rust，Zig 侧不需要 |
| `rmp-serde` / `serde` | `wire.zig` 自带的最小子集 | 没有第三方依赖 |

宿主集成时注意三条实测过的约束：

- **时间戳必须是 RFC 3339 字符串**：宿主的 `LppTimestampsV1` 是 `Option<String>`，
  并用 `chrono::DateTime::parse_from_rfc3339` 校验。
- **`FsStat.mime` 不能为空**：宿主 DTO 是 `String`。
- **`schema_hash` 必须与宿主一致**：宿主用 `rmp_serde::to_vec_named` 重新编码记录结构再算
  fnv1a64，Zig 侧的 `schema.toValue` 因此严格保持字段顺序与"空值省略"规则。
