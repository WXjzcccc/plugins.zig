# Zig 插件模板（LPP v2 / SDK 0.2.0）

一个能加载、能出结果、能打包的最小 LovelyCarve 插件：读取 Linux 系统视图里的
`etc/os-release`，每个上报字段产出一条带类型的记录。

它展示一个完整插件的全部组成：

| 文件 | 作用 |
|---|---|
| `src/root.zig` | 身份、记录结构、**分析逻辑**、测试用的假宿主 |
| `src/describe.zig` | 从库代码导出 `schema.json`（`zig build schema` 使用） |
| `build.zig` / `build.zig.zon` | 产出动态库、测试、`schema` 与 `package` 步骤 |
| `scripts/pack.zig` | 暂存包目录、写 SHA-256、打成 STORED ZIP（无外部工具） |
| `scripts/drive.py` | 用 LPP v2 帧驱动真宿主 `lc-plugin-host`，端到端跑一遍 |
| `plugin.toml` | 清单：身份、库名、内存上限、分析器 |

## 快速开始

```sh
cd templates/LovelyCarve-plugin-zigtemplate

zig build test                     # 单元测试（含假宿主，不需要真宿主）
zig build                          # ReleaseSafe 动态库 -> zig-out/lib/
zig build schema                   # 从库导出 zig-out/schema.json
zig build package                  # -> zig-out/<id>-<version>-<platform>.lcpkg
zig build -Doptimize=Debug         # 调试构建（默认是 ReleaseSafe）
```

用真宿主验证：

```sh
# 先构建加载器（仓库根目录）
cargo build --locked --manifest-path plugins/Cargo.toml -p lc-plugin-host

# 1) 对照 schema：库自己报的结构必须和 zig build schema 一致
plugins/target/debug/lc-plugin-host.exe --describe --library zig-out/lib/zigtemplate.dll

# 2) 端到端跑一次分析（脚本扮演 LovelyCarve 那一侧）
python scripts/drive.py plugins/target/debug/lc-plugin-host.exe zig-out/lib/zigtemplate.dll
```

`drive.py` 会打印 `plugin.hello`（协议版本、插件 id、SDK 版本、分析器、记录类型、
结构哈希）、每条记录及其来源、进度与日志。默认分析器是 `zigtemplateosrelease`，
可以用第三个参数指定。

## 换成你自己的插件

复制这个目录，然后改这几处：

| 位置 | 改什么 |
|---|---|
| `plugin.toml` | `id` / `name` / `version` / `library` / `[[analyzer]] id` |
| `build.zig` | `addLibrary(.name = "…")`（= 清单的 `library`）、包名与 `--platform` |
| `build.zig.zon` | `.name`、`.fingerprint`、SDK 依赖路径 |
| `src/root.zig` | `PLUGIN_ID` / `ANALYZER_ID` / `NS`、`RELEASE_SCHEMA`、`analyze()` |

`.fingerprint` 是 Zig 0.17 的硬要求，且不能随便编（它是包名与依赖的哈希）：改包名或
依赖后第一次 `zig build` 会报 `invalid fingerprint: ...; use this value: 0x...`，
把提示的值填回去即可。

两个命名规则容易踩：

- **分析器 id 是小写标识符**（`a-z`、`0-9`、`_`，最长 64 字节），不能带点：
  `zigtemplateosrelease`，不是 `zigtemplate.osrelease`。清单和
  `lc.analyzer(ANALYZER_ID, analyze)` 必须一致，否则握手失败（`INVALID_ANALYZER` /
  清单校验不过）。
- **记录类型是带命名空间的小写标识**（点分）：`zigtemplate.release`。插件最多 256
  种记录类型、每种最多 128 个字段。

## 记录

一个记录类型是一份 `lc.RecordSchema`：字段按**位置**给出值，宿主为它建一张类型化
的表，列名、排序、检索都来自结构。模板的记录类型：

```zig
const RELEASE_SCHEMA = lc.RecordSchema.new(RELEASE_TYPE, "系统信息", &.{
    lc.Field.new("key", "英文名称", .text).asKey(),
    lc.Field.new("field_value", "值", .text),
    lc.Field.new("source", "源文件", .path),
}).withTitle("{key}");
```

```zig
try run.record(RELEASE_TYPE, &.{
    lc.wire.str(reported.key),
    lc.wire.str(value),
    lc.wire.str(release.path),
}).from(&release.file).emit();
```

- `key` 字段组成记录身份；`withTitle("{key}")` 用字段值渲染标题。不写 `title`
  时，键字段用 ` · ` 连接。
- 字段类型（`kind`）决定存储、显示、排序与检索：`text`、`int`、`float`、
  `boolean`、`timestamp`、`size`、`duration`、`path`、`hash`、`ip`、
  `enumeration`、`list`、`json`。
- `withTimeline("login")` 只对 `timestamp` 字段有效，且值必须带时区偏移才会投影
  到案件时间线；时区未知的本地时间照常存储与排序，但不会被当成 UTC。
- `.from(&file)` 自动填来源（卷键、卷内路径、节点 id），界面据此「定位源文件」。
  还可以 `.at(offset, length)` 收窄到字节区间，`.note("第 12 行")` 说明记录在来源
  中的位置，`.title(...)` / `.severity(...)` 覆盖标题与严重级别。
- 运行时才知道列的结构用 `lc.DynamicRecord.init(alloc, schema)` + `.set(field, value)`。

## 运行期 API

`analyze(run: *const lc.Run)` 里能用的主要接口：

- 视图：`run.requireView()`（files 作用域没有视图，会得到 `INVALID_TARGET`）、
  `view.open` / `readText` / `readLines` / `read` / `stat` / `exists` /
  `isFile` / `isDir` / `list` / `listOrEmpty` / `find`（glob）/ `source`。
- 文件句柄：`FileRef.readAt` / `readAll` / `readText` / `readLines` / `readv` /
  `materialize`（需要清单权限 `file_materialize`）。
- 记录：`emit` / `record`（builder）/ `dynamic` / `recordValues`。
- 画像事实：`run.provide("hostname", lc.wire.str(name))`，清单里用 `provides` 声明。
- 诊断：`run.warn` / `run.warnFile`（随结果保存，不使运行失败）、
  `run.progress`、`run.setSummary`、`run.log`。
- 取消：长循环里轮询 `run.checkCancelled()`；宿主调用在取消后返回 `CANCELLED`。

记录在 SDK 里按结构校验后成批发送（每批最多 1000 条或 2 MiB），`emit` 的错误会
丢弃整个运行已发出的记录，所以宁可 `warn` 也不要为一条坏记录失败。

## 清单（plugin.toml）

```toml
id = "com.wxjzc.zigtemplate"     # 与 PLUGIN_ID 一致
name = "模板"
version = "0.2.0"
protocol = 2                      # 只支持 LPP v2
library = "zigtemplate"           # 无扩展名时按平台补 zigtemplate.dll / libzigtemplate.so
memory = "512MiB"                 # 插件进程内存上限，缺省 2GiB

[[analyzer]]
id = "zigtemplateosrelease"       # 与 ANALYZER_ID 一致
name = "系统信息（模板）"
scope = "system"                  # system / evidence / files
platforms = ["linux"]             # 仅 system：适用的系统族
trigger = "manual"                # 或 auto（检材上线 / 依赖事实发布时自动建任务）
category = "baseinfo"
inputs = ["etc/os-release", "usr/lib/os-release"]
```

`inputs` 是宿主在运行前解析成输入文件的视图路径模式（最多 64 个），匹配到的文件
通过 `run.inputsOf()` 交给插件；模板为了演示 `view.open` 仍然自己打开文件。

## 测试

`lc.testing` 是假宿主：填一个 `handle` 应答宿主方法，就能通过真实的 C ABI 入口驱动
整个插件，`run.start` 一路跑到记录落盘。

```zig
var stub = lc.testing.Stub.init(testing.allocator, null, MockHost.handle);
defer stub.deinit();
var api = stub.api();
var table = try lc.testing.entry(&api, &plugin);
defer table.destroy(table.instance);
```

- `stub` 必须是局部变量（或堆上）且**不能移动**：插件表里存的是它的地址。
- 桩自己应答 `run.emit` / `run.progress` / `run.warn` / `file.release`，并把
  它们记在 `stub.emits` / `stub.progress` / `stub.warnings` 里；其余方法
  （`view.*`、`file.read`、`file.readv`、`file.materialize`、`source.*`）
  交给你的 `handle`。
- `stub.emittedRecords(alloc)` 展平所有批次，便于断言记录内容与来源。

模板的测试覆盖：握手（协议版本、插件 id、SDK 版本、分析器、记录结构与
`schema_hash`）、`run.start` 端到端出记录、没有 os-release 时的摘要、日志与进度、
未知分析器被拒绝、以及 os-release 解析规则。

## 打包

`zig build package` 产出两个东西：

```text
zig-out/com.wxjzc.zigtemplate-0.2.0-windows-x64/          # 暂存的包目录
├── plugin.toml
├── zigtemplate.dll
├── schema.json
├── README.md
├── build.json            # 插件 id、版本、协议、平台、库名、构建时间
└── SHA256SUMS.txt        # 每个文件的 SHA-256（sha256sum -c 格式）
zig-out/com.wxjzc.zigtemplate-0.2.0-windows-x64.lcpkg     # 上面目录的 ZIP
```

- 平台标签来自构建目标：`windows-x64`、`linux-x64`、`linux-arm64`、
  `macos-x64`、`macos-arm64`。
- `.lcpkg` 是包目录的 ZIP，`plugin.toml` 在压缩包根部；条目用 STORED（method 0）
  存放，库字节原样保留，CRC-32 与 SHA-256 由 `scripts/pack.zig` 自己算，不调用
  外部 zip 工具。
- 可选 `locales/`：插件有翻译时，目录里的 `*.toml` 会被一起打包（模板没有）。

## 装进 LovelyCarve

1. 把 `.lcpkg` 拷到目标机器；
2. 在「设置 → 插件」里安装（命令行等价于 `plugins create <包路径>`）；
3. 安装目录是用户数据目录下的 `plugins/<插件 id>`，程序旁边的内置插件不会被替换；
4. 重启应用或重新安装后生效（已加载的库不会卸载）。

也可以直接把包目录复制到插件扫描目录（用户数据目录的 `plugins`、程序目录旁的
`plugins`，或 `LOVELYCARVE_PLUGIN_DIR` 指定的目录），发现即加载。

安装与握手会校验：清单、`schema.json`、语言包、当前平台的库文件，以及库自己
`plugin.hello` 报告的分析器 / 记录结构 / `schema_hash` 是否与包内文件一致。任何
一项对不上都会被拒绝，并提示重新构建插件包。

## Zig 0.17 的坑

完整清单（12 条，含 `std.Io` 文件 IO、`std.atomic.Mutex`、`&.{...}` 栈临时量、
互递归要显式 error set、`callconv(.c)`、`fingerprint` 必填等）见
`plugins/zig-sdk/README.md` 的「Zig 0.17 的坑」。插件作者另外要注意：

- **`main(init: std.process.Init)`**：独立程序（`src/describe.zig`、
  `scripts/pack.zig`）的文件 IO 用 `init.io` 加 `std.Io.Dir.cwd()`，读文件是
  `cwd.readFileAlloc(io, path, alloc, .limited(n))`，写文件是
  `cwd.writeFile(io, .{ .sub_path = path, .data = bytes })`。库代码里没有 `Io`。
- **`ArrayList` 是非托管容器**：`.empty` 初始化，每次调用都传分配器。
- **默认 ReleaseSafe**：`build.zig` 用 `b.option(std.builtin.Optimize, ...) orelse .safe`，
  所以 `zig build` 直接出发布库，`-Doptimize=Debug` 出调试库；测试始终 Debug。
- **插件名用 ASCII**：中文名在 PE 导出表和日志里可能显示成乱码（字节是对的）。

## 相关文档

- `plugins/zig-sdk/README.md`：SDK 每个模块与 API、Zig 0.17 迁移清单。
- `docs/PLUGIN_PROTOCOL.md`：LPP v2 协议、清单字段、记录结构与打包安装规则。
