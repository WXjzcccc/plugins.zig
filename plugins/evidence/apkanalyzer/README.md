# APK 分析插件（LPP v2 / SDK 0.2.0）

把独立项目 `apk_analyzer` 的全部分析能力搬进 LovelyCarve：解析 ZIP 中央目录、
Android 二进制清单（AXML）、资源表（resources.arsc）、JAR v1 与 APK Signature
Scheme v2/v3/v3.1 签名，以及权限目录、加固与框架识别、应用图标提取，并把结果写成
带类型的记录。解析核心仍是原来那份 Zig 代码，只是文件 IO 换成了宿主的只读文件句柄。

## 两个分析器

| 分析器 | 作用域 | 触发 | 作用 |
|---|---|---|---|
| `apkevidence` | evidence | auto | 解析检材中**所有** `*.apk`（清单 `inputs = ["**/*.apk"]`，宿主按扩展名匹配，大小写不敏感） |
| `apkfile` | files | manual | 解析用户在文件浏览器中**选中**的 APK（`extensions = ["apk"]`） |

两个分析器走同一段分析代码（`src/plugin/analyze.zig`），所以同一个 APK 无论从哪个入口
进入，产出的记录完全一致。检材作用域在检材上线后自动建任务，逐个包报告进度；单个包读不出、
不是 ZIP、缺 `AndroidManifest.xml` 都只记为运行告警（`run.warn`），不影响其余包。

## 记录

一个包会产出多张表。每张表以 `package_name`（包名）开头并作为记录身份（2.0.0 起不再有
`file` 列）：一次运行覆盖多个 APK 时靠包名与行级名称（组件名/权限名/方案等）区分记录，
来源文件通过记录的系统来源定位跳转。manifest 缺包名的 APK 以文件名兜底作包名。
`apkevidence`（检材级）与 `apkfile`（文件级）共用同一条记录构造路径，两个作用域一致：

| 记录类型 | 内容 |
|---|---|
| `apk.info` | 包名、应用名、版本名/版本号、min/target/compile SDK、启动 Activity、可调试、允许备份、大小、SHA-256、条目统计、资源统计、签名方案、加固、框架 |
| `apk.component` | Activity / 别名 / Service / Receiver / Provider：导出、启用、权限、进程、authorities、标签，Intent 过滤器与元数据在详情里 |
| `apk.permission` | 权限名、风险等级（普通/敏感/危险，来自内置权限目录）、maxSdkVersion、显示名与说明 |
| `apk.feature` | `<uses-feature>`：名称、OpenGL ES 版本、是否必需 |
| `apk.metadata` | `<meta-data>`：名称、值、值类型 |
| `apk.signer` | 每个签名方案的签名者：方案、min/max SDK、签名与摘要算法、证书数 |
| `apk.certificate` | 证书：SHA-256/SHA-1/MD5、序列号、主题、颁发者、生效/失效时间（RFC 3339）、算法、公钥位数 |
| `apk.detection` | 加固（`protection`）与框架（`framework`）识别结果及其证据条目 |
| `apk.entry` | 归档条目（仅勾选「列出归档条目」时） |
| `apk.diagnostic` | 解析过程中可恢复的问题（阶段、级别、代码、消息、条目、偏移） |
| `apk.icon` | 启动图标：条目、类型（位图/自适应/SVG）、大小、SHA-256 |

`apk.info` 的标题用包名；危险权限记录带 `high` 严重级别，方便在结果里先看高危项。
签名结构与证书只做解析，**不做密码学验签**，`cryptographic_verification` 恒为 `false`，
与原始项目的安全声明一致。

## 选项

两个分析器的选项相同：

| 选项 | 类型 | 说明 |
|---|---|---|
| `items` | multi | 要输出的子项（应用信息、组件、权限、特性、元数据、签名、加固与框架、诊断、图标）；留空 = 全选 |
| `entries` | flag | 列出归档条目；默认关闭，单个 APK 可能上万条 |
| `locale` | text | 资源语言（如 `zh-CN`）；留空使用 Android 默认资源 |
| `density` | text | 资源密度（dpi，如 `480`）；影响图标与尺寸类资源的挑选 |
| `max_size` | text | 最大 APK 大小（MiB）；留空用解析器上限（2 GiB） |

## 目录结构

解析核心保持原项目的树形结构，插件层单独放在 `src/plugin/`：

```text
src/
├── root.zig                    插件身份、两个分析器的注册、握手与端到端测试
├── describe.zig                导出 schema.json（zig build schema）
├── probe.zig                   开发工具：解析一个 APK 并逐字段校验记录值
├── embeded_asset.zig           内置的权限/加固/框架目录
├── assets/data/*.json          上述目录的 JSON 源文件
├── core/                       解析核心（与 apk_analyzer 一一对应）
│   ├── limits.zig  model.zig
│   ├── analysis/               engine、catalog、icon、signing_info
│   ├── android/                chunk、string_pool、typed_value、axml/、manifest/、resources/
│   └── signing/                der、x509、cms、apk_block、parser、algorithms
├── utils/
│   ├── io/cursor.zig           越界安全的游标
│   ├── zip/archive.zig         ZIP/APK 中央目录、ZIP64、deflate
│   └── logging.zig             把解析日志转给 SDK 的插件日志
└── plugin/
    ├── run.zig                 两个分析器入口（evidence / files）与共用循环
    ├── analyze.zig             读文件、调核心、发记录、错误映射
    ├── conversion.zig          解析模型 → 记录值（位置参数）
    └── records.zig             记录结构与字段定义
```

## 构建与验证

```sh
zig build test                 # 单元测试（解析核心 + 插件层，含假宿主端到端）
zig build                      # ReleaseSafe 动态库 -> zig-out/lib/apkanalyzer.dll
zig build schema               # 从库导出 zig-out/schema.json
zig build package              # -> ../../../../dist/<id>-<version>-<platform>.lcpkg
zig build probe                # 开发工具 -> zig-out/bin/probe.exe
```

用真宿主 `lc-plugin-host` 验证：

```sh
# 1) 库自己报的结构必须与包内 schema.json 一致
plugins/target/debug/lc-plugin-host.exe --describe --library zig-out/lib/apkanalyzer.dll
diff <(cat zig-out/schema.json) <(plugins/target/debug/lc-plugin-host.exe --describe --library zig-out/lib/apkanalyzer.dll)

# 2) 端到端：脚本扮演 LovelyCarve 那一侧，按真实 APK 应答 file.read
python scripts/drive.py plugins/target/debug/lc-plugin-host.exe zig-out/lib/apkanalyzer.dll app.apk
python scripts/drive.py plugins/target/debug/lc-plugin-host.exe zig-out/lib/apkanalyzer.dll a.apk b.apk apkevidence

# 3) 逐字段校验记录值（开发时排查结构与转换不一致）
zig-out/bin/probe.exe app.apk
```

## 装进 LovelyCarve

把 `zig-out/<id>-<version>-<platform>.lcpkg` 拷到目标机器，在「设置 → 插件」里安装
（CLI 等价于 `plugins create <包路径>`），或直接把包目录放进插件扫描目录。
`apkevidence` 会在检材上线后自动运行；`apkfile` 在文件浏览器里选中 APK 后手动发起。

## 与原始项目的差异

| 原始项目 | 插件 | 原因 |
|---|---|---|
| `analyzeFile(io, …)` 直接读磁盘 | `analyzeBytes(alloc, data, …)` | 插件只能通过宿主的只读句柄读证据；文件读取在 `plugin/analyze.zig` |
| 资源语言回退到本机 Windows 语言 | 只按选项/界面语言 | 分析结果不应取决于取证人员所用机器的区域设置 |
| `logz` 写 `apk-analyzer.log` | SDK 的插件日志（`Run.log`） | 插件日志统一由宿主收集，日志里带解析子系统前缀 |
| CLI / GUI 的文本与 JSON 输出（`utils/output/`） | 带类型的记录表 | 结果进 `records.db`，由界面按结构渲染、排序与检索；归档清单由「列出归档条目」选项产出 `apk.entry` |
| `embeded_asset` 模块路径在仓库根 | `src/embeded_asset.zig` | 模块内 `@embedFile` 只能引用模块目录内的文件 |
| `core/analysis/api.zig`（转发 engine） | 不需要 | 插件直接引用 `core/analysis/engine.zig` |
| CLI（`cli/`）与 GUI（`gui/`） | 不需要 | 参数解析与界面属于应用侧，插件只做解析 |
