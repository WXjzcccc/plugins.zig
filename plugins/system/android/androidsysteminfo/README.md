# androidsysteminfo — Android 系统信息

 LovelyCarve 插件（LPP v2，SDK 0.2.0）：解析 Android `data` 分区（来自 zip/镜像内的
`data/` 目录树）的系统信息、系统日志、应用列表与网络相关记录。检材参考为小米
MIUI（Android 13， venus / Mi 11），核心格式解析不绑定厂商。

**时间**：所有时间戳统一以 **UTC+8** 输出（epoch 值换算；带其他偏移的墙钟时间先按原偏移定位瞬间再换算到 +8，文本无偏移时按 +8 解释）。

## 分析器

| 分析器 | 名称 | 作用域 | 分类 | 输入 |
| --- | --- | --- | --- | --- |
| `baseinfo` | 系统信息 | evidence | baseinfo | `data/system/dropbox/SYSTEM_BOOT@*.txt`、`data/system/last-header.txt`、`data/system/packages.xml`、`data/system/users/*.xml` |
| `syslog` | 系统日志 | evidence | syslog | `data/local/bootlog/bootlog.txt`、`data/system/dropbox/*`、`data/anr/*` |
| `applist` | 应用列表 | evidence | appinfo | `data/system/packages.xml`、`data/system/packages.list`、`data/misc_de/*/apexdata/com.android.permission/runtime-permissions.xml` |
| `netrecords` | 网络与其他记录 | evidence | netrecord | `data/misc/apexdata/com.android.wifi/WifiConfigStore*.xml`、`data/misc/bluedroid/bt_config.conf{,.bak}`、`data/misc/adb/adb_keys`、`data/misc/adb/adb_temp_keys.xml`、`data/system_ce/*/accounts_ce.db`、`data/system/gnssCollectData.db` |

## 记录

| 记录类型 | 名称 | 来源 |
| --- | --- | --- |
| `androidsysteminfo.device` | 系统属性 | SYSTEM_BOOT / last-header 头（Build/Hardware/Kernel/Radio…）+ packages.xml 的 `<version>` 框架属性（sdkVersion/fingerprint…）；同名属性后解析的文件覆盖先解析的 |
| `androidsysteminfo.boot` | 开机记录 | dropbox `SYSTEM_BOOT@<epoch-ms>` 条目，时间取自条目名；`历史开机` = isPrevious |
| `androidsysteminfo.user` | 设备用户 | `users/<id>.xml`（ABX） |
| `androidsysteminfo.log` | 运行日志 | bootlog.txt 全量 logcat（threadtime 格式），一条头行 + 其后续行合并为一条记录；时间 = 横幅年份+时区偏移与行内月日时分秒 |
| `androidsysteminfo.entry` | 系统事件 | dropbox 条目（wtf 等，时间取条目名）与 ANR 记录（时间取 `----- pid N at ... +0800 -----`，缺省时回退文件名） |
| `androidsysteminfo.app` | 应用列表 | packages.xml（ABX）为主，packages.list 补数据目录/seinfo；packages.xml 不可用时整体回退 packages.list |
| `androidsysteminfo.permission` | 授权权限 | Android 12+ 授权在 runtime-permissions.xml（普通 XML）；旧版本 packages.xml `<perms>` 同样解析 |
| `androidsysteminfo.wifi` | Wi-Fi 网络 | WifiConfigStore.xml：SSID/安全类型/明文 PSK/最近连接断开时间/网关 MAC 等 |
| `androidsysteminfo.softap` | 热点配置 | WifiConfigStoreSoftAp.xml：SSID/安全类型/明文密码 |
| `androidsysteminfo.bluetooth` | 蓝牙记录 | bt_config.conf（INI）：本机适配器与已配对设备（bt_config.bak 仅在主文件无设备时兜底） |
| `androidsysteminfo.adbkey` | ADB 授权密钥 | adb_keys（永久）+ adb_temp_keys.xml（临时，含最后连接时间）；按密钥 SHA-256 去重，永久优先 |
| `androidsysteminfo.bssid` | 连接热点 MAC | adb_temp_keys.xml 的 wifiAP BSSID |
| `androidsysteminfo.account` | 系统账号 | accounts_ce.db（SQLite，只读临时副本）；本检材该表为空 |
| `androidsysteminfo.gnss` | GNSS 记录 | gnssCollectData.db（SQLite）；本检材该表为空 |

## 选项

| 分析器 | 选项 | 类型 | 语义 |
| --- | --- | --- | --- |
| baseinfo | `items` | multi | `device`（系统属性）/ `boot`（开机记录）/ `users`（设备用户）；**留空 = 全部** |
| syslog | `buffers` | multi | `main`/`system`/`crash`/`radio`/`events`；**留空 = 全部缓冲区** |
| syslog | `levels` | multi | `v`/`d`/`i`/`w`/`e`/`f`（小写 id，对应 logcat V~F）；**留空 = 全部级别** |
| applist | `items` | multi | `list`（应用列表）/ `permissions`（授权权限）；**留空 = 全部** |
| netrecords | `items` | multi | `wifi`/`bluetooth`/`adb`/`accounts`/`gnss`；**留空 = 全部** |

## 格式实现

- **ABX**（Android Binary XML，`ABX\0` 魔数，`BinaryXmlSerializer` 线格式）：`core/abx.zig`
  自行实现——token=低半字节 XmlPullParser 事件、类型=高半字节、`FastDataOutput`
  大端原语、0xFFFF 引入新串的字典编码。与 `libs/axml.zig`（APK 的资源 AXML）是两种不同格式。
- **普通 XML**（WifiConfigStore 等 TypedXmlSerializer 输出，`<类型 name="键">` 形状）：`core/xml.zig` 极简解析器。
- **logcat**：横幅行取年份与时区（CST=+08:00 等少数缩写），行内时间只有月日时分秒；
  换算到 UTC+8 输出（横幅无已知缩写时按 +8 解释行内墙钟）。设备早期引导时钟未同步时
  （如本检材 02-28 的行）如实按横幅年份落时间，不猜测跨年。
- **gzip**：dropbox 的 `.txt.gz` 条目（如 SYSTEM_RECOVERY_LOG）经 `std.compress.flate`
  解压后按普通条目解析，解压上限 `MAX_TEXT_SIZE`（64 MiB）防解压炸弹；解压缓冲走 libc
  分配、逐条目释放。
- **SQLite**：`libs/zqlite.zig`（karlseguin，捆绑官方 amalgamation，静态链接）。检材内的库文件经
  `file.materialize`（插件声明了 `file_materialize` 权限）落成只读临时副本后打开。
- **INI**（bt_config）：共享库 `libs/ini.zig`。

## 内存与上限（具名常量，见 `plugin/analyze.zig`）

| 常量 | 值 | 含义 |
| --- | --- | --- |
| `MAX_TEXT_SIZE` | 64 MiB | 单个文本文件读取上限（bootlog.txt 实测 13 MiB / 9.5 万行） |
| `MAX_XML_SIZE` | 32 MiB | 单个 ABX/XML 文件上限（packages.xml 实测 342 KB） |
| `MAX_DB_SIZE` | 64 MiB | 单个 SQLite 库上限 |
| `MAX_MESSAGE_BYTES` | 32 KiB | 单条日志 message 上限（含堆栈续行） |

文本文件整读入 libc 分配的缓冲、逐文件释放（读取回复实际驻留 run arena，不单独释放）；
解析值驻留 run arena。坏文件 = 告警（`ANDROIDSYSTEMINFO_*`），不失败整次运行。

## 构建与验证

```sh
zig build test      # 单元测试 + lc.testing 假宿主端到端（每个分析器各一例）
zig build probe     # zig-out/bin/probe.exe <data 分区文件...>，按文件名分发，无宿主
zig build package   # dist/com.wxjzc.androidsysteminfo-<版本>-<平台>.lcpkg
```

真宿主验证（本检材，CLI `plugins tasks create --function com.wxjzc.androidsysteminfo/<id>`）：

| 分析器 | 结果 |
| --- | --- |
| baseinfo | 12 条（10 系统属性 + 1 开机 + 1 用户） |
| syslog | 94766 条日志 + 2 个系统事件（1 条 .gz 压缩条目告警跳过） |
| applist | 348 应用 + 3970 授权权限 |
| netrecords | 3 Wi-Fi + 1 热点 + 1 蓝牙 + 7 ADB 密钥 + 2 BSSID（accounts/GNSS 表为空） |

已知差异/限制：

- logcat 时间依赖横幅的时区缩写表（CST/UTC/GMT）；未知缩写按 +8 解释行内墙钟。
- `data/system_ce/*/accounts_ce.db` 与 `gnssCollectData.db` 在本检材中表为空，路径与解析已验证。
- ANR 墙钟时间不带偏移时按 +8 解释；带任意偏移都会换算到 +8 输出。

## 与参考实现的差异

无公开参考实现；ABX 线格式对照 AOSP `frameworks/libs/modules-utils` 的
`BinaryXmlSerializer.java` / `FastDataOutput.java`（Android 13 `TKQ1.220829.002` 检材验证）。
协议机制见[PLUGIN_PROTOCOL.md](../../../docs/PLUGIN_PROTOCOL.md)。
