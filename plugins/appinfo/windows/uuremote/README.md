# UU远程分析（uuremote）

分析网易 UU远程（GameViewer）在本机留下的痕迹：账号身份与 JWT 凭据、内部设备
标识与最近使用时间线、主控/被控会话日志、缓存的远端文件列表、升级历史、遥测
会话，以及注册表中的安装信息与登录手机号。

插件 ID `com.wxjzc.uuremote`，记录命名空间 `uuremote`。INI 解析使用本仓库的
共享库 [`libs/ini.zig`](../../../../libs/ini.zig)，注册表 hive 解析使用
[`libs/regf.zig`](../../../../libs/regf.zig)。

## 数据来源与加密边界

三个数据目录（安装目录以实际为准，注册表 `HKCU\Software\Netease\GameViewer`
的 `instDir` 可确认）：

| 目录 | 内容 |
| --- | --- |
| `ProgramData\Netease\GameViewer` | `user_info.ini`（账号凭据）、`config.ini`（客户端 UUID）、`remote_assist_code.ini`（协助验证码设置） |
| `Users\<u>\AppData\Local\GameViewer` | `setting_<userId>.ini`（最近连接设备）、`security.ini`、`file_transfer\<deviceId>.json`（远端文件列表缓存）、`upgrade\upgrade.ini` |
| `<安装目录>\GameViewer\log|config` | 各组件 `.slog` 日志（按文件名分析）、`Sentry` 遥测、按设备显示配置 |

**有意不解析的加密数据**（遇到即跳过，不做逆向）：

- 所有 `.slog` 日志内容是 `SLOG` 加密格式——只解析文件名（时间戳、PID、角色、
  分段）与文件魔数。
- `remote_assist_code.ini` 的 `code`/`customize_code` 是 Windows DPAPI 密文
  （`AQAAANCMnd8…`）——只记录"已配置"，不尝试解密。
- 界面上显示的数字设备 ID（如 `398918340`）不存在于任何明文文件或注册表中，
  只能从加密日志或服务端获得；本插件记录的是 16 位内部设备标识
  （`user_info.ini` 的 `deviceId`、各文件名与节名中的 ID），两者无法互查。
- 注册表 `report_home_date` 等 REG_BINARY 值结构未知，跳过。

JWT 凭据是 base64url 编码的明文载荷，属标准解析而非解密：仅读取 `sub`、
`device_id`、`client_id`、`system_id`、`ip`、`iat`、`jti` 等声明，不校验签名。

## 分析器

| ID | scope | 输入 |
| --- | --- | --- |
| `uuremoteevidence` | evidence | `**/Netease/GameViewer/**/*`、`**/AppData/Local/GameViewer/**/*`、`**/GameViewer/log/**/*`、`**/GameViewer/config/**/*`、`**/NTUSER.DAT`（目录名大小写不敏感） |
| `uuremotefile` | files | 扩展名 `ini` / `json` / `slog` / `conf` / `dat`（含 NTUSER.DAT） |

两个分析器走同一分类逻辑：按扩展名与内容特征分发（`user_info.ini` 靠
`[General] deviceId`/`token` 识别，`upgrade.ini` 靠版本形节名识别等），不依赖
文件所在路径，因此文件模式下同样有效。

## 记录类型

| 类型 | 说明 | 关键字段 |
| --- | --- | --- |
| `uuremote.account` | 账号身份（user_info.ini + JWT 载荷） | `user_id`；`device_id`、`client_id`、`system_id`、`login_ip`、`issued_at`、`credential_id` |
| `uuremote.device` | 关联设备（多来源合并） | `device_id`；`role`（本机/远端）、`last_connect`、`assist_configured`、`assist_refreshed_at`、`privacy_seen`、`server_config`、`transfer_cached` |
| `uuremote.session` | 远程会话（主控/被控连接日志） | `role`+`start`+`pid`；`last_activity`、`size`、`segments`、`encrypted` |
| `uuremote.run_log` | 组件运行日志（client/server/service/launcher/healthd/upgrade） | `component`+`start`+`pid`；`size`、`segments`、`encrypted` |
| `uuremote.telemetry` | Sentry 遥测会话（应用版本证据） | —；`component`、`release`、`user_id`、`started`、`status`、`errors` |
| `uuremote.file_trace` | 远端文件浏览痕迹（file_transfer 缓存） | `device_id`+`path`；`name`、`kind`、`modified` |
| `uuremote.upgrade` | 升级记录（upgrade.ini） | `version`；`discovered_at`、`status`、`previous_version`、`subtitle`、`install_path`、`download_url`、`md5`、`error` |
| `uuremote.login` | 登录与安装信息（NTUSER.DAT） | `phone`；`login_time`、`app_version`、`install_dir`、`cache_path`、`installed`、`ever_run` |

合并语义与来源绑定：

- `uuremote.device` 由多文件合并（deviceslatest、security.ini、协助码、
  file_transfer、config/server），同一设备的观察合并为一行；记录绑定到**首个
  建立该设备的输入文件**，其余来源只补充标志位——这是"多来源合并记录"的例
  外，来源列不保留（见 PLUGIN_SPEC 第二节）。
- `uuremote.session` 将同一会话的 `connection_log_*` 与 `streamer_log_*`（相
  同时间戳+PID）以及 `.1/.2` 旋转分段合并为一行，`segments`/`size` 累加。
- 会话时间戳取自文件名（本地时钟，无时区信息），按 UTC 渲染；`last_activity`
  取文件的修改时间。

## 选项

| 选项 | 类型 | 缺省 | 说明 |
| --- | --- | --- | --- |
| `include_run_logs` | bool | true（留空即全选） | 是否为每个组件运行日志生成 `uuremote.run_log` 记录；关闭后仍产出会话、设备等其余记录 |

## 内存与上限

- INI/JSON 文本单文件读取上限 32 MiB（`MAX_TEXT_FILE`），超出记 WARN 跳过。
- 注册表 hive **不设上限**：真实用户 hive 常见数百 MB；峰值约为 hive 的 2-3 倍
  （读取缓冲 + regf 镜像副本），由 `plugin.toml` 的 `memory = "2GiB"` 兜底。
- 文件缓冲走 libc 分配器，解析值用每文件 arena，产出值进入 run arena。

## 构建与验证

```sh
zig build test      # 单元测试 + 端到端样例测试（根构建一次性跑全部插件）
zig build probe     # 真机验证：zig-out/bin/probe.exe <文件...>
zig build package   # 出包 dist/<id>-<version>-<platform>.lcpkg
```

`testfiles/` 存放本机采集的真实样例（与 winsysteminfo 的 `testfiles/7` 注册表
集同源），**不属于发布包**（`build.zig.zon` 的 `.paths` 未包含）。端到端测试
在运行时读取该目录：缺目录则跳过，样例中的账号值**不会**出现在测试代码里——
断言只检查结构与字段存在性。注册表 hive 样例较大，端到端中由
`registry.collect` 直接读取验证（经 stub 逐块读取会拖垮构建器的测试协议），
记录发射路径由单元测试与 probe 覆盖。

真机验证（在本机实测通过）：

```sh
zig-out/bin/probe.exe \
  testfiles/ProgramData/Netease/GameViewer/user_info.ini \
  testfiles/AppData/Local/GameViewer/setting_<userId>.ini \
  testfiles/AppData/Local/GameViewer/upgrade/upgrade.ini \
  testfiles/AppData/Local/GameViewer/file_transfer/<deviceId>.json \
  testfiles/log/service/Log/log_<ts>_<pid>.slog \
  testfiles/NTUSER.DAT
```

## 与参考实现的差异

- 参考 ForensicsTool 的 GameViewer 提取思路，但**不实现**任何解密：SLOG 日志
  与 DPAPI 验证码均只到"文件名/配置"层。
- 登录手机号来自注册表 `login\userPhone`（值名即手机号，QWORD 为微秒级时间
  戳），范围校验失败时时间记为空而非猜测。
