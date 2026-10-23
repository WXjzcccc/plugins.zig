# Windows 系统信息插件（LPP v2 / SDK 0.2.0）

把 ForensicsTool 的注册表取证分析（`analyzers/winreg`）复刻为 LovelyCarve 插件：
从检材中的 **SYSTEM / SOFTWARE / SECURITY / SAM / NTUSER.DAT** 配置单元提取系统
信息、网卡信息、用户账户（含 NT 密码哈希解密）与默认浏览器，写成带类型的记录。配置单元
（REGF 格式）的解析本身由本仓库的 `libs/regf.zig` 独立库完成，本插件只在其上
实现取证问题；SAM 哈希解密用的 RC4 / DES / AES-CBC / MD5 来自
[zig-cryptobin](https://github.com/WXjzcccc/zig-cryptobin)。

## 分析器

| 分析器 | 作用域 | 触发 | 作用 |
|---|---|---|---|
| `winsysteminfoevidence` | evidence | auto | 在检材里查找注册表配置单元（`inputs = ["**/SYSTEM", "**/SOFTWARE", "**/SAM", "**/*.DAT"]`，宿主按文件名匹配、大小写不敏感），上线后自动运行 |

文件名决定配置单元的角色，与 ForensicsTool 的目录遍历一致：`SYSTEM`、
`SOFTWARE`、`SAM` 各取一个，其余所有 `*.DAT` 视为用户配置单元（NTUSER.DAT
及同类）。不是配置单元的匹配文件只记一条运行告警，不影响其余分析。

## 记录

| 记录类型 | 内容 |
|---|---|
| `winsysteminfo.system` | 系统信息：Build、版本、计算机名称、安装时间、产品 ID、注册所有者/组织、时区、最后一次正常关机时间、产品密钥备份、上次登录的用户；每行一条，`source` 标明来自哪个配置单元 |
| `winsysteminfo.network` | 当前控制集（`Select\Current`）每个 TCP/IP 接口：连接名称、IP/掩码/网关、当前与物理 MAC、DHCP 地址/网关/服务器与租约起止时间 |
| `winsysteminfo.user` | SAM 用户：用户名、SID（机器 SID 来自 SECURITY 的 `PolMachineSid`，缺失时回退 SAM 域 `V` 值末 12 字节）、RID、解密后的 NT 哈希、全名、描述、上次登录/改密/登录失败时间、登录次数、用户属性 |
| `winsysteminfo.browser` | 每个用户配置单元的 HTTP `UserChoice` ProgId（默认浏览器） |

所有时间戳一律输出为绝对时刻（UTC），由宿主按界面时区渲染；`FILETIME` 为 0
（从未发生）的时间不输出。

记录的来源由系统来源（`.from`）承载——在软件里可直接"定位源文件"跳转到对应
配置单元，不再单设"数据来源"列。唯一的例外是 `winsysteminfo.browser` 的 `hive`
字段：一次运行覆盖多个用户的 NTUSER 配置单元，仅凭 ProgId 无法区分记录身份，
因此按插件规范（`docs/PLUGIN_SPEC.md` 第二节）作为身份字段保留。

## SAM 哈希解密

复刻 ForensicsTool（经由 pypykatz）的完整链路：

1. 引导密钥（boot key）：`ControlSetXXX\Control\LSA\{JD,Skew1,GBG,Data}` 四个
   子键的 class name（regf 不直接暴露 class name，插件从 nk 原始单元读取），
   十六进制解码后按固定置换重排；
2. `SAM\Domains\Account` 的 `F` 值 → 域密钥数据（RC4 旧式或 AES），配合引导
   密钥解出 hashed boot key（旧式校验 MD5 校验和，不符即放弃解密并告警）；
3. 每个用户：`Users\Names\<用户>` 默认值以**注册表类型码**携带 RID（regf 的
   值类型读取即得，与原实现的 `GetValue` 语义一致），`Users\<RID>` 的 `V` 值
   按 pypykatz 布局解析，`F` 值给出登录时间与计数；
4. NT 哈希按域密钥数据的方案解密（RC4+MD5 或 AES-CBC），再用 RID 派生的两个
   DES 密钥解出最终哈希。

与原实现的差异（均为修正）：

| 原实现 | 插件 | 原因 |
|---|---|---|
| 以哈希块首字节是否为 1 判断旧式/AES | 以域密钥数据的方案（`F` 的标记字节）判断 | 首字节实为 PekID；PekID≠1 的配置单元（如部分 Win7 镜像）会被误判为 AES 而解析失败 |
| 机器 SID 取域 `V` 值固定 408 字节偏移 | 优先读 SECURITY 的 `Policy\PolMachineSid`（标准二进制 SID），缺失时回退域 `V` 值末 12 字节（pypykatz 的做法） | 现代 SAM 的域 `V` 普遍短于 424 字节，固定偏移必然解析失败，SID 只能输出 `-RID` |

## 选项

| 选项 | 类型 | 说明 |
|---|---|---|
| `items` | multi | 要输出的子项（系统信息、网卡信息、用户信息、默认浏览器）；留空 = 全选 |

缺少某个配置单元只影响对应子项并记运行告警：无 SOFTWARE → 系统信息、无 SYSTEM
→ 网卡信息（且用户哈希不可解密）、无 SAM → 用户信息；无 SECURITY → 机器 SID
回退到 SAM 域 `V` 值推算，通常无影响。

## 构建与验证

```sh
zig build test                 # 单元测试（解析核心 + 插件层，含假宿主端到端）
zig build                      # ReleaseSafe 动态库 -> zig-out/lib/winreganalyzer.dll
zig build schema               # 从库导出 zig-out/schema.json
zig build package              # -> ../../../../dist/<id>-<version>-<platform>.lcpkg
zig build probe                # 开发工具 -> zig-out/bin/probe.exe
```

`libs/regf.zig/testfiles/` 自带一套真实 hive（Windows 7 镜像），可用 probe
直接核对：

```sh
zig-out/bin/probe.exe ../../../libs/regf.zig/testfiles/SYSTEM \
                     ../../../libs/regf.zig/testfiles/SOFTWARE \
                     ../../../libs/regf.zig/testfiles/SAM
```

用真宿主 `lc-plugin-host` 验证：

```sh
# 1) 库自己报的结构必须与包内 schema.json 一致
plugins/target/debug/lc-plugin-host.exe --describe --library zig-out/lib/winreganalyzer.dll

# 2) 端到端：脚本扮演 LovelyCarve 那一侧，按真实 hive 应答 file.read
python ../../../../scripts/drive.py plugins/target/debug/lc-plugin-host.exe \
    zig-out/lib/winreganalyzer.dll \
    ../../../libs/regf.zig/testfiles/SYSTEM ../../../libs/regf.zig/testfiles/SOFTWARE \
    ../../../libs/regf.zig/testfiles/SAM winsysteminfoevidence
```
