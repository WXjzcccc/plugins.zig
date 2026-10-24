# Navicat 连接分析插件（LPP v2 / SDK 0.2.0）

把 ForensicsTool 的 Navicat 提取（`analyzers/extractor/tool/navicatTool.go`）的
**注册表部分**复刻为 LovelyCarve 插件：Navicat 把连接配置（主机、端口、用户与
保存的密码）存在每个用户的 `NTUSER.DAT` 里（`Software\PremiumSoft`），本插件
解析这些连接并解密保存的密码。配置单元（REGF 格式）的解析由本仓库的
`libs/regf.zig` 独立库完成；密码解密用的 AES-CBC / Blowfish / SHA-1 来自
[zig-cryptobin](https://github.com/WXjzcccc/zig-cryptobin)。

## 分析器

| 分析器 | 作用域 | 触发 | 作用 |
|---|---|---|---|
| `navicatevidence` | evidence | auto | 解析检材中**所有** `NTUSER.DAT`（清单 `inputs = ["**/NTUSER.DAT"]`），检材上线后自动运行 |
| `navicatfile` | files | manual | 解析用户在文件浏览器中选中的 `.dat` 配置单元 |

两个分析器走同一段分析代码（`src/plugin/analyze.zig`），产出的记录完全一致；
单个配置单元读不出、不是 hive 都只记为运行告警，不影响其余配置单元。

## 记录

按连接家族分表，每张表一行一个连接（`Software\PremiumSoft\<家族>\Servers\<连接>`
子键）：

| 记录类型 | 内容 |
|---|---|
| `navicat.mysql` / `navicat.mariadb` / `navicat.mongodb` / `navicat.oracle` / `navicat.postgresql` | 连接名、地址、端口、用户名、**解密后的密码**、缓存路径 |
| `navicat.mssql` | 同上，另有默认数据库与认证模式 |
| `navicat.sqlite` | 同上，另有默认数据库、是否加密、是否保存密码 |

记录不携带来源列：记录的来源由系统来源（`.from`）承载——在软件里可直接
"定位源文件"跳转到对应配置单元（插件规范 `docs/PLUGIN_SPEC.md` 第二节）。

## 密码解密

Navicat 的两种存储方案都把密文存为**十六进制文本**，按版本依次尝试
（与 ForensicsTool 的 `decryptNavicat` 一致）：

1. **Navicat 12+**：hex → AES-128-CBC（固定密钥 `libcckeylibcckey`、IV
   `libcciv libcciv `、PKCS7 填充）；结果必须是合法 UTF-8 才采纳；
2. **Navicat 11**：hex → Blowfish（密钥为 `SHA1("3DC5CA39")`，IV 为该密钥下
   `FF×8` 的 ECB 加密），按原实现的链规则解密（链接值吸收密文），明文不填充、
   末尾不足一个块的部分按 CFB 流处理。

解不开时密码记为空字符串，不影响其余字段。密码的注册表值：各家族读 `Pwd`，
SQLite 读 `EncryptionPassword`（加密数据库的密码，与原实现一致）。

## 构建与验证

```sh
zig build test                 # 单元测试（解析核心 + 插件层，含假宿主端到端）
zig build                      # ReleaseSafe 动态库 -> zig-out/lib/navicatanalyzer.dll
zig build schema               # 从库导出 zig-out/schema.json
zig build package              # -> ../../../../dist/<id>-<version>-<platform>.lcpkg
zig build probe                # 开发工具 -> zig-out/bin/probe.exe
```

```sh
# 用真实配置单元核对（libs/regf.zig/testfiles 的 SAM 中没有 Navicat 数据，
# 正常输出“no Navicat connections”）
zig-out/bin/probe.exe ../../../libs/regf.zig/testfiles/SAM

# 真宿主端到端
python ../../../../scripts/drive.py plugins/target/debug/lc-plugin-host.exe \
    zig-out/lib/navicatanalyzer.dll <NTUSER.DAT> navicatfile
```
