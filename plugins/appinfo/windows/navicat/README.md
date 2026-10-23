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

| 记录类型 | 内容 |
|---|---|
| `navicat.connection` | 连接名、连接类型（MySQL / MariaDB / MongoDB / Oracle / PostgreSQL / SQL Server / SQLite）、地址、端口、用户名、**解密后的密码**、缓存路径；SQL Server 另有默认数据库与认证模式，SQLite 另有是否加密、是否保存密码 |

每个 `Software\PremiumSoft\<家族>\Servers\<连接>` 子键一行，`source` 列标明
来自哪个配置单元。

## 密码解密

按 Navicat 的两种存储方案依次尝试（与 ForensicsTool 的 `decryptNavicat` 一致）：

1. **Navicat 12+**：base64 → AES-128-CBC（固定密钥 `libcckeylibcckey`、IV
   `libcciv libcciv `、PKCS7 填充）；结果必须是合法 UTF-8 才采纳；
2. **Navicat 11**：hex → Blowfish（密钥为 `SHA1("3DC5CA39")`，IV 为该密钥下
   `FF×8` 的 ECB 加密），按原实现的链规则解密（链接值吸收密文），去除尾部
   NUL 填充。

与原实现的差异（修正）：原工具把 Navicat 12+ 的密文**不经 base64 解码**直接
喂给 AES（`FromString`），多数字符串长度不是 16 的倍数，解密必然失败。插件按
Navicat 实际存储格式先 base64 解码，解不开再回落 Navicat 11 方案。

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
