# MobaXterm 凭据分析插件（LPP v2 / SDK 0.2.0）

把 ForensicsTool 的 MobaXterm 提取（`analyzers/extractor/tool/mobaTool.go`）的
**注册表部分**复刻为 LovelyCarve 插件：MobaXterm 把保存的会话密码（`P` 值）和
命名凭据（`C` 值）存在每个用户的 `NTUSER.DAT` 里
（`Software\Mobatek\MobaXterm`），本插件解析并解密这些凭据。原工具的 `.ini`
分支属于文件格式解析，不在本插件范围内。配置单元（REGF 格式）的解析由本仓库
的 `libs/regf.zig` 独立库完成。

## 分析器

| 分析器 | 作用域 | 触发 | 作用 |
|---|---|---|---|
| `mobaevidence` | evidence | auto | 解析检材中**所有** `NTUSER.DAT`（清单 `inputs = ["**/NTUSER.DAT"]`），检材上线后自动运行 |
| `mobafile` | files | manual | 解析用户在文件浏览器中选中的 `.dat` 配置单元 |

## 记录

| 记录类型 | 内容 |
|---|---|
| `mobaxterm.password` | `P` 值：协议（值名首个冒号前）、连接账户与地址（值名其余部分）、**解密后的密码** |
| `mobaxterm.credential` | `C` 值：凭据名（值名）、用户名、**解密后的密码** |

`P`/`C` 子键缺失时该表为空；单个配置单元解析失败只记运行告警。

## 密码解密

复刻 ForensicsTool 的 `decryptMoba`：

- 密钥 = `SHA-512(主密码)` 前 32 字节（AES-256）；未设置主密码时即对空串求
  哈希，与 MobaXterm 默认行为一致；
- IV = 该密钥下 16 个零字节的 AES-256-ECB 加密结果；
- 密文为 base64，模式为 **AES-256-CFB8**（8 位反馈）。`zig-cryptobin` 未提供
  CFB8（其 CFB 为整块反馈），插件在 AES 核心（`std.crypto.core.aes`）上补了
  这一模式的实现。

## 选项

| 选项 | 类型 | 说明 |
|---|---|---|
| `master_password` | text | MobaXterm 主密码；未设置时留空（使用默认密钥派生） |

设置主密码后，密文按该密码派生的密钥解密；解不开的值密码列输出为空（与原
实现一致，不影响其余值）。

## 构建与验证

```sh
zig build test                 # 单元测试（解析核心 + 插件层，含假宿主端到端）
zig build                      # ReleaseSafe 动态库 -> zig-out/lib/mobaxtermanalyzer.dll
zig build schema               # 从库导出 zig-out/schema.json
zig build package              # -> zig-out/<id>-<version>-<platform>.lcpkg
zig build probe                # 开发工具 -> zig-out/bin/probe.exe
```

```sh
# 用真实配置单元核对（libs/regf.zig/testfiles 的 SAM 中没有 MobaXterm 数据）
zig-out/bin/probe.exe ../libs/regf.zig/testfiles/SAM
zig-out/bin/probe.exe --master <主密码> <NTUSER.DAT>

# 真宿主端到端（主密码经环境变量 DRIVE_OPTIONS 传入）
DRIVE_OPTIONS='{"master_password":"<主密码>"}' python scripts/drive.py \
    plugins/target/debug/lc-plugin-host.exe \
    zig-out/lib/mobaxtermanalyzer.dll <NTUSER.DAT> mobafile
```
