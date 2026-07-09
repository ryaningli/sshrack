# sshrack

> 终端原生的远程服务器管理工具。在系统 `ssh` / `scp` / `sftp` 之上叠加配置与凭据层，附带交互式 TUI 与可脚本化、非交互的 CLI。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust: 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/tools/install)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](#-支持平台)
[![Stage](https://img.shields.io/badge/stage-Alpha%20%7C%20active%20development-9cf.svg)](#-路线图)

[English](README.md) | **简体中文**

## ✨ 特性

- **配置 + 凭据层** —— 主机与凭据集中在一个 TOML 文件。一份凭据可被多个主机复用，改名或更新一处即处处生效，无需重复填写。优先使用密钥；密码作为兜底。
- **三种存储模式** —— 密码静态存储可选 **OS keyring**（默认）、加密 **vault**（主密码保护）或 **plaintext**（`0600`）。随时可切换；`store use` 一键迁移全部密钥。
- **非交互 CLI** —— 每条命令都可脚本化：`sshrack web1 df -h`、`sshrack scp ./app.tar web1:/tmp/`、`sshrack --format json host ls`。绝不交互提问；缺失输入即报错，而非发问。
- **交互式 TUI** —— ratatui 外壳，含 Hosts / Credentials / Settings 三标签、模糊过滤、frecency 排序列表与完整的添加/编辑向导。裸 `sshrack` 即打开 TUI。
- **SSH · SCP · SFTP** —— 驱动系统自带的 OpenSSH 二进制（**不**重新实现 SSH）。`connect` 开 shell、`scp` 脚本化传文件、`sftp` 开双面板传输屏。
- **天然安全** —— 密码绝不进 argv / `ps`，也绝不记入日志、打印或写进错误信息。主动式主机密钥预检；拒绝静默的 `accept-new` 信任。
- **Frecency 排序** —— zoxide 式打分把你最常连的主机排到前面。使用记录在**连接之前**就落盘，连接卡死也不会丢。

> sshrack 正在积极开发中（Alpha）。CLI、TUI 与 SFTP 传输屏均已可用，但仍可能有粗糙之处。

## 📦 安装

sshrack 尚处预发布阶段，目前请从源码构建。打标签的发布版会随后提供预编译二进制。

### 从源码构建

前置依赖：

- [Rust](https://www.rust-lang.org/tools/install) 工具链（MSRV **1.88+**，edition 2024）
- `PATH` 中可用的系统 `ssh`、`scp`、`sftp`（OpenSSH）

```bash
git clone https://github.com/ryaningli/sshrack.git
cd sshrack
cargo build --release
# 二进制位于 target/release/sshrack（请加入你的 PATH）
```

## 🚀 使用

### CLI（非交互）

```bash
sshrack web1 df -h                       # 连接并跑一次性命令
sshrack ssh web1                         # 交互式远程 shell
sshrack scp ./app.tar web1:/tmp/         # 脚本化文件传输
sshrack sftp web1                        # 双面板传输屏

sshrack host add web1 --host 10.0.0.4 --user deploy --identity ~/.ssh/id_ed25519
sshrack host ls --sort frecency          # 列出主机，按 frecency 排序
sshrack cred add deploy --user deploy --identity ~/.ssh/id_ed25519
sshrack --format json host ls            # 供脚本消费的 JSON 输出
```

单次连接覆盖项（`-l`/`-p`/`-i`/`-c`/`--ad-hoc`/`--accept-new`）会叠加在已解析的配置之上，仅对本次连接生效。

### TUI（交互）

```bash
sshrack                                  # 裸调用即打开 TUI
```

| 按键 | 动作 |
| --- | --- |
| `Tab` / `Shift-Tab` | 切换标签（Hosts / Credentials / Settings） |
| 输入字符 | 过滤当前面板（模糊匹配） |
| `↑`/`↓` | 移动选择 |
| `Enter` | Hosts：连接 · Credentials：编辑 · Settings：编辑存储模式 |
| `^a` / `^e` / `^d` | 添加 / 编辑 / 删除（删除会弹确认） |
| `F1` / `Esc` / `^c` | 帮助 / 清除或关闭 / 取消或退出 |

在主机上按 `Ctrl-T` 打开 SFTP 传输屏（`Tab` 切换面板/方向，`Space` 标记，`^s` 入队，`^Q` 管理队列）。

## ⚙️ 配置

| 文件 | 位置 | 用途 |
| --- | --- | --- |
| `config.toml` | `~/.config/sshrack/config.toml` | 存储元信息 + 主机 + 凭据（可移植；vault 模式下密钥内联加密） |
| `frecency.toml` | `~/.local/share/sshrack/frecency.toml` | 使用状态（ULID → 分数、last_used）；机器本地，不跨机同步 |

存储模式与完整磁盘布局见 [`docs/architecture.md`](docs/architecture.md)。

## 💻 支持平台

| 平台 | 状态 |
| --- | --- |
| Linux | ✅ 支持（主平台） |
| macOS | ✅ 支持（路径遵循 `directories` crate 约定） |
| Windows | ⚪ 跨平台就绪，暂未投入——平台差异已用 `cfg(target_os)` 隔离，后续落地无需重构 |

## 🛠️ 开发

```bash
cargo build --workspace                  # 构建 core + sshrack 二进制
cargo run -- --help                      # CLI 帮助；裸 `cargo run -q --` 打开 TUI
cargo fmt                                # 格式化
cargo clippy --workspace --all-targets -- -D warnings   # lint（警告视为错误）
cargo test --workspace                   # 跑全部测试
```

每次提交前的质量门禁：`cargo fmt` 通过、clippy 通过、测试通过。

CI 在 pty 下跑测试套件（`script -qec "cargo test --workspace" /dev/null`），因为部分 TUI 测试会构建真实的终端 backend。完整架构、路由规则与约束见 [`CLAUDE.md`](CLAUDE.md)。

## 🧱 架构

sshrack 在单个二进制内采用 **严格的后端/前端分离**：

```
sshrack-core（纯后端，零 UI 依赖）              ─▶  sshrack 二进制（前端）
  config · credential · secret · connect            ├─ cli/   非交互，绝不提问
  hostkey · frecency · askpass · error              └─ tui/   交互式 ratatui 外壳
   │                                                    │
   └─ 副作用通过 trait 注入                               └─ 注入 crossterm 实现
     (SecretBackend, PassphraseProvider, host-key confirm)
                              │
                              ▼
                  系统 ssh / scp / sftp  （继承 stdio，无 PTY 泵）
```

- **`sshrack-core` 零 UI** —— 其 `Cargo.toml` 绝不引入 `ratatui` / `crossterm` / `nucleo-matcher` / `console`。引入即按设计编译失败。
- **绝不重新实现 SSH** —— spawn 并驱动系统 OpenSSH 二进制；不引入任何 SSH 协议库。
- **二进制自身兼作 `SSH_ASKPASS` 助手** —— `main.rs` 依据 `SSHRACK_ASKPASS_FILE` / `SSHRACK_KEYRING_KEY` 分派到 askpass 角色。

## 🔐 安全

- 密码绝不进 argv / `ps`，也绝不记入日志、打印或写进错误信息；内存中的密钥用完即清。
- vault 以 Argon2id + XChaCha20-Poly1305 内联加密密钥；OS keyring 则把密钥放在配置文件之外。
- 主动式主机密钥预检：新密钥确认一次；变更的密钥一律拒绝。
- plaintext/vault 模式把密码暂存于 `0600` 临时文件，用完即删；粘贴（内联）的身份密钥在退出或 `Ctrl-C` / `SIGTERM` 时清掉。

## 🗺️ 路线图

sshrack 正在分步构建。

- ✅ 核心 config/credential/secret 模型 + CLI + TUI 外壳。
- ✅ SFTP 双面板传输屏（ControlMaster + 系统 `sftp`）。
- ✅ 内联（粘贴的）身份密钥，覆盖全部存储模式。
- 🔜 Windows 支持（已用 `cfg(target_os)` 隔离，无需重构）。
- 🔜 打标签发布，提供预编译二进制。

## 📚 文档

- [`docs/architecture.md`](docs/architecture.md) —— workspace、身份/配置模型、磁盘布局、进程边界
- [`docs/tui.md`](docs/tui.md) —— TUI 结构设计（外壳 / 标签 / 浮层 / 向导）
- [`docs/sftp.md`](docs/sftp.md) —— SFTP 传输设计
- [`docs/dependency-policy.md`](docs/dependency-policy.md) —— 依赖规则 + 禁用依赖清单
- [`docs/migration.md`](docs/migration.md) · [`docs/release.md`](docs/release.md) —— 迁移说明 + 发布手册

## 🤝 贡献

欢迎贡献。改动前请先阅读 [`CLAUDE.md`](CLAUDE.md) —— 它涵盖了架构、路由规则、代码风格，以及每次改动必须通过的质量门禁。较大改动建议先开 issue 讨论方向。

## 📄 许可证

[MIT](LICENSE) © ryaningli
