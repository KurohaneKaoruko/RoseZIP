# RoseZIP

高性能 Rust 解压缩工具，内置多线程密码爆破引擎。提供**三种使用方式**：
桌面 GUI（Tauri + React）、终端 TUI（无参数直接进入）、经典 CLI（子命令 + 参数）。

## 功能

- **全格式原生支持（零外部依赖，不调用任何系统命令）**：
  - **ZIP**：自研解析器 + flate2 解压/压缩，含 ZipCrypto 加密写出、UTF-8 文件名（EFS）、空目录保留
  - **7z**：`sevenz-rust` 纯 Rust 解码与**编码**（LZMA/LZMA2 + AES-256-SHA-256），支持加密头（`-mhe=on`）
  - **tar / tar.gz / tar.xz / tar.bz2 / gz / xz / bz2**：完整读+写，`.tar.*` 按整体归档列出与解包
- **加密 ZIP 全支持**：
  - ZipCrypto（传统加密）—— 原生完整支持解压、加密压缩与爆破
  - WinZip AES（AE-1/AE-2，AES-128/192/256）—— 原生完整支持解压与爆破
- **归档编辑**（就地改写，无需解压再打包）：
  - 删除条目（ZIP 原始字节复制，不重压缩；7z/tar 同格式重建）
  - 重命名条目 / 目录（支持中文等 UTF-8 名称）
  - CLI：`rosezip delete`、`rosezip rename OLD=NEW`
  - GUI：右键条目 → 解压所选 / 复制路径 / 重命名 / 删除
- **时间戳保留**：解压 ZIP 时恢复修改时间（DOS 时间）
- **多线程密码爆破**：暴力破解（可配置字符集与长度）+ 字典攻击
- **7z 密码攻击**：进程内逐候选解码验证（~30ms/次），无需系统 7z
- **性能**：4 线程下 ZipCrypto 约 **17–20M 密码/秒**（见下方数据）

## 三种前端

| 前端 | 启动方式 | 技术栈 |
|---|---|---|
| 桌面 GUI | `cargo run -p rosezip-app --release` 或 `npm run tauri dev`（在 `app/` 下） | Tauri 2 + React 18 + Vite |
| 终端 TUI | `rosezip`（无参数） | 零依赖 raw-mode（termios） |
| 经典 CLI | `rosezip <子命令> …` | clap 4 |

三者共用同一引擎库 `crates/core`（解析、密码学、爆破、任务管理）。

## 编译

```bash
# CLI + TUI + 引擎
cargo build --release

# 桌面 GUI（需要 WebKit2GTK-4.1 / GTK3 开发库；前端已预构建到 app/dist）
cargo build --release -p rosezip-app
./target/release/rosezip-app

# 修改前端后重新构建 GUI
cd app && npm install && npm run build && cargo build --release -p rosezip-app

# 开发模式（热重载）
cd app && npm run tauri dev
```

## CLI 用法

```bash
# 查看归档内容（* 标记加密条目）
rosezip list archive.zip

# 查看加密类型（ZipCrypto vs WinZip AES）
rosezip check archive.zip

# 解压（原生 ZIP 路径，含加密 ZIP）
rosezip extract archive.zip -o out_dir -p 密码

# 创建 ZIP（level 0-9）
rosezip compress 文件或目录 -o out.zip
rosezip compress dir -o enc.zip -p 密码     # 原生 ZipCrypto 加密，unzip/7z 均可解

# 其他格式（-F 或按 -o 扩展名自动推断）
rosezip compress dir -o out.7z -p 密码      # 7z LZMA2 + AES-256 + 加密头
rosezip compress dir -o out.tar.gz          # tar.gz / tar.xz / tar.bz2 / tar 同理
rosezip compress big.bin -F xz -o big.xz    # 单流压缩

# 归档编辑（就地改写）
rosezip delete archive.zip dir/             # 删除整个目录（含条目）
rosezip delete archive.zip a.txt b.txt
rosezip rename archive.zip 旧名.txt=新名.txt

# 完整性测试（解码全部条目并校验 CRC，不写盘）
rosezip test archive.zip -p 密码            # 密码可省略（无加密时）

# 爆破 ZipCrypto：小写+数字，1~6 位
rosezip crack archive.zip -c lower+digits -n 1 -x 6

# 字典攻击（支持 AES 与 7z 格式）
rosezip crack archive.zip -d wordlist.txt
rosezip crack archive.7z -d wordlist.txt

# 基准测试
rosezip bench
```

### TUI（无参数启动）

`rosezip` 直接回车进入交互界面：方向键选功能、回车确认、Esc/q 退出，
支持列表 / 解压 / 压缩 / 爆破（实时进度 + 任意时刻取消）/ 基准测试。
在非 TTY 环境（如管道）下会报错退出，属预期行为。

### 字符集写法

| 写法 | 含义 |
|---|---|
| `lower` / `upper` / `digits` / `symbols` | 基础集合 |
| `lower+digits` | 组合（36 个字符） |
| `abc123` | 任意字面字符集 |
| `all` | 全部可打印 ASCII 符号 |

## 性能实测（4 核 AMD Ryzen R2314）

| 目标 | 模式 | 结果 |
|---|---|---|
| ZipCrypto 6 位 `k9m2x7`（lower+digits，21.7 亿空间） | 暴力 | **23.7s**（20M/s） |
| ZipCrypto 6 位 `x7k2m9` | 暴力 | **85s**（17M/s） |
| WinZip AES-256 `mem1` | 字典 | 瞬时（PBKDF2×1000） |
| 7z AES-256 `7zpass`（含加密头） | 字典 | 瞬时（AES 密钥派生 ~30ms/候选） |

优化要点：

1. **前缀密钥状态缓存**：候选生成按「前缀 + 末字符」组织，同一前缀下
   扫描全部末字符只需 1 次密钥初始化，吞吐提升约 2 倍
2. **12 字节头快速校验**：错误密码平均 12 字节即排除（1/256 误报率
   再由完整解密+inflate+CRC 确认）
3. **无锁热循环**：静态分块 + relaxed 原子计数，无跨核共享可变状态
4. **mmap 字典**：按换行切块给各线程，保持内存局部性

## 密码学实现（纯 Rust，零依赖）

- CRC-32（表驱动）
- ZipCrypto 流密码（PKWARE 规范，密钥随明文演进）
- SHA-1 / HMAC-SHA1 / PBKDF2（WinZip AES 密钥派生）
- AES-128/192/256 前向密码 + CTR 模式（兼容 WinZip 大端与 7z 小端 counter）

整个代码库**不调用任何外部进程**（`zip`/`7z`/`unzip` 均不需要）；所有格式解码、
加密、爆破都在进程内完成，适合沙箱与无系统工具的环境运行。

## 架构

```
Cargo.toml          workspace（core / cli / app）
crates/core/        引擎库（被三种前端共用）
├── archive.rs      ZIP 中央目录解析、格式探测、7z/tar/gz/xz/bz2 原生解码
├── zipcrypt.rs     ZipCrypto / WinZip AES / SHA-1 / AES / 校验器
├── crack.rs        多线程爆破引擎（暴力 + 字典）+ 可轮询后台任务
├── ops.rs          高层操作（list/extract/compress/破解准备）
├── charset.rs      字符集与候选生成
└── progress.rs     终端进度条
crates/cli/         终端版（clap 子命令 + 无参数 TUI）
app/                桌面版
├── ui/             React 18 前端源码（Vite 构建 → dist/）
└── src-tauri/      Tauri 2 后端（IPC 命令 + 破解任务管理）
```

`rosezip test` 会对 ZIP 逐条目解压校验 CRC；7z 走全量解码校验；
tar/gz/xz/bz2 走完整解包探测。测试失败以非零退出码结束，可直接用于 CI。

### GUI 与引擎的并发模型

GUI 通过 `crack_start` 启动后台爆破任务（`crack::spawn_job`），
前端每 180ms 轮询 `crack_status` 拿进度快照（已尝试/速度/是否找到），
`crack_cancel` 置原子标志位让工作线程在下一个候选处退出。
全程无阻塞 IPC，窗口保持流畅。

## 法律提示

仅用于恢复自己拥有的文件的密码。未经授权破解他人文件在大多数司法
辖区属于违法行为。

## 开发

```bash
# 调试构建（CLI + TUI + 引擎）
cargo build

# 运行全部单元测试与集成测试（无需外部测试数据，自动生成临时归档）
cargo test

# 本地验证 CLI
./target/debug/rosezip list some.zip
./target/debug/rosezip test some.zip
```

代码结构约定：

- 引擎（`crates/core`）不含任何 UI 代码；CLI/TUI/GUI 只是薄封装
- ZIP 写出、就地编辑（delete/rename）均为手写字节级实现，
  改动时请运行 `cargo test -p rosezip-core` 覆盖的 round-trip 用例
- 集成测试在 `crates/core/tests/edit_test.rs`，自包含（临时目录 + 自产归档）

## 许可证

本项目基于 **GPL-3.0-only** 发布（见 [LICENSE](LICENSE)）。
这意味着：你可以自由使用、修改和再分发本项目，但基于它的衍生作品
同样必须以 GPL-3.0 开源。
