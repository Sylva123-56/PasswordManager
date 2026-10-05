# Vaultroom · 本地密码库 MVP

Vaultroom 是一个按《密码管理器_MVP_项目设计文档.md》实现的 Windows 优先、离线本地密码管理器 MVP。

## 已实现

- Tauri 2 + Svelte + TypeScript + Vite 工程骨架
- Rust 端 Argon2id 密钥派生、XChaCha20-Poly1305 AEAD 加密
- 随机 DEK + 主密码包装，版本化 JSON Vault 容器
- 原子保存、Windows 原子替换、最近三份加密备份
- 主密码创建、解锁、锁定、修改和加密 Vault 导出
- 条目增删改查、收藏、搜索、标签和排序
- 操作系统安全随机密码生成器
- Rust 端剪贴板写入、按摘要匹配后清理、锁定时清理
- 5 / 15 / 30 分钟或关闭的空闲自动锁定设置
- 锁定后清理 Rust 会话数据和前端敏感详情状态
- 受控 Tauri IPC；前端不直接读写文件、不实现密码学

## 本地运行

需要 Node.js、npm、Rust、Windows WebView2 和 Tauri 所需的 Windows 构建工具。

    npm install
    npm run tauri dev

仅构建前端：

    npm run build

运行 Rust 核心测试：

    cargo test --manifest-path src-tauri/Cargo.toml

构建 Windows 调试程序：

    npm run tauri -- build --debug

## Vault 格式

默认密码库文件名为 vault.pmvault，由 Rust 放在系统应用数据目录。外层是版本化 JSON：

- kdf：Argon2id 的 salt 和参数
- key_wrap：使用派生 KEK 包装随机 32 字节 DEK
- payload：使用 DEK 加密的 Vault JSON 数据
- nonce 使用 24 字节 XChaCha20-Poly1305 nonce，认证标签包含在 ciphertext 中

磁盘文件不会写入主密码、KEK、DEK 或条目明文。应用日志只记录不包含敏感值的错误类别。

## 安全边界

MVP 不承诺抵御已控制操作系统、键盘记录器或内存取证环境。前端通过原生文件选择器选择其他 Vault 或导出位置，Rust 端仍会校验文件大小、格式和导出扩展名。

当前设计不包含云同步、浏览器扩展、自动填充、在线账号、生物识别、多用户共享或明文 CSV 导出。
