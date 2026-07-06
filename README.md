# nju-heartbeat

南京大学校园网心跳登录守护程序。自动检测网络连通状态，发现被拦截到统一认证页面时自动凭据登录，保持网络持续在线。

## 目录结构

```
nju-heartbeat/
├── .gitignore             # Git 忽略规则
├── LICENSE
├── EncryptedToken         # 加密存储的凭据文件（自动生成）
├── nju-heartbeat.py       # Python 版（零第三方依赖，仅需 Python 3.6+）
├── nju-heartbeat.exe      # Go 编译产物
└── src/
    ├── main.go            # Go 源码入口
    ├── go.mod
    └── crypto/
        └── crypto.go      # AES-256-GCM + PBKDF2 凭据加解密
```

## 使用方式

项目分为 Python 版（单文件，无依赖）和 Go 版（单可执行文件，无需 Python 环境），两个版本的功能完全相同且登录凭据可以互通。

### Python 版

Python 3.6+ 即可运行，无需安装任何第三方库。

#### 首次使用

```bash
python nju-heartbeat.py
```

按提示输入：
1. **学号**（统一身份认证账号）
2. **统一认证密码**
3. **本地加密密码** — 用于加密保存凭据，每次启动需输入

凭据加密保存在 `EncryptedToken` 文件中。

#### 日常运行

```bash
python nju-heartbeat.py [-t 秒数]
```

- 默认每 **120 秒**检测一次网络连通性
- 可通过 `-t` 参数自定义检测间隔（单位：秒），例如 `-t 60` 为每分钟检测一次

### Go 版

下载 [Release](https://github.com/m0okra/nju-heartbeat/releases) 中的二进制可执行文件或者自行编译。

Go 版的使用方法与 Python 版完全相同。

#### 首次使用

```bash
nju-heartbeat.exe
```

#### 日常运行

```bash
nju-heartbeat.exe [-t 秒数]
```

#### 编译

如果当前系统所需的版本不在 [Release](https://github.com/m0okra/nju-heartbeat/releases) 中，可以从源码自行编译：

- 需要 Go ≥ 1.25
- 在 `src/` 目录下执行：

```bash
go build -o ../nju-heartbeat.exe .
```

产物 `nju-heartbeat.exe` 位于项目根目录。

## 工作原理简述

程序每 N 秒（默认 120）检测一次网络连通性：

1. **DNS 检测** — 解析 `www.baidu.com`，连续 3 次失败则退出
2. **HTTP 检测** — 请求 `http://www.baidu.com/`：
   - 收到百度内容 → 网络已连通，继续等待下一轮
   - 收到南大认证页面（`p.nju.edu.cn` + `Authentication is required`）→ 自动登录
   - 收到异常响应或请求失败 → 计数 +1，连续 3 次失败才退出（容忍网络抖动）

检测到认证页面时自动执行登录，登录后最多重检 3 次（间隔 5 秒），确认网络连通后才认为登录成功。

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-t` | `120` | 心跳检测间隔（秒）|

### 容错机制

- **DNS 连续失败上限**：3 次（应对 DNS 服务器暂时不可用）
- **HTTP 异常连续失败上限**：3 次（应对临时网络抖动）
- **登录后重检次数**：最多 3 次，间隔 5 秒（Portal 认证生效可能延迟）
- 计数器在检测到连通或认证页面成功登录后归零

### 脱敏处理

登录响应的 JSON 输出时自动脱敏敏感字段：

| 字段 | 脱敏方式 |
|---|---|
| `acctsessionid` | 全部替换为 `*****` |
| `mac` | 保留前 5 字符，其余掩码为 `:**:**:**:**` |
| `fullname` | 仅显示姓氏，如 `张**` |
| `username` | 保留前 3 字符，如 `221*****` |
| `user_ipv4` | 仅显示前两段，如 `10.10.***.***` |
| `user_ipv6` | 全部替换为 `*****` |

## 许可证

本项目使用 MIT 许可证。
