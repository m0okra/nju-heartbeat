#!/usr/bin/env python3
"""
nju-heartbeat.py — 南京大学校园网心跳登录守护程序

单文件 Python 版，复刻 Go 原版 nju-heartbeat。
零第三方依赖，仅使用 Python 标准库。

用法:
  python nju-heartbeat.py            # 默认每 120 秒检测一次
  python nju-heartbeat.py -t 60      # 每 60 秒检测一次
  python nju-heartbeat.py -s         # 静默模式：心跳连通时不打印日志
  python nju-heartbeat.py -a         # 持续模式：达到失败上限不退出，继续下一轮
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

# ============================================================================
# 常量
# ============================================================================

TOKEN_FILE = "EncryptedToken"
LOGIN_URL = "https://p.nju.edu.cn/api/portal/v1/login"
CHECK_HOST = "www.baidu.com"
CHECK_URL = "http://www.baidu.com/"
DEFAULT_INTERVAL_SEC = 120
MAX_DNS_FAIL = 3
MAX_HTTP_FAIL = 3
MAX_LOGIN_CHECK = 3
LOGIN_CHECK_INTERVAL = 5  # 秒

SALT_LEN = 16
IV_LEN = 12
AUTH_TAG_LEN = 16
PBKDF2_ITER = 100000
KEY_LEN = 32

# ============================================================================
# 纯 Python AES-256 实现
# ============================================================================


# ---- AES S-box 及逆 S-box ----
_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a):
    """GF(2^8) 下的 x·a (乘以 x 即左移 1 位，溢出时异或 0x1B)。"""
    return ((a << 1) ^ 0x11B) & 0xFF if (a & 0x80) else (a << 1)


def _gf_mul(a, b):
    """GF(2^8) 乘法。"""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _sub_word(w):
    """对 4 字节字应用 S-box。"""
    return tuple(_SBOX[b] for b in w)


def _rot_word(w):
    """循环左移 1 字节。"""
    return w[1:] + w[:1]


def _key_expansion(key: bytes) -> list:
    """AES-256 密钥扩展，返回 15 轮子密钥 (每轮 16 字节)。"""
    assert len(key) == 32
    # 初始 8 个字 (32 字节)
    w = list(struct.unpack(">8I", key))
    for i in range(8, 60):  # AES-256: 60 个字
        temp = w[i - 1]
        if i % 8 == 0:
            temp_rot = _rot_word(struct.pack(">I", temp))
            temp_sbox = _sub_word(tuple(temp_rot))
            temp = struct.unpack(">I", bytes(temp_sbox))[0] ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            temp_sbox = _sub_word(struct.pack(">I", temp))
            temp = struct.unpack(">I", bytes(temp_sbox))[0]
        w.append(w[i - 8] ^ temp)
    # 转为 15 轮子密钥 (round 0-14)，每个 16 字节
    return [struct.pack(">4I", *w[r * 4: r * 4 + 4]) for r in range(15)]


def _sub_bytes(state: bytearray):
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _shift_rows(state: bytearray):
    # 状态矩阵按列存储: [0,4,8,12] 为第0行
    # 第0行不移位, 第1行左移1, 第2行左移2, 第3行左移3
    # 实际访问: state[r + 4*c]
    t = [state[i] for i in range(16)]
    state[1] = t[5]
    state[5] = t[9]
    state[9] = t[13]
    state[13] = t[1]
    state[2] = t[10]
    state[6] = t[14]
    state[10] = t[2]
    state[14] = t[6]
    state[3] = t[15]
    state[7] = t[3]
    state[11] = t[7]
    state[15] = t[11]


def _mix_columns(state: bytearray):
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i]     = _gf_mul(2, a0) ^ _gf_mul(3, a1) ^ a2 ^ a3
        state[i + 1] = a0 ^ _gf_mul(2, a1) ^ _gf_mul(3, a2) ^ a3
        state[i + 2] = a0 ^ a1 ^ _gf_mul(2, a2) ^ _gf_mul(3, a3)
        state[i + 3] = _gf_mul(3, a0) ^ a1 ^ a2 ^ _gf_mul(2, a3)


def _add_round_key(state: bytearray, rk: bytes):
    for i in range(16):
        state[i] ^= rk[i]


def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """AES-256 单块加密 (16 字节)。"""
    assert len(plaintext) == 16
    assert len(key) == 32

    round_keys = _key_expansion(key)
    state = bytearray(plaintext)

    _add_round_key(state, round_keys[0])

    for r in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])

    # 最后一轮无 MixColumns
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[14])

    return bytes(state)


# ============================================================================
# 纯 Python GCM 模式 (AES-256-GCM)
# ============================================================================


def _ghash_mult(x: bytes, y: bytes) -> bytes:
    """GF(2^128) 乘法，不可约多项式 x^128 + x^7 + x^2 + x + 1。"""
    # 将 x, y 转为整数 (大端)
    xi = int.from_bytes(x, byteorder="big")
    yi = int.from_bytes(y, byteorder="big")
    # R = 0xE1 << 120
    R = 0xE1000000000000000000000000000000
    z = 0
    v = yi
    for i in range(128):
        if (xi >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z.to_bytes(16, byteorder="big")


def _ghash(h: bytes, data: bytes) -> bytes:
    """GHASH 认证计算。"""
    y = b"\x00" * 16
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        # y = (y XOR block) * H
        y_block = bytes(a ^ b for a, b in zip(y, block))
        y = _ghash_mult(y_block, h)
    return y


def _gcm_inc32(block: bytes) -> bytes:
    """GCM 递增计数器 (低 32 位 +1)。"""
    counter = int.from_bytes(block[12:16], byteorder="big") + 1
    return block[:12] + counter.to_bytes(4, byteorder="big")


def aes_gcm_encrypt(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> tuple:
    """AES-256-GCM 加密。

    Returns:
        (ciphertext: bytes, auth_tag: bytes)
    """
    assert len(key) == 32
    assert len(nonce) == 12

    # 初始计数器 J0 = nonce || 0x00000001
    j0 = nonce + b"\x00\x00\x00\x01"
    # H = AES_K(0^128)
    h = aes_encrypt_block(b"\x00" * 16, key)

    # 加密: CTR 模式 (从 J0+1 开始)
    ciphertext = b""
    counter = _gcm_inc32(j0)
    offset = 0
    while offset < len(plaintext):
        ekey = aes_encrypt_block(counter, key)
        chunk = plaintext[offset:offset + 16]
        ct_chunk = bytes(a ^ b for a, b in zip(chunk, ekey[:len(chunk)]))
        ciphertext += ct_chunk
        offset += 16
        counter = _gcm_inc32(counter)

    # GHASH
    u = (16 - len(ciphertext) % 16) % 16
    v = (16 - len(aad) % 16) % 16
    ghash_input = aad + b"\x00" * v + ciphertext + b"\x00" * u
    ghash_input += struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)

    s = _ghash(h, ghash_input)

    # auth_tag = GHASH XOR AES_K(J0)
    tag_ekey = aes_encrypt_block(j0, key)
    auth_tag = bytes(a ^ b for a, b in zip(s, tag_ekey))

    return ciphertext, auth_tag


def aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, auth_tag: bytes,
                     aad: bytes = b"") -> bytes:
    """AES-256-GCM 解密并验证。验证失败抛 ValueError。"""
    assert len(key) == 32
    assert len(nonce) == 12
    assert len(auth_tag) == 16

    j0 = nonce + b"\x00\x00\x00\x01"
    h = aes_encrypt_block(b"\x00" * 16, key)

    # GHASH
    u = (16 - len(ciphertext) % 16) % 16
    v = (16 - len(aad) % 16) % 16
    ghash_input = aad + b"\x00" * v + ciphertext + b"\x00" * u
    ghash_input += struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)

    s = _ghash(h, ghash_input)

    # 验证 auth_tag
    tag_ekey = aes_encrypt_block(j0, key)
    expected_tag = bytes(a ^ b for a, b in zip(s, tag_ekey))

    if auth_tag != expected_tag:
        raise ValueError("解密失败，密码错误或数据已损坏")

    # 解密
    plaintext = b""
    counter = _gcm_inc32(j0)
    offset = 0
    while offset < len(ciphertext):
        ekey = aes_encrypt_block(counter, key)
        chunk = ciphertext[offset:offset + 16]
        pt_chunk = bytes(a ^ b for a, b in zip(chunk, ekey[:len(chunk)]))
        plaintext += pt_chunk
        offset += 16
        counter = _gcm_inc32(counter)

    return plaintext


# ============================================================================
# 加解密 — AES-256-GCM + PBKDF2
# ============================================================================


def _derive_key(password: str, salt: bytes) -> bytes:
    """使用 PBKDF2-SHA256 从密码派生出 32 字节 AES-256 密钥。"""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITER, dklen=KEY_LEN
    )


def encrypt_json(source: dict, password: str) -> str:
    """将字典加密为 Base64 字符串。

    格式: salt(16) | nonce(12) | authTag(16) | ciphertext → Base64
    完全兼容 Go crypto/crypto.go 的格式。
    """
    plaintext = json.dumps(
        source, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(IV_LEN)

    key = _derive_key(password, salt)
    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, nonce)

    combined = salt + nonce + auth_tag + ciphertext
    return base64.b64encode(combined).decode("ascii")


def decrypt_json(encrypted_b64: str, password: str) -> dict:
    """解密 Base64 字符串为字典。

    格式兼容 Go crypto/crypto.go。
    """
    combined = base64.b64decode(encrypted_b64.strip())

    if len(combined) < SALT_LEN + IV_LEN + AUTH_TAG_LEN:
        raise ValueError("加密数据过短")

    salt = combined[:SALT_LEN]
    nonce = combined[SALT_LEN: SALT_LEN + IV_LEN]
    auth_tag = combined[SALT_LEN + IV_LEN: SALT_LEN + IV_LEN + AUTH_TAG_LEN]
    ciphertext = combined[SALT_LEN + IV_LEN + AUTH_TAG_LEN:]

    key = _derive_key(password, salt)
    try:
        plaintext = aes_gcm_decrypt(ciphertext, key, nonce, auth_tag)
    except ValueError as e:
        raise ValueError("解密失败，密码错误或数据已损坏") from e

    return json.loads(plaintext.decode("utf-8"))


# ============================================================================
# HTTP 辅助 — 替代 requests 库 (仅标准库 urllib)
# ============================================================================


def _http_get(url: str, timeout: float):
    """发送 HTTP GET 请求，返回 (status_code, body_str)。

    自动跟随重定向；网络层异常抛 ConnectionError。
    """
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except urllib.error.URLError as e:
        raise ConnectionError(f"请求失败: {e.reason}") from e


def _http_post_json(url: str, data: dict, timeout: float):
    """发送 HTTP POST JSON 请求，返回 (status_code, body_str)。"""
    body_bytes = json.dumps(
        data, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    req = urllib.request.Request(url, data=body_bytes, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        raise ConnectionError(f"请求失败: {e.reason}") from e


# ============================================================================
# 凭据管理
# ============================================================================


def load_credentials() -> dict:
    """加载或首次创建加密凭据。

    首次运行自动引导输入学号、密码和本地加密密码，
    加密保存至 EncryptedToken 文件。后续运行直接解密加载。
    """
    if not os.path.exists(TOKEN_FILE):
        print("未检测到加密凭据文件，首次使用请设置。")

        username = input("请输入学号: ").strip()
        password = input("请输入统一认证密码: ").strip()
        local_pwd = input("请设置本地加密密码（用于加密保存凭据）: ").strip()

        creds = {"username": username, "password": password}

        try:
            encrypted = encrypt_json(creds, local_pwd)
        except Exception as e:
            print(f"加密失败: {e}")
            sys.exit(1)

        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(encrypted)

        print(f"凭据已加密保存至 {TOKEN_FILE}")
        return creds
    else:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            data = f.read()

        local_pwd = getpass.getpass("请输入本地加密密码: ")

        try:
            creds = decrypt_json(data, local_pwd)
        except ValueError as e:
            print(f"密码错误或凭据文件损坏: {e}")
            sys.exit(1)

        print("解密成功，凭据已加载。")
        return creds


# ============================================================================
# DNS 检测
# ============================================================================


def check_dns(stamp: str = "") -> bool:
    """检查 DNS 能否解析 www.baidu.com（仅 IPv4）。"""
    try:
        _ = socket.getaddrinfo(CHECK_HOST, 80, socket.AF_INET, socket.SOCK_STREAM)
        return True
    except socket.gaierror as e:
        print(f"{stamp}[DNS] ✗ 解析失败: {e}")
        return False


# ============================================================================
# HTTP 连通性检测
# ============================================================================


def check_http(stamp: str = "", silent: bool = False):
    """请求 http://www.baidu.com/ 检测网络连通状态。

    Args:
        stamp: 行首时间戳前缀（仅本函数打印的首行需要带）。
        silent: 静默模式为 True 时，连通成功不打印日志。

    Returns:
        (connected: bool, reason: str, message: str)

    reason 取值:
        - ""         连通
        - "auth_page"  被拦截到南大认证页面
        - "http_err"   请求异常（超时、连接拒绝等）
        - "unknown"    收到非预期响应
    """
    try:
        status, body = _http_get(CHECK_URL, timeout=5)
    except ConnectionError as e:
        return (False, "http_err", f"请求失败: {e}")

    body_lower = body.lower()

    # 成功：收到百度内容
    if "baidu" in body_lower:
        if not silent:
            print(f"{stamp}[HTTP] ✓ 状态 {status}，收到百度响应，网络已连通")
        return (True, "", "")

    # 南大认证页面
    if "p.nju.edu.cn" in body and "authentication is required" in body_lower:
        print(f"{stamp}[HTTP] ✗ 状态 {status}，被拦截到南大统一认证页面")
        print(f"        内容: {_truncate(body, 200)}")
        return (False, "auth_page", "")

    # 其他未知情况
    msg = f"状态码 {status}，响应体: {_truncate(body, 300)}"
    return (False, "unknown", msg)


def _truncate(text: str, max_len: int) -> str:
    """截断字符串到指定长度（按字符计数）。"""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


# ============================================================================
# 登录认证
# ============================================================================


def try_login(creds: dict):
    """向南大 Portal 发送登录请求。

    Returns:
        (status_code: int, response_body: str)
    """
    payload = {
        "username": creds["username"],
        "password": creds["password"],
        "domain": "default",
    }

    try:
        status, body = _http_post_json(LOGIN_URL, payload, timeout=10)
    except ConnectionError as e:
        return (0, f"登录请求失败: {e}")

    return (status, body)


def try_login_with_retry(creds: dict, silent: bool = False, always: bool = False):
    """检测到认证页面 -> 登录 -> 重检连通性，失败则退出（持续模式仅返回不退出）。"""
    print("[main] 检测到认证页面，正在尝试登录...")
    status, resp_body = try_login(creds)

    if status != 200:
        print(f"[登录] ✗ HTTP {status}，登录失败")
        print(f"        响应体:\n{mask_sensitive_json(resp_body)}")
        if always:
            print("[main] 持续模式已开启，不退出，等待下一轮执行。")
            return
        sys.exit(1)

    print(f"[登录] ✓ HTTP {status}，登录请求成功")
    print(f"        响应:\n{mask_sensitive_json(resp_body)}")

    # 登录后多次重检测网络
    for i in range(MAX_LOGIN_CHECK):
        print(f"[main] 登录后重检测网络 ({i + 1}/{MAX_LOGIN_CHECK})...")
        time.sleep(LOGIN_CHECK_INTERVAL)

        connected, _reason, _msg = check_http(silent=silent)
        if connected:
            print("[main] ✓ 登录成功，网络已连通。")
            return

        print("[main] 重检未连通")

    print("[main] 登录后多次重试仍未连通，可能余额不足或需其他认证。")
    if always:
        print("[main] 持续模式已开启，不退出，等待下一轮执行。")
        return
    sys.exit(1)


# ============================================================================
# JSON 脱敏处理
# ============================================================================

_SENSITIVE_FIELDS = {
    "acctsessionid",
    "mac",
    "fullname",
    "username",
    "user_ipv4",
    "user_ipv6",
}


def mask_sensitive_json(raw: str) -> str:
    """将 JSON 响应中的敏感字段做脱敏处理。

    递归遍历 JSON 树，对已知敏感 key 进行掩码。
    非 JSON 字符串原样返回。
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw  # 非 JSON 则原样返回

    data = _walk_mask(data)
    return json.dumps(data, indent=2, ensure_ascii=False)


def _walk_mask(v):
    """递归遍历 JSON 树。"""
    if isinstance(v, dict):
        return {k: _mask_field(k, _walk_mask(sub)) for k, sub in v.items()}
    elif isinstance(v, list):
        return [_walk_mask(item) for item in v]
    else:
        return v


def _mask_field(key: str, v):
    """根据字段名返回脱敏后的值。"""
    if key not in _SENSITIVE_FIELDS:
        return v

    if key == "acctsessionid":
        return "*****"

    if key == "mac":
        if isinstance(v, str) and len(v) > 5:
            return v[:5] + ":**:**:**:**"
        return "**:**:**:**:**:**"

    if key == "fullname":
        if isinstance(v, str) and len(v) > 0:
            return v[0] + "**"
        return "**"

    if key == "username":
        if isinstance(v, str) and len(v) > 3:
            return v[:3] + "*****"
        return "*****"

    if key == "user_ipv4":
        if isinstance(v, (int, float)):
            n = int(v)
            a = (n >> 24) & 0xFF
            b = (n >> 16) & 0xFF
            return f"{a}.{b}.***.***"
        if isinstance(v, str):
            parts = v.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.***.***"
        return v

    if key == "user_ipv6":
        return "*****"

    return v


# ============================================================================
# 监控主循环
# ============================================================================


def monitor(creds: dict, interval: int, silent: bool = False, always: bool = False):
    """主监控循环：DNS 检测 → HTTP 检测 → 发现认证页自动登录。

    Args:
        silent: 静默模式，心跳连通成功时不打印日志（也不打印时间戳）。
        always: 持续模式，三个失败计数器达到上限时不退出，重置后继续下一轮。
    """
    dns_fail_count = 0
    http_fail_count = 0

    print(f"\n开始网络监控，每 {interval} 秒检查一次...")

    next_tick = time.monotonic()

    def wait_next_tick():
        nonlocal next_tick
        next_tick += interval
        remaining = next_tick - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)

    while True:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S") + " "

        # ---- 1. DNS ----
        dns_ok = check_dns(stamp=stamp)

        if not dns_ok:
            dns_fail_count += 1
            print(
                f"{stamp}[main] DNS 解析失败 ({dns_fail_count}/{MAX_DNS_FAIL})，"
                f"物理网络可能断开"
            )
            if dns_fail_count >= MAX_DNS_FAIL:
                if always:
                    print(f"{stamp}[main] DNS 连续失败次数达到上限，重置计数器继续下一轮。")
                    dns_fail_count = 0
                else:
                    print(f"{stamp}[main] DNS 连续失败次数达到上限，退出程序。")
                    sys.exit(1)
            wait_next_tick()
            continue

        # DNS 成功，重置连续失败计数器
        dns_fail_count = 0

        # ---- 2. HTTP ----
        connected, reason, message = check_http(stamp=stamp, silent=silent)

        if connected:
            # 已连通，重置 HTTP 失败计数器
            http_fail_count = 0
            wait_next_tick()
            continue

        # ---- 3. 未连通，根据原因处理 ----
        if reason == "auth_page":
            http_fail_count = 0
            try_login_with_retry(creds, silent=silent, always=always)
        else:  # "unknown", "http_err"
            http_fail_count += 1
            print(
                f"{stamp}[main] HTTP 检测异常 ({http_fail_count}/{MAX_HTTP_FAIL}): "
                f"{message}"
            )
            if http_fail_count >= MAX_HTTP_FAIL:
                if always:
                    print(f"{stamp}[main] HTTP 连续失败 {MAX_HTTP_FAIL} 次，重置计数器继续下一轮。")
                    http_fail_count = 0
                else:
                    print(f"{stamp}[main] HTTP 连续失败 {MAX_HTTP_FAIL} 次，退出程序。")
                    sys.exit(1)

        wait_next_tick()


# ============================================================================
# main
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="南京大学校园网心跳登录守护程序"
    )
    parser.add_argument(
        "-t",
        type=int,
        default=DEFAULT_INTERVAL_SEC,
        metavar="秒数",
        help=f"心跳检测间隔（秒），默认 {DEFAULT_INTERVAL_SEC}",
    )
    parser.add_argument(
        "-s", "--silent",
        action="store_true",
        help="静默模式：心跳连通成功时不打印日志（也不打印时间戳）",
    )
    parser.add_argument(
        "-a", "--always",
        action="store_true",
        help="持续模式：三个失败计数器达到上限时不退出，重置后继续下一轮",
    )
    args = parser.parse_args()

    creds = load_credentials()
    monitor(creds, args.t, silent=args.silent, always=args.always)


if __name__ == "__main__":
    main()
