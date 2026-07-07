package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	saltLen    = 16
	ivLen      = 12
	authTagLen = 16
	pbkdf2Iter = 100000
	keyLen     = 32
)

// deriveKey 使用 PBKDF2 从密码派生出 AES-256 密钥
func deriveKey(password string, salt []byte) []byte {
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, keyLen)
	if err != nil {
		panic(err)
	}
	return key
}

// marshalNoEscape 将对象序列化为紧凑 JSON，不转义 <, >, &，
// 以匹配 Python json.dumps(ensure_ascii=False, separators=(",", ":")) 的输出。
func marshalNoEscape(source interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(source); err != nil {
		return nil, err
	}
	// json.Encoder.Encode 末尾会自动追加 '\n'，需要去掉以与 Python 行为一致
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// EncryptJSON 将任意可 JSON 序列化的对象用 password 加密，返回 Base64 字符串。
// 格式: salt(16) | iv(12) | authTag(16) | ciphertext → Base64
func EncryptJSON(source interface{}, password string) (string, error) {
	jsonBytes, err := marshalNoEscape(source)
	if err != nil {
		return "", fmt.Errorf("json marshal failed: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt gen failed: %w", err)
	}
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("iv gen failed: %w", err)
	}

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm failed: %w", err)
	}

	sealed := gcm.Seal(nil, iv, jsonBytes, nil)
	ciphertext := sealed[:len(sealed)-authTagLen]
	authTag := sealed[len(sealed)-authTagLen:]

	combined := bytes.NewBuffer(nil)
	combined.Write(salt)
	combined.Write(iv)
	combined.Write(authTag)
	combined.Write(ciphertext)

	return base64.StdEncoding.EncodeToString(combined.Bytes()), nil
}

// DecryptJSON 将 Base64 加密字符串用 password 解密，结果写入 target（应为指针）
func DecryptJSON(encryptedB64 string, password string, target interface{}) error {
	combined, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedB64))
	if err != nil {
		return fmt.Errorf("base64 decode failed: %w", err)
	}
	if len(combined) < saltLen+ivLen+authTagLen {
		return fmt.Errorf("encrypted data too short")
	}

	salt := combined[:saltLen]
	iv := combined[saltLen : saltLen+ivLen]
	authTag := combined[saltLen+ivLen : saltLen+ivLen+authTagLen]
	ciphertext := combined[saltLen+ivLen+authTagLen:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes cipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm failed: %w", err)
	}

	sealed := append(ciphertext, authTag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return fmt.Errorf("解密失败，密码错误或数据已损坏: %w", err)
	}

	if err := json.Unmarshal(plain, target); err != nil {
		return fmt.Errorf("decrypted data is not valid JSON: %w", err)
	}
	return nil
}
