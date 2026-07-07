package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"nju-heartbeat/crypto"
)

const (
	tokenFile          = "EncryptedToken"
	loginURL           = "https://p.nju.edu.cn/api/portal/v1/login"
	checkHost          = "www.baidu.com"
	checkURL           = "http://www.baidu.com/"
	defaultIntervalSec = 120
	maxDNSFail         = 3
	maxHTTPFail        = 3
	maxLoginCheck      = 3
	loginCheckInterval = 5 * time.Second
)

// Credentials 学号和统一认证密码
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

// ============================================================================
// 凭据加载（与原 main.go 一致）
// ============================================================================

func loadCredentials() Credentials {
	var creds Credentials

	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("未检测到加密凭据文件，首次使用请设置。")

		fmt.Print("请输入学号: ")
		line, _ := reader.ReadString('\n')
		creds.Username = strings.TrimSpace(line)

		fmt.Print("请输入统一认证密码: ")
		line, _ = reader.ReadString('\n')
		creds.Password = strings.TrimSpace(line)

		fmt.Print("请设置本地加密密码（用于加密保存凭据）: ")
		line, _ = reader.ReadString('\n')
		localPwd := strings.TrimSpace(line)

		encrypted, err := crypto.EncryptJSON(creds, localPwd)
		if err != nil {
			fmt.Printf("加密失败: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(tokenFile, []byte(encrypted), 0600); err != nil {
			fmt.Printf("写入凭据文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("凭据已加密保存至 %s\n", tokenFile)
	} else {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			fmt.Printf("读取 %s 失败: %v\n", tokenFile, err)
			os.Exit(1)
		}

		fmt.Print("请输入本地加密密码: ")
		pwdBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // ReadPassword 不输出换行
		if err != nil {
			fmt.Printf("读取密码失败: %v\n", err)
			os.Exit(1)
		}
		localPwd := string(pwdBytes)

		if err := crypto.DecryptJSON(string(data), localPwd, &creds); err != nil {
			fmt.Printf("密码错误或凭据文件损坏: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("解密成功，凭据已加载。")
	}
	return creds
}

// ============================================================================
// DNS 检测
// ============================================================================

func checkDNS(stamp string) bool {
	ips, err := net.LookupHost(checkHost)
	if err != nil {
		fmt.Printf("%s[DNS] ✗ 解析失败: %v\n", stamp, err)
		return false
	}
	var v4 []string
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			v4 = append(v4, ip)
		}
	}
	if len(v4) == 0 {
		fmt.Printf("%s[DNS] ✗ 未解析到 IPv4 地址\n", stamp)
		return false
	}
	return true
}

// ============================================================================
// HTTP 连通性检测
// ============================================================================

type checkResult struct {
	connected bool
	reason    string // "auth_page" | "http_err" | "unknown"
	message   string
}

// checkHTTP 检测网络连通状态。
// stamp 为本函数打印首行需要带的时间戳前缀；silent 为静默模式开关，
// 为 true 时连通成功不打印日志。
func checkHTTP(stamp string, silent bool) checkResult {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(checkURL)
	if err != nil {
		return checkResult{false, "http_err", fmt.Sprintf("请求失败: %v", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return checkResult{false, "http_err", fmt.Sprintf("读取响应失败: %v", err)}
	}

	bodyLower := bytes.ToLower(body)

	// 成功：收到百度内容
	if bytes.Contains(bodyLower, []byte("baidu")) {
		if !silent {
			fmt.Printf("%s[HTTP] ✓ 状态 %d，收到百度响应，网络已连通\n", stamp, resp.StatusCode)
		}
		return checkResult{connected: true}
	}

	// 南大认证页面
	if bytes.Contains(body, []byte("p.nju.edu.cn")) &&
		bytes.Contains(bodyLower, []byte("authentication is required")) {
		fmt.Printf("%s[HTTP] ✗ 状态 %d，被拦截到南大统一认证页面\n", stamp, resp.StatusCode)
		fmt.Printf("        内容: %s\n", truncateRunes(body, 200))
		return checkResult{false, "auth_page", ""}
	}

	// 其他未知情况
	msg := fmt.Sprintf("状态码 %d，响应体: %s", resp.StatusCode, truncateRunes(body, 300))
	return checkResult{false, "unknown", msg}
}

// ============================================================================
// 登录认证
// ============================================================================

func tryLogin(creds Credentials) (int, string) {
	reqBody := loginRequest{
		Username: creds.Username,
		Password: creds.Password,
		Domain:   "default",
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Sprintf("序列化登录请求失败: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(loginURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return 0, fmt.Sprintf("登录请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Sprintf("读取响应失败: %v", err)
	}
	return resp.StatusCode, string(body)
}

// tryLoginWithRetry 登录成功后多次重检测网络连通性。
// silent 为静默模式开关；always 为持续模式开关，达到登录重检上限时不退出。
func tryLoginWithRetry(creds Credentials, silent, always bool) {
	fmt.Println("[main] 检测到认证页面，正在尝试登录...")
	status, respBody := tryLogin(creds)
	if status != 200 {
		fmt.Printf("[登录] ✗ HTTP %d，登录失败\n", status)
		fmt.Printf("        响应体:\n%s\n", maskSensitiveJSON(respBody))
		if always {
			fmt.Println("[main] 持续模式已开启，不退出，等待下一轮执行。")
			return
		}
		os.Exit(1)
	}

	fmt.Printf("[登录] ✓ HTTP %d，登录请求成功\n", status)
	fmt.Printf("        响应:\n%s\n", maskSensitiveJSON(respBody))

	// 登录后多次重检测网络
	for i := 0; i < maxLoginCheck; i++ {
		fmt.Printf("[main] 登录后重检测网络 (%d/%d)...\n", i+1, maxLoginCheck)
		time.Sleep(loginCheckInterval)

		result := checkHTTP("", silent)
		if result.connected {
			fmt.Println("[main] ✓ 登录成功，网络已连通。")
			return
		}
		fmt.Printf("[main] 重检未连通\n")
	}

	fmt.Println("[main] 登录后多次重试仍未连通，可能余额不足或需其他认证。")
	if always {
		fmt.Println("[main] 持续模式已开启，不退出，等待下一轮执行。")
		return
	}
	os.Exit(1)
}

// ============================================================================
// 脱敏处理
// ============================================================================

// maskSensitiveJSON 将登录响应的 JSON 中敏感字段做脱敏处理。
func maskSensitiveJSON(raw string) string {
	var data interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return raw // 非 JSON 则原样返回
	}
	data = walkMask(data)
	masked, _ := json.MarshalIndent(data, "", "  ")
	return string(masked)
}

// walkMask 递归遍历 JSON 树，对已知敏感 key 做脱敏。
func walkMask(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, sub := range val {
			val[k] = maskField(k, sub)
		}
		return val
	case []interface{}:
		for i, sub := range val {
			val[i] = walkMask(sub)
		}
		return val
	default:
		return v
	}
}

// maskField 根据字段名返回脱敏后的值。
func maskField(key string, v interface{}) interface{} {
	// 先递归处理子对象（比如 results 本身也是个 map）
	if _, isMap := v.(map[string]interface{}); isMap {
		return walkMask(v)
	}

	switch key {
	case "acctsessionid":
		return "*****"

	case "mac":
		s, ok := v.(string)
		if !ok || s == "" {
			return "**:**:**:**:**:**"
		}
		if len(s) > 5 {
			return s[:5] + ":**:**:**:**"
		}
		return "**:**:**:**:**:**"

	case "fullname":
		s, ok := v.(string)
		if !ok || s == "" {
			return v
		}
		runes := []rune(s)
		if len(runes) > 0 {
			return string(runes[0]) + "**"
		}
		return "**"

	case "username":
		s, ok := v.(string)
		if !ok || s == "" {
			return v
		}
		if len(s) > 3 {
			return s[:3] + "*****"
		}
		return "*****"

	case "user_ipv4":
		if f, ok := v.(float64); ok {
			n := uint32(f)
			ip := net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
			return fmt.Sprintf("%d.%d.***.***", ip[0], ip[1])
		}
		if s, ok := v.(string); ok {
			parts := strings.SplitN(s, ".", 4)
			if len(parts) == 4 {
				return fmt.Sprintf("%s.%s.***.***", parts[0], parts[1])
			}
		}
		return v

	case "user_ipv6":
		s, ok := v.(string)
		if !ok || s == "" {
			return v
		}
		return "*****"

	default:
		return v
	}
}

// ============================================================================
// 工具
// ============================================================================

func truncateRunes(b []byte, maxLen int) string {
	s := string(b)
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// ============================================================================
// 监控主循环
// ============================================================================

func monitor(creds Credentials, interval time.Duration, silent, always bool) {
	dnsFailCount := 0
	httpFailCount := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Printf("\n开始网络监控，每%v检查一次...\n", interval)

	for {
		stamp := time.Now().Format("2006-01-02 15:04:05") + " "

		// ---- 1. DNS ----
		dnsOK := checkDNS(stamp)

		if !dnsOK {
			dnsFailCount++
			fmt.Printf("%s[main] DNS 解析失败 (%d/%d)，物理网络可能断开\n", stamp, dnsFailCount, maxDNSFail)
			if dnsFailCount >= maxDNSFail {
				if always {
					fmt.Printf("%s[main] DNS 连续失败次数达到上限，重置计数器继续下一轮。\n", stamp)
					dnsFailCount = 0
				} else {
					fmt.Printf("%s[main] DNS 连续失败次数达到上限，退出程序。\n", stamp)
					os.Exit(1)
				}
			}
			<-ticker.C
			continue
		}

		// DNS 成功，重置连续失败计数器
		dnsFailCount = 0

		// ---- 2. HTTP ----
		result := checkHTTP(stamp, silent)

		if result.connected {
			// 已连通，重置 HTTP 失败计数器
			httpFailCount = 0
			<-ticker.C
			continue
		}

		// ---- 3. 未连通，根据原因处理 ----
		switch result.reason {
		case "auth_page":
			httpFailCount = 0
			tryLoginWithRetry(creds, silent, always)

		case "unknown", "http_err":
			httpFailCount++
			fmt.Printf("%s[main] HTTP 检测异常 (%d/%d): %s\n", stamp, httpFailCount, maxHTTPFail, result.message)
			if httpFailCount >= maxHTTPFail {
				if always {
					fmt.Printf("%s[main] HTTP 连续失败 %d 次，重置计数器继续下一轮。\n", stamp, maxHTTPFail)
					httpFailCount = 0
				} else {
					fmt.Printf("%s[main] HTTP 连续失败 %d 次，退出程序。\n", stamp, maxHTTPFail)
					os.Exit(1)
				}
			}
		}

		<-ticker.C
	}
}

// ============================================================================
// main
// ============================================================================

func main() {
	intervalSec := flag.Int("t", defaultIntervalSec, "心跳检测间隔（秒）")
	silent := flag.Bool("s", false, "静默模式：心跳连通成功时不打印日志（也不打印时间戳）")
	always := flag.Bool("a", false, "持续模式：三个失败计数器达到上限时不退出，重置后继续下一轮")
	flag.Parse()

	creds := loadCredentials()
	monitor(creds, time.Duration(*intervalSec)*time.Second, *silent, *always)
}
