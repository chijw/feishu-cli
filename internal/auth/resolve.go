package auth

import (
	"fmt"
	"os"
)

var refreshAccessTokenFunc = RefreshAccessToken

// logf 输出日志到 stderr，避免污染 stdout 的 JSON 输出
func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// ResolveStoredToken reads the locally stored OAuth token from token.json and
// refreshes it when needed. It only uses the token saved by auth login and
// does not consult flag / env / config static tokens.
func ResolveStoredToken(appID, appSecret, baseURL string) (*TokenStore, error) {
	token, err := LoadToken()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, fmt.Errorf("尚未登录，请先执行: feishu-cli auth login")
	}
	if token.IsAccessTokenValid() {
		return token, nil
	}
	if !token.IsRefreshTokenValid() {
		return nil, fmt.Errorf("User Access Token 已过期（access_token 和 refresh_token 均已失效）。\n" +
			"请重新登录: feishu-cli auth login")
	}
	if appID == "" || appSecret == "" {
		return nil, fmt.Errorf("Access Token 已过期，需要 app_id 和 app_secret 才能自动刷新。\n" +
			"请配置凭证后重试，或重新登录: feishu-cli auth login")
	}
	if baseURL == "" {
		baseURL = "https://open.feishu.cn"
	}

	logf("[自动刷新] Access Token 已过期，正在刷新...")
	newToken, refreshErr := refreshAccessTokenFunc(token.RefreshToken, appID, appSecret, baseURL)
	if refreshErr != nil {
		logf("[自动刷新] 刷新失败: %v", refreshErr)
		return nil, fmt.Errorf("User Access Token 刷新失败，请重新登录: feishu-cli auth login")
	}
	if saveErr := SaveToken(newToken); saveErr != nil {
		logf("[自动刷新] Token 已刷新但保存失败: %v", saveErr)
	} else {
		logf("[自动刷新] 刷新成功，新 Token 有效期至 %s", newToken.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
	return newToken, nil
}

// ResolveUserAccessToken 按优先级链获取 user_access_token，支持自动刷新
//
// 优先级:
//  1. flagValue（--user-access-token 参数）
//  2. FEISHU_USER_ACCESS_TOKEN 环境变量
//  3. token.json（access_token 有效直接返回；过期则用 refresh_token 刷新）
//  4. configValue（config.yaml 静态配置）
//  5. 全部为空 → 返回错误
func ResolveUserAccessToken(flagValue, configValue, appID, appSecret, baseURL string) (string, error) {
	// 1. 命令行参数
	if flagValue != "" {
		return flagValue, nil
	}

	// 2. 环境变量
	if envToken := os.Getenv("FEISHU_USER_ACCESS_TOKEN"); envToken != "" {
		return envToken, nil
	}

	// 3. token.json
	if token, err := ResolveStoredToken(appID, appSecret, baseURL); err == nil && token != nil {
		return token.AccessToken, nil
	}

	// 4. 配置文件
	if configValue != "" {
		return configValue, nil
	}

	// 5. 区分"从未登录"和"登录过期"
	if token, err := LoadToken(); err == nil && token != nil {
		return "", fmt.Errorf("User Access Token 不可用，请重新登录: feishu-cli auth login")
	}
	return "", fmt.Errorf("缺少 User Access Token，请通过以下方式之一提供:\n" +
		"  1. OAuth 登录: feishu-cli auth login\n" +
		"  2. 命令行参数: --user-access-token <token>\n" +
		"  3. 环境变量: export FEISHU_USER_ACCESS_TOKEN=<token>\n" +
		"  4. 配置文件: user_access_token: <token>")
}
