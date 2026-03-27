package cmd

import (
	"fmt"

	"github.com/riba2534/feishu-cli/internal/auth"
	"github.com/riba2534/feishu-cli/internal/config"
	"github.com/spf13/cobra"
)

var authTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "输出当前有效的 User Access Token",
	Long: `读取本地登录保存的 User Access Token。

如果 access_token 已过期且 refresh_token 仍有效，会自动刷新并保存新的 token。

示例:
  # 直接输出 token（适合 shell 管道）
  feishu-cli auth token

  # JSON 格式输出（适合插件 / AI Agent）
  feishu-cli auth token -o json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Get()
		token, err := auth.ResolveStoredToken(cfg.AppID, cfg.AppSecret, cfg.BaseURL)
		if err != nil {
			return err
		}

		output, _ := cmd.Flags().GetString("output")
		if output == "json" {
			result := map[string]any{
				"logged_in":     true,
				"access_token":  token.AccessToken,
				"token_type":    token.TokenType,
				"scope":         token.Scope,
				"access_valid":  token.IsAccessTokenValid(),
				"refresh_valid": token.IsRefreshTokenValid(),
			}
			if !token.ExpiresAt.IsZero() {
				result["access_token_expires_at"] = token.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
			}
			if !token.RefreshExpiresAt.IsZero() {
				result["refresh_token_expires_at"] = token.RefreshExpiresAt.Format("2006-01-02T15:04:05Z07:00")
			}
			return printJSON(result)
		}

		fmt.Println(token.AccessToken)
		return nil
	},
}

func init() {
	authCmd.AddCommand(authTokenCmd)
	authTokenCmd.Flags().StringP("output", "o", "", "输出格式（json）")
}
