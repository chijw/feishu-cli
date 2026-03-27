package auth

import "strings"

// RecommendedLoginScopes is the default set of user OAuth scopes requested by
// feishu-cli. The goal is to cover the generic interactive feature set in one
// authorization step, including docs browsing, wiki navigation, messaging,
// calendar, and task workflows.
var RecommendedLoginScopes = []string{
	"offline_access",
	"search:docs:read",
	"search:message",
	"drive:drive:readonly",
	"drive:drive.search:readonly",
	"drive:drive.metadata:readonly",
	"space:document:retrieve",
	"space:document:delete",
	"docs:document.media:upload",
	"docs:permission.member:create",
	"docs:permission.member:retrieve",
	"wiki:node:read",
	"wiki:wiki:readonly",
	"wiki:space:retrieve",
	"docx:document",
	"docx:document:readonly",
	"calendar:calendar:read",
	"calendar:calendar.event:read",
	"calendar:calendar.event:create",
	"calendar:calendar.event:update",
	"calendar:calendar.event:reply",
	"calendar:calendar.free_busy:read",
	"task:task:read",
	"task:task:write",
	"task:tasklist:read",
	"task:tasklist:write",
	"im:chat",
	"im:message:readonly",
	"im:message",
	"im:message.group_msg:get_as_user",
	"im:chat:read",
	"im:chat.members:read",
	"contact:user.base:readonly",
}

// NormalizeLoginScopes normalizes login scopes:
//   - returns the recommended scope set when no explicit scope is provided
//   - preserves user-provided scopes and always appends offline_access
//   - deduplicates tokens and trims extra whitespace
func NormalizeLoginScopes(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return strings.Join(RecommendedLoginScopes, " ")
	}
	return normalizeScopeTokens(append(strings.Fields(raw), "offline_access"))
}

func normalizeScopeTokens(tokens []string) string {
	ordered := make([]string, 0, len(tokens))
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		ordered = append(ordered, token)
	}
	return strings.Join(ordered, " ")
}
