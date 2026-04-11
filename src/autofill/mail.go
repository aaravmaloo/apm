package autofill

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	src "github.com/aaravmaloo/apm/src"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const mailProviderGmail = "gmail"

var otpCodeRegex = regexp.MustCompile(`\b\d{4,8}\b`)

type MailConfig struct {
	Provider     string          `json:"provider"`
	EmailAddress string          `json:"email_address,omitempty"`
	TokenJSON    json.RawMessage `json:"token_json,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type MailOTPResult struct {
	MessageID  string    `json:"message_id,omitempty"`
	Code       string    `json:"code"`
	From       string    `json:"from,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Snippet    string    `json:"snippet,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Score      int       `json:"score,omitempty"`
}

func SetupGmail(ctx context.Context) (*MailConfig, error) {
	config, err := google.ConfigFromJSON(src.GetDefaultCreds(), gmail.GmailReadonlyScope)
	if err != nil {
		return nil, err
	}
	config.RedirectURL = "http://localhost:8080"

	token, err := performGoogleOAuthFlow(ctx, config)
	if err != nil {
		return nil, err
	}

	svc, err := gmail.NewService(ctx, option.WithHTTPClient(config.Client(ctx, token)))
	if err != nil {
		return nil, err
	}
	profile, err := svc.Users.GetProfile("me").Do()
	if err != nil {
		return nil, err
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	cfg := &MailConfig{
		Provider:     mailProviderGmail,
		EmailAddress: strings.TrimSpace(profile.EmailAddress),
		TokenJSON:    tokenJSON,
		UpdatedAt:    time.Now().UTC(),
	}
	if err := saveMailConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func MailConfigured() bool {
	cfg, err := loadMailConfig()
	return err == nil && cfg != nil && strings.EqualFold(cfg.Provider, mailProviderGmail) && len(cfg.TokenJSON) > 0
}

func DisconnectGmail() error {
	path, err := mailConfigFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func LookupGmailOTP(ctx context.Context, req RequestContext, consumed map[string]time.Time) ([]MailOTPResult, error) {
	cfg, err := loadMailConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil || !strings.EqualFold(cfg.Provider, mailProviderGmail) || len(cfg.TokenJSON) == 0 {
		return nil, errors.New("gmail is not configured")
	}

	config, err := google.ConfigFromJSON(src.GetDefaultCreds(), gmail.GmailReadonlyScope)
	if err != nil {
		return nil, err
	}

	var token oauth2.Token
	if err := json.Unmarshal(cfg.TokenJSON, &token); err != nil {
		return nil, err
	}

	tokenSource := config.TokenSource(ctx, &token)
	freshToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}
	if freshJSON, err := json.Marshal(freshToken); err == nil && string(freshJSON) != string(cfg.TokenJSON) {
		cfg.TokenJSON = freshJSON
		cfg.UpdatedAt = time.Now().UTC()
		_ = saveMailConfig(cfg)
	}

	svc, err := gmail.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, err
	}

	list, err := svc.Users.Messages.List("me").Q("newer_than:1d").MaxResults(12).Do()
	if err != nil {
		return nil, err
	}

	candidates := make([]MailOTPResult, 0, len(list.Messages))
	cutoff := time.Now().Add(-8 * time.Minute)
	for _, ref := range list.Messages {
		if mailMessageConsumed(ref.Id, consumed) {
			continue
		}
		msg, err := svc.Users.Messages.Get("me", ref.Id).Format("metadata").MetadataHeaders("From", "Subject").Do()
		if err != nil {
			continue
		}

		receivedAt := time.UnixMilli(msg.InternalDate)
		if receivedAt.Before(cutoff) {
			continue
		}

		subject := gmailHeader(msg.Payload.Headers, "Subject")
		from := gmailHeader(msg.Payload.Headers, "From")
		body := strings.TrimSpace(subject + "\n" + from + "\n" + msg.Snippet)
		code := extractMailOTPCode(body)
		if code == "" {
			continue
		}

		candidate := MailOTPResult{
			MessageID:  ref.Id,
			Code:       code,
			From:       from,
			Subject:    subject,
			Snippet:    msg.Snippet,
			ReceivedAt: receivedAt,
		}
		candidate.Score = scoreMailOTPResult(candidate, req)
		candidates = append(candidates, candidate)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].ReceivedAt.After(candidates[j].ReceivedAt)
	})
	return candidates, nil
}

func loadMailConfig() (*MailConfig, error) {
	path, err := mailConfigFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg MailConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveMailConfig(cfg *MailConfig) error {
	if cfg == nil {
		return errors.New("mail config is required")
	}
	path, err := mailConfigFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func performGoogleOAuthFlow(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {
	authURL := config.AuthCodeURL("apm-autocomplete-mail", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	fmt.Printf("Open this URL to connect Gmail:\n%s\n", authURL)
	openURL(authURL)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			code := strings.TrimSpace(r.URL.Query().Get("code"))
			if code == "" {
				http.Error(w, "Missing code in redirect.", http.StatusBadRequest)
				select {
				case errCh <- errors.New("oauth redirect did not contain a code"):
				default:
				}
				return
			}
			_, _ = w.Write([]byte("Gmail is connected. You can close this window and return to APM."))
			select {
			case codeCh <- code:
			default:
			}
		}),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	var authCode string
	select {
	case authCode = <-codeCh:
	case err := <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, errors.New("gmail setup timed out")
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)

	return config.Exchange(ctx, authCode)
}

func openURL(rawURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	case "darwin":
		cmd = exec.Command("open", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	_ = cmd.Start()
}

func gmailHeader(headers []*gmail.MessagePartHeader, name string) string {
	for _, header := range headers {
		if strings.EqualFold(strings.TrimSpace(header.Name), name) {
			return strings.TrimSpace(header.Value)
		}
	}
	return ""
}

func extractMailOTPCode(text string) string {
	matches := otpCodeRegex.FindAllString(strings.TrimSpace(text), -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func scoreMailOTPResult(candidate MailOTPResult, req RequestContext) int {
	joined := strings.ToLower(strings.TrimSpace(candidate.Subject + " " + candidate.From + " " + candidate.Snippet))
	score := 100
	if containsAny(joined, "otp", "verification", "security code", "one-time", "2fa", "two-factor") {
		score += 180
	}

	for _, token := range mailContextTokens(req) {
		if token == "" {
			continue
		}
		if strings.Contains(joined, token) {
			score += 120
		}
	}

	if inferFieldIntent(req) == fieldIntentMailOTP {
		score += 120
	}

	if age := time.Since(candidate.ReceivedAt); age > 0 {
		score -= int(age / time.Minute)
	}
	return score
}

func mailContextTokens(req RequestContext) []string {
	parts := []string{
		normalizeDomain(req.Domain),
		strings.ToLower(strings.TrimSpace(req.ProcessName)),
		strings.ToLower(strings.TrimSpace(req.WindowTitle)),
	}
	for _, hint := range req.DomainHints {
		parts = append(parts, normalizeDomain(hint))
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		for _, token := range strings.FieldsFunc(part, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-')
		}) {
			token = strings.Trim(token, ".-")
			if len(token) < 3 || isCommonMailToken(token) {
				continue
			}
			if _, exists := seen[token]; exists {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}
	return out
}

func isCommonMailToken(token string) bool {
	switch token {
	case "https", "http", "www", "gmail", "google", "chrome", "safari", "edge", "browser", "sign", "login", "verify", "code":
		return true
	}
	return false
}

func mailMessageConsumed(messageID string, consumed map[string]time.Time) bool {
	if strings.TrimSpace(messageID) == "" || len(consumed) == 0 {
		return false
	}
	expiry, ok := consumed[strings.TrimSpace(messageID)]
	return ok && time.Now().Before(expiry)
}
