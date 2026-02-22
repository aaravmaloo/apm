package apm

import (
	"context"
	"testing"
)

func TestParseOAuthTokenOrRaw(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{
		{
			name: "raw-token",
			in:   []byte("abc123"),
			want: "abc123",
		},
		{
			name: "trimmed-raw-token",
			in:   []byte("  abc123  "),
			want: "abc123",
		},
		{
			name: "oauth-json",
			in:   []byte(`{"access_token":"oauth-access","token_type":"Bearer"}`),
			want: "oauth-access",
		},
		{
			name:    "empty-token",
			in:      []byte("   "),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOAuthTokenOrRaw(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestGetCloudProviderTokenHandling(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	provider, err := GetCloudProvider("github", ctx, nil, []byte(`{"access_token":"gho_demo"}`), "")
	if err != nil {
		t.Fatalf("GetCloudProvider(github) failed: %v", err)
	}
	gm, ok := provider.(*GitHubManager)
	if !ok {
		t.Fatalf("expected *GitHubManager, got %T", provider)
	}
	if gm.Token != "gho_demo" {
		t.Fatalf("expected parsed github token, got %q", gm.Token)
	}

	provider, err = GetCloudProvider("dropbox", ctx, nil, []byte(`{"access_token":"dbx_demo"}`), "")
	if err != nil {
		t.Fatalf("GetCloudProvider(dropbox) failed: %v", err)
	}
	dm, ok := provider.(*DropboxManager)
	if !ok {
		t.Fatalf("expected *DropboxManager, got %T", provider)
	}
	if dm.Token != "dbx_demo" {
		t.Fatalf("expected parsed dropbox token, got %q", dm.Token)
	}

	if _, err := GetCloudProvider("github", ctx, nil, nil, ""); err == nil {
		t.Fatal("expected error when github token is missing")
	}

	if _, err := GetCloudProvider("unsupported", ctx, nil, nil, ""); err == nil {
		t.Fatal("expected unsupported provider error")
	}
}
