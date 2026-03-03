package autofill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Client struct {
	addr       string
	token      string
	httpClient *http.Client
}

func NewClientFromState() (*Client, error) {
	state, err := loadDaemonState()
	if err != nil {
		return nil, err
	}
	return &Client{
		addr:  state.Addr,
		token: state.Token,
		httpClient: &http.Client{
			Timeout: 6 * time.Second,
		},
	}, nil
}

func DaemonStateExists() bool {
	path, err := stateFilePath()
	if err != nil {
		return false
	}
	_, statErr := os.Stat(path)
	return statErr == nil
}

func (c *Client) Status(ctx context.Context) (*DaemonStatus, error) {
	var out DaemonStatus
	if err := c.doJSON(ctx, http.MethodGet, "/v1/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Stop(ctx context.Context) error {
	var out SimpleResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/stop", nil, &out); err != nil {
		return err
	}
	if !out.OK {
		if out.Error == "" {
			return errors.New("daemon stop failed")
		}
		return errors.New(out.Error)
	}
	return nil
}

func (c *Client) Unlock(ctx context.Context, req UnlockRequest) error {
	var out SimpleResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/vault/unlock", req, &out); err != nil {
		return err
	}
	if !out.OK {
		if out.Error == "" {
			return errors.New("unlock failed")
		}
		return errors.New(out.Error)
	}
	return nil
}

func (c *Client) Lock(ctx context.Context) error {
	var out SimpleResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/vault/lock", nil, &out); err != nil {
		return err
	}
	if !out.OK {
		if out.Error == "" {
			return errors.New("lock failed")
		}
		return errors.New(out.Error)
	}
	return nil
}

func (c *Client) ListProfiles(ctx context.Context) ([]Profile, error) {
	var out struct {
		Profiles []Profile `json:"profiles"`
		Error    string    `json:"error,omitempty"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/autofill/profiles", nil, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, errors.New(out.Error)
	}
	return out.Profiles, nil
}

func (c *Client) RequestFill(ctx context.Context, req FillRequest) (*FillResponse, error) {
	var out FillResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/autofill/request", req, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, errors.New(out.Error)
	}
	return &out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, in any, out any) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		if payload.Error != "" {
			return errors.New(payload.Error)
		}
		return fmt.Errorf("daemon returned status %d", resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
