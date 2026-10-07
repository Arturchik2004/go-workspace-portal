package nextcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OCSResponse описывает стандартную структуру ответа Nextcloud OCS API.
type OCSResponse struct {
	OCS struct {
		Meta struct {
			Status     string `json:"status"`
			StatusCode int    `json:"statuscode"`
			Message    string `json:"message"`
		} `json:"meta"`
	} `json:"ocs"`
}

// Client is an HTTP client for working with the Nextcloud Provisioning (OCS) API.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewClient creates a Nextcloud client with a sane HTTP timeout.
func NewClient(baseURL, username, password string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CreateUser creates a new user account via Nextcloud OCS API.
func (c *Client) CreateUser(ctx context.Context, newUserLogin, newUserPassword string) error {
	endpoint := fmt.Sprintf("%s/ocs/v1.php/cloud/users", c.baseURL)

	data := url.Values{}
	data.Set("userid", newUserLogin)
	data.Set("password", newUserPassword)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create nextcloud request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("OCS-APIRequest", "true")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform nextcloud request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nextcloud returned unexpected HTTP status: %d", resp.StatusCode)
	}

	var ocsResp OCSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ocsResp); err != nil {
		return fmt.Errorf("failed to decode nextcloud response: %w", err)
	}

	// В OCS API код 100 означает успешное выполнение операции
	if ocsResp.OCS.Meta.StatusCode != 100 {
		return fmt.Errorf("nextcloud error (code %d): %s", 
			ocsResp.OCS.Meta.StatusCode, 
			ocsResp.OCS.Meta.Message,
		)
	}

	return nil
}
