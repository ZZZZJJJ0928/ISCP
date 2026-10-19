package iscpbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ProfileProduction = "production"
	ProfileLocalLab   = "local-lab"
)

type Config struct {
	Profile                string        `json:"profile"`
	IdentityDirectory      string        `json:"identity_directory"`
	IdentityKeyBackend     string        `json:"identity_key_backend"`
	IdentityKeyringService string        `json:"identity_keyring_service"`
	EnrollmentFile         string        `json:"enrollment_file"`
	Permission             string        `json:"permission"`
	Gateway                GatewayConfig `json:"gateway"`
	Relay                  RelaySettings `json:"relay"`
}

type GatewayConfig struct {
	BaseURL        string `json:"base_url"`
	UnixSocket     string `json:"unix_socket,omitempty"`
	TokenFile      string `json:"token_file,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type RelaySettings struct {
	ReconnectMinSeconds   int `json:"reconnect_min_seconds"`
	ReconnectMaxSeconds   int `json:"reconnect_max_seconds"`
	RequestTimeoutSeconds int `json:"request_timeout_seconds"`
	EventPollMilliseconds int `json:"event_poll_milliseconds"`
	EnvelopeTTLSeconds    int `json:"envelope_ttl_seconds"`
}

func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read Bridge config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode Bridge config: %w", err)
	}
	baseDir := filepath.Dir(path)
	config.IdentityDirectory = resolveConfigPath(baseDir, config.IdentityDirectory)
	config.EnrollmentFile = resolveConfigPath(baseDir, config.EnrollmentFile)
	config.Gateway.TokenFile = resolveConfigPath(baseDir, config.Gateway.TokenFile)
	config.Gateway.UnixSocket = resolveConfigPath(baseDir, config.Gateway.UnixSocket)
	if err := config.normalizeAndValidate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c *Config) normalizeAndValidate() error {
	c.Profile = strings.ToLower(strings.TrimSpace(c.Profile))
	if c.Profile == "" {
		c.Profile = ProfileProduction
	}
	if c.Profile != ProfileProduction && c.Profile != ProfileLocalLab {
		return errors.New("Bridge profile must be production or local-lab")
	}
	if strings.TrimSpace(c.IdentityDirectory) == "" || strings.TrimSpace(c.EnrollmentFile) == "" {
		return errors.New("identity_directory and enrollment_file are required")
	}
	c.IdentityKeyBackend = strings.ToLower(strings.TrimSpace(c.IdentityKeyBackend))
	if c.IdentityKeyBackend == "" {
		if c.Profile == ProfileProduction {
			c.IdentityKeyBackend = IdentityKeyBackendKeyring
		} else {
			c.IdentityKeyBackend = IdentityKeyBackendFile
		}
	}
	if c.IdentityKeyBackend != IdentityKeyBackendKeyring && c.IdentityKeyBackend != IdentityKeyBackendFile {
		return errors.New("identity_key_backend must be keyring or file")
	}
	if c.Profile == ProfileProduction && c.IdentityKeyBackend != IdentityKeyBackendKeyring {
		return errors.New("production Bridge requires the keyring identity key backend")
	}
	if strings.TrimSpace(c.IdentityKeyringService) == "" {
		c.IdentityKeyringService = DefaultIdentityKeyringService
	}
	if strings.TrimSpace(c.Gateway.BaseURL) == "" && strings.TrimSpace(c.Gateway.UnixSocket) == "" {
		c.Gateway.BaseURL = defaultGatewayURL
	}
	if strings.TrimSpace(c.Permission) == "" {
		c.Permission = "agent.bridge"
	}
	if c.Gateway.TimeoutSeconds <= 0 {
		c.Gateway.TimeoutSeconds = int(defaultGatewayTimeout.Seconds())
	}
	if c.Gateway.TimeoutSeconds > 300 {
		return errors.New("gateway.timeout_seconds must not exceed 300")
	}
	if c.Relay.ReconnectMinSeconds <= 0 {
		c.Relay.ReconnectMinSeconds = 1
	}
	if c.Relay.ReconnectMaxSeconds <= 0 {
		c.Relay.ReconnectMaxSeconds = 30
	}
	if c.Relay.ReconnectMaxSeconds < c.Relay.ReconnectMinSeconds || c.Relay.ReconnectMaxSeconds > 300 {
		return errors.New("Relay reconnect bounds are invalid")
	}
	if c.Relay.RequestTimeoutSeconds <= 0 {
		c.Relay.RequestTimeoutSeconds = 30
	}
	if c.Relay.RequestTimeoutSeconds > 120 {
		return errors.New("Relay request timeout must not exceed 120 seconds")
	}
	if c.Relay.EventPollMilliseconds <= 0 {
		c.Relay.EventPollMilliseconds = 500
	}
	if c.Relay.EventPollMilliseconds < 100 || c.Relay.EventPollMilliseconds > 10_000 {
		return errors.New("Relay event poll interval must be between 100 and 10000 milliseconds")
	}
	if c.Relay.EnvelopeTTLSeconds <= 0 {
		c.Relay.EnvelopeTTLSeconds = 300
	}
	if c.Relay.EnvelopeTTLSeconds > 86400 {
		return errors.New("Relay envelope TTL must not exceed 86400 seconds")
	}
	return nil
}

func (c Config) LoadGatewayToken() (string, error) {
	if strings.TrimSpace(c.Gateway.TokenFile) == "" {
		return "", nil
	}
	return LoadPrivateTokenFile(c.Gateway.TokenFile)
}

func LoadPrivateTokenFile(path string) (string, error) {
	if err := requirePrivateFile(path); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Gateway token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	return token, nil
}

func (c Config) DeviceFiles() DeviceFiles {
	return DeviceFiles{
		Directory:    c.IdentityDirectory,
		IdentityFile: filepath.Join(c.IdentityDirectory, IdentityFileName),
		KeyFile:      filepath.Join(c.IdentityDirectory, IdentityKeyFileName),
	}
}

func (c Config) GatewayTimeout() time.Duration {
	return time.Duration(c.Gateway.TimeoutSeconds) * time.Second
}

func (c Config) RelayRequestTimeout() time.Duration {
	return time.Duration(c.Relay.RequestTimeoutSeconds) * time.Second
}

func (c Config) EventPollInterval() time.Duration {
	return time.Duration(c.Relay.EventPollMilliseconds) * time.Millisecond
}

func resolveConfigPath(baseDir, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}
