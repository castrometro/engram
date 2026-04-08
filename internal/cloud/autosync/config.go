// Package autosync (config helpers)
package autosync

import (
	"encoding/json"
	"os"
)

// CloudConfig is the persistent cloud sync configuration stored in
// ~/.engram/cloud.json. It is written by "engram cloud setup" and read
// by the autosync Manager at startup.
type CloudConfig struct {
	ServerURL  string `json:"server_url"`
	APIKey     string `json:"api_key"`
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Project    string `json:"project"`
}

// ReadCloudConfig reads a CloudConfig from the JSON file at path.
// Returns os.ErrNotExist (wrapped) if the file does not exist.
func ReadCloudConfig(path string) (*CloudConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg CloudConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// WriteCloudConfig writes cfg to the JSON file at path (mode 0600).
func WriteCloudConfig(path string, cfg *CloudConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
