package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Data struct {
	SecretKey string     `json:"secret_key"`
	KeyGroups []KeyGroup `json:"key_groups,omitempty"`
}

type KeyGroup struct {
	Coordinator           string `json:"coordinator"`
	AggregatePublicKey    string `json:"aggregate_public_key"`
	EncodedSecretKeyShard string `json:"encoded_secret_key_shard"`
}

func lockDir() error {
	name := filepath.Join(dir, "lock")
	if _, err := os.Stat(name); os.IsNotExist(err) {
		_, err := os.Create(name)
		return err
	} else {
		return fmt.Errorf("lock file exists")
	}
}

func unlockDir() {
	name := filepath.Join(dir, "lock")
	os.Remove(name)
}

func storeData(data Data) error {
	jdata, _ := json.MarshalIndent(data, "", "  ")

	if err := os.WriteFile(filepath.Join(dir, "data.json"), jdata, 0644); err != nil {
		return err
	}

	return nil
}

func readData(dir string) (Data, error) {
	if dir == "" {
		return Data{}, fmt.Errorf("missing --dir")
	}

	if bdata, err := os.ReadFile(filepath.Join(dir, "data.json")); err != nil && !os.IsNotExist(err) {
		return Data{}, fmt.Errorf("failed to read data.json: %w", err)
	} else if err := json.Unmarshal(bdata, &data); err != nil && len(bdata) != 0 {
		return Data{}, fmt.Errorf("error parsing data.json ('%s'): %w", string(bdata), err)
	} else if len(bdata) == 0 {
		os.MkdirAll(dir, 0777)
		randkey := make([]byte, 32)
		rand.Read(randkey)

		data = Data{
			SecretKey: hex.EncodeToString(randkey),
		}

		if err := storeData(data); err != nil {
			return Data{}, err
		}
	}

	return data, nil
}
