package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
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

func storeData(data Data) error {
	jdata, _ := json.MarshalIndent(data, "", "  ")

	if err := os.WriteFile(filepath.Join(dir, "data.json"), jdata, 0644); err != nil {
		return err
	}

	return nil
}

func readData(dir string) (Data, error) {
	if dir == "" {
		var err error
		dir, err = homedir.Expand("~/.config/promd")
		if err != nil {
			return Data{}, fmt.Errorf("can't get ~/.config/promd directory: %w", err)
		}
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
