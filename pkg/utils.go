package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"runtime"

	"golang.org/x/crypto/argon2"
)

func ReadFileWithInfo(path string) ([]byte, fs.FileInfo, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	return content, info, nil
}

func GetArgonIdKey(password string, salt []byte, workers int) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, uint8(workers), 32)
}

func CreateAesGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm, nil
}

func WriteFileOriginal(path string, data []byte, info fs.FileInfo) error {
	err := os.WriteFile(path, data, 0)
	if err != nil {
		return err
	}

	err = os.Chmod(path, info.Mode())
	if err != nil {
		return err
	}

	err = os.Chtimes(path, info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

func GetCpuCores() int {
	return runtime.NumCPU()
}

func IsFileEncrypted(content []byte, identifier string, saltSize int) bool {
	if len(content) < len(identifier)+saltSize {
		return false
	}
	id := content[:len(identifier)]
	stringId := string(id)
	return stringId == identifier
}

func GetVersionInfo() (*string, error) {
	type VersionInfo struct {
		Version string `json:"version"`
	}
	data, err := os.ReadFile("./../version.json")
	if err != nil {
		fmt.Printf("Failed to read config file: %s\n", err.Error())
		return nil, err
	}
	var config VersionInfo
	err = json.Unmarshal(data, &config)
	if err != nil {
		fmt.Printf("Failed to parse config file: %s\n", err.Error())
		return nil, err
	}
	return &config.Version, nil
}
