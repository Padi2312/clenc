package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Padi2312/clenc/pkg"
	"github.com/stretchr/testify/assert"
)

func TestEncryptFile(t *testing.T) {

	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "test_file")
	if err != nil {
		t.Fatal("Failed to create temporary file:", err)
	}
	defer func() {
		os.Remove(tempFile.Name())
		tempFile.Close()
	}()
	// Write content to the temporary file
	content := []byte("Hello, World!")
	_, err = tempFile.Write(content)

	if err != nil {
		t.Fatal("Failed to write content to the temporary file:", err)
	}
	tempFile.Close()

	// Test encryptFile function
	password := "mySecretPassword"
	err = encryptFile(tempFile.Name(), password)
	assert.NoError(t, err, "encryptFile should not return an error")

	// Verify that the file is encrypted
	fileContent, _, err := pkg.ReadFileWithInfo(tempFile.Name())
	assert.NoError(t, err, "Failed to read encrypted file content")
	assert.NotEqual(t, content, fileContent, "File content should be encrypted")
}

func TestDecryptFile(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "test_file")
	if err != nil {
		t.Fatal("Failed to create temporary file:", err)
	}
	defer func() {
		os.Remove(tempFile.Name())
		tempFile.Close()
	}()
	// Write content to the temporary file
	content := []byte("Hello, World!")
	_, err = tempFile.Write(content)
	if err != nil {
		t.Fatal("Failed to write content to the temporary file:", err)
	}
	// Encrypt the file
	password := "mySecretPassword"
	err = encryptFile(tempFile.Name(), password)
	assert.NoError(t, err, "Failed to encrypt file for testing")

	// Test decryptFile function
	err = decryptFile(tempFile.Name(), password)
	assert.NoError(t, err, "decryptFile should not return an error")

	// Verify that the file is decrypted
	fileContent, _, err := pkg.ReadFileWithInfo(tempFile.Name())
	assert.NoError(t, err, "Failed to read decrypted file content")
	assert.Equal(t, content, fileContent, "File content should be decrypted")
}

func TestCountFiles(t *testing.T) {
	// Create a temporary directory with files for testing
	tempDir := t.TempDir()
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "file2.txt")
	file3 := filepath.Join(tempDir, "file3.txt")
	err := os.WriteFile(file1, []byte("Content1"), 0644)
	assert.NoError(t, err, "Failed to create temporary file 1")
	err = os.WriteFile(file2, []byte("Content2"), 0644)
	assert.NoError(t, err, "Failed to create temporary file 2")
	err = os.WriteFile(file3, []byte("Content3"), 0644)
	assert.NoError(t, err, "Failed to create temporary file 3")

	// Test countFiles function
	count := countFiles(tempDir)
	assert.Equal(t, int32(3), count, "countFiles returned incorrect count")
}
