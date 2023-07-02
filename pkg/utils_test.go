package pkg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadFileWithInfo(t *testing.T) {
	// Create a temporary file for testing
	tempFile, err := os.CreateTemp("", "test_file")
	if err != nil {
		t.Fatal("Failed to create temporary file:", err)
	}
	defer os.Remove(tempFile.Name())

	// Write content to the temporary file
	content := []byte("Hello, World!")
	_, err = tempFile.Write(content)
	if err != nil {
		t.Fatal("Failed to write content to the temporary file:", err)
	}

	// Close the file to ensure the content is flushed
	tempFile.Close()

	// Test ReadFileWithInfo function
	fileContent, fileInfo, err := ReadFileWithInfo(tempFile.Name())
	assert.NoError(t, err, "ReadFileWithInfo should not return an error")
	assert.Equal(t, content, fileContent, "ReadFileWithInfo returned incorrect file content")
	assert.NotNil(t, fileInfo, "ReadFileWithInfo should return non-nil file info")
}

func TestGetArgonIdKey(t *testing.T) {
	password := "mySecretPassword"
	salt := []byte("randomsalt")
	workers := 4

	// Test GetArgonIdKey function
	key := GetArgonIdKey(password, salt, workers)
	assert.NotNil(t, key, "GetArgonIdKey should return non-nil key")
}

func TestCreateAesGcm(t *testing.T) {
	key := []byte("12345678901234567890123456789012")

	// Test CreateAesGcm function
	aesgcm, err := CreateAesGcm(key)
	assert.NoError(t, err, "CreateAesGcm should not return an error")
	assert.NotNil(t, aesgcm, "CreateAesGcm should return non-nil AEAD")
}

func TestWriteFileOriginal(t *testing.T) {
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

	// Get file info
	fileInfo, err := tempFile.Stat()
	if err != nil {
		t.Fatal("Failed to get file info:", err)
	}

	// Test WriteFileOriginal function
	err = WriteFileOriginal(tempFile.Name(), content, fileInfo)
	assert.NoError(t, err, "WriteFileOriginal should not return an error")

	// Verify the file permissions and timestamps
	updatedFileInfo, err := os.Stat(tempFile.Name())
	assert.NoError(t, err, "Failed to retrieve file info after writing")
	assert.Equal(t, fileInfo.Mode(), updatedFileInfo.Mode(), "File permissions are incorrect")
	assert.Equal(t, fileInfo.ModTime(), updatedFileInfo.ModTime(), "File timestamps are incorrect")
}

func TestGetCpuCores(t *testing.T) {
	// Test GetCpuCores function
	cores := GetCpuCores()
	assert.Greater(t, cores, 0, "GetCpuCores should return a positive value")
}
