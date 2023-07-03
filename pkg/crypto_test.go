package pkg

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsFileEncrypted(t *testing.T) {
	cryptoClenc := NewCryptoClenc("password123", 16, "ENCRYTPED")

	// Test encrypted content
	encryptedContent := []byte("ENCRYTPEDsalt123encrypted_data")
	assert.True(t, cryptoClenc.IsFileEncrypted(encryptedContent, "ENCRYTPED", 16), "Expected encrypted content to be recognized as encrypted")

	// Test non-encrypted content
	nonEncryptedContent := []byte("random_data")
	assert.False(t, cryptoClenc.IsFileEncrypted(nonEncryptedContent, "ENCRYTPED", 16), "Expected non-encrypted content to be recognized as non-encrypted")
}

func TestEncryptDecrypt(t *testing.T) {
	cryptoClenc := NewCryptoClenc("password123", 16, "ENCRYTPED")

	// Test encrypting and decrypting content
	originalContent := []byte("test_data")
	encryptedContent, err := cryptoClenc.Encrypt(originalContent)
	assert.NoError(t, err, "Error encrypting content")
	assert.NotNil(t, encryptedContent, "Encrypted content should not be nil")

	decryptedContent, err := cryptoClenc.Decrypt(encryptedContent)
	assert.NoError(t, err, "Error decrypting content")
	assert.Equal(t, originalContent, decryptedContent, "Decrypted content should match original content")
}

func TestEncryptDecryptFile(t *testing.T) {
	cryptoClenc := NewCryptoClenc("password123", 16, "ENCRYTPED")

	// Create a temporary test file
	file, err := os.CreateTemp("", "test_file.txt")
	assert.NoError(t, err, "Error creating test file")
	defer os.Remove(file.Name())

	originalContent := []byte("test_data")
	err = os.WriteFile(file.Name(), originalContent, 0644)
	assert.NoError(t, err, "Error writing to test file")

	// Test encrypting and decrypting file
	err = cryptoClenc.EncryptFile(file.Name())
	assert.NoError(t, err, "Error encrypting file")

	err = cryptoClenc.DecryptFile(file.Name())
	assert.NoError(t, err, "Error decrypting file")

	// Read the decrypted file content
	decryptedContent, err := os.ReadFile(file.Name())
	assert.NoError(t, err, "Error reading decrypted file")
	assert.Equal(t, originalContent, decryptedContent, "Decrypted file content should match original content")
}

func createTestFile(filePath string, size int) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	buffer := make([]byte, size)
	_, err = rand.Read(buffer)
	if err != nil {
		return err
	}

	_, err = file.Write(buffer)
	if err != nil {
		return err
	}

	return nil
}

func TestEncryptDecryptLargeFile(t *testing.T) {
	cryptoClenc := NewCryptoClenc("password123", 16, "ENCRYTPED")

	// Create a temporary test file with random content
	file, err := os.CreateTemp("", "large_test_file.txt")
	assert.NoError(t, err, "Error creating large test file")
	defer os.Remove(file.Name())

	fileSize := 10 * 1024 * 1024 // 10MB
	err = createTestFile(file.Name(), fileSize)
	assert.NoError(t, err, "Error creating large test file")

	// Test encrypting and decrypting large file
	err = cryptoClenc.EncryptFile(file.Name())
	assert.NoError(t, err, "Error encrypting large file")

	err = cryptoClenc.DecryptFile(file.Name())
	assert.NoError(t, err, "Error decrypting large file")
}
