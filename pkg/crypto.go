package pkg

import (
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"
)

type CryptoClenc struct {
	password   string
	saltSize   int
	identifier *string
}

func NewCryptoClenc(password string, saltSize int, identifier string) *CryptoClenc {
	return &CryptoClenc{
		password:   password,
		saltSize:   saltSize,
		identifier: &identifier,
	}
}

// IsFileEncrypted checks if the given content is encrypted based on the provided identifier and salt size.
func (c *CryptoClenc) IsFileEncrypted(content []byte, identifier string, saltSize int) bool {
	if len(content) < len(identifier)+saltSize {
		return false
	}
	id := content[:len(identifier)]
	stringId := string(id)
	return stringId == identifier
}

// Encrypt encrypts the given data using the configured encryption settings.
func (c *CryptoClenc) Encrypt(data []byte) ([]byte, error) {
	var identifier string
	if c.identifier != nil {
		identifier = *c.identifier
	} else {
		PrintWarn("If you don't use an identifier you won't be able to detect encrypted files later on.")
		identifier = ""
	}

	salt := make([]byte, c.saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := GetArgonIdKey(c.password, salt, runtime.NumCPU())
	aesgcm, err := CreateAesGcm(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encContent := aesgcm.Seal(nonce, nonce, data, nil)
	encContent = c.setupEncryptedData(encContent, salt, identifier)
	return encContent, nil
}

// Decrypt decrypts the given data using the configured decryption settings.
func (c *CryptoClenc) Decrypt(data []byte) ([]byte, error) {
	var identifier string
	if c.identifier != nil {
		identifier = *c.identifier
	} else {
		PrintWarn("Empty identifier. Try encrypt file, be prepared for errors.")
		identifier = ""
	}

	idSaltLength := len(identifier) + c.saltSize
	salt, content := data[len(identifier):idSaltLength], data[idSaltLength:]
	key := GetArgonIdKey(c.password, salt, runtime.NumCPU())
	aesgcm, err := CreateAesGcm(key)
	if err != nil {
		return nil, err
	}

	if len(content) < aesgcm.NonceSize() {
		return nil, errors.New("file too short to be encrypted")
	}

	nonce, content := content[:aesgcm.NonceSize()], content[aesgcm.NonceSize():]
	plainContent, err := aesgcm.Open(nil, nonce, content, nil)
	if err != nil {
		return nil, err
	}
	return plainContent, nil
}

// EncryptFile encrypts the file located at the specified path using the configured encryption settings.
func (c *CryptoClenc) EncryptFile(path string) error {
	content, info, err := c.readFileWithInfo(path)
	if err != nil {
		return err
	}

	encryptedContent, err := c.Encrypt(content)
	if err != nil {
		return err
	}

	err = WriteFileOriginal(path, encryptedContent, info)
	if err != nil {
		return err
	}
	return nil
}

// DecryptFile decrypts the file located at the specified path using the configured decryption settings.
func (c *CryptoClenc) DecryptFile(path string) error {
	content, info, err := ReadFileWithInfo(path)
	if err != nil {
		return err
	}

	decryptedContent, err := c.Decrypt(content)
	if err != nil {
		return err
	}

	err = WriteFileOriginal(path, decryptedContent, info)
	if err != nil {
		return err
	}
	return nil
}

// readFileWithInfo reads the file content and retrieves its information using the specified file path.
func (c *CryptoClenc) readFileWithInfo(path string) ([]byte, fs.FileInfo, error) {
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

// setupEncryptedData prepares the encrypted data for storage by appending the identifier, salt, and encrypted content.
func (c *CryptoClenc) setupEncryptedData(content []byte, salt []byte, identifier string) []byte {
	// First add identifier to content for checking encryption
	var preparedContent []byte = []byte(identifier)
	// Add salt to file content
	preparedContent = append(preparedContent, salt...)
	// Finally add encrypted file data
	preparedContent = append(preparedContent, content...)
	return preparedContent
}
