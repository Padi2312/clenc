package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/term"

	"github.com/Padi2312/clenc/pkg"
)

const (
	saltSize = 16
)

var (
	totalFiles, doneFiles int32
	mu                    sync.Mutex // Mutex to ensure thread-safety when updating the progress bar
	workers               int        = 4
	force                 bool       = false
)

func main() {
	pkg.LogTime("time")

	var (
		target   string
		password string
		mode     string
		err      error
	)
	flag.StringVar(&target, "target", "", "target file or directory to encrypt/decrypt")
	flag.StringVar(&mode, "mode", "", "operation mode (encrypt/decrypt)")
	flag.IntVar(&workers, "workers", pkg.GetCpuCores(), "amount of workers used for operations")
	flag.BoolVar(&force, "force", false, "force multiple encryption")
	flag.Parse()

	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln("Failed to read password:", err)
	}
	password = string(bytePassword)
	if password == "" {
		log.Fatalln("\nNo password given.")
	}
	// target = "./test.png"
	// password = "test"
	// mode = "encrypt"

	if target == "" || password == "" || mode == "" {
		flag.Usage()
		os.Exit(1)
	}

	totalFiles = countFiles(target)

	if mode == "decrypt" {
		err = processTarget(target, password, decryptFile)
	} else if mode == "encrypt" {
		err = processTarget(target, password, encryptFile)
	} else {
		flag.Usage()
		log.Fatalln("Use mode 'encrypt' or 'decrypt'")
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
	log.Println("")
	pkg.LogTimeEnd("time")
}

// This function will start worker goroutines and feed them file paths to process.
func processTarget(target string, password string, processFile func(string, string) error) error {
	fileChan := make(chan string) // Create a channel to send file paths to the workers.

	var wg sync.WaitGroup
	wg.Add(workers) // Add the number of workers to the WaitGroup.
	// Start the worker goroutines.
	for i := 0; i < workers; i++ {
		go func() {
			for filename := range fileChan { // Continuously receive file paths from the channel until it's closed.
				if err := processFile(filename, password); err != nil {
					log.Printf("Failed to process %s: %v\n", filename, err)
				} else {
					printProgress(filename)
				}
			}
			wg.Done() // When there are no more file paths, signal the WaitGroup that this worker is done.
		}()
	}

	// Walk the directory and send the file paths to the workers.
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			fileChan <- path
		}
		return nil
	})
	close(fileChan) // Close the channel after all file paths have been sent.
	wg.Wait()       // Wait for all workers to finish.
	return err
}

func encryptFile(filename string, password string) error {
	content, info, err := pkg.ReadFileWithInfo(filename)
	if err != nil {
		return err
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key := pkg.GetArgonIdKey(password, salt, workers)

	aesgcm, err := pkg.CreateAesGcm(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	encContent := aesgcm.Seal(nonce, nonce, content, nil)
	err = pkg.WriteFileOriginal(filename, append(salt, encContent...), info)
	if err != nil {
		return err
	}
	return nil
}

func decryptFile(filename string, password string) error {
	content, info, err := pkg.ReadFileWithInfo(filename)
	if err != nil {
		return err
	}

	if len(content) < saltSize {
		return errors.New("file too short to be encrypted")
	}

	salt, content := content[:saltSize], content[saltSize:]
	key := pkg.GetArgonIdKey(password, salt, workers)
	aesgcm, err := pkg.CreateAesGcm(key)
	if err != nil {
		return err
	}

	if len(content) < aesgcm.NonceSize() {
		return errors.New("file too short to be encrypted")
	}

	nonce, content := content[:aesgcm.NonceSize()], content[aesgcm.NonceSize():]
	plainContent, err := aesgcm.Open(nil, nonce, content, nil)
	if err != nil {
		return errors.New("decryption failed, data may have been tampered with")
	}

	err = pkg.WriteFileOriginal(filename, plainContent, info)
	if err != nil {
		return err
	}
	return nil
}

func countFiles(root string) int32 {
	var count int32
	filepath.WalkDir(root, func(_ string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			atomic.AddInt32(&count, 1)
		}
		return nil
	})
	return count
}

func printProgress(filename string) {
	mu.Lock()
	defer mu.Unlock()
	atomic.AddInt32(&doneFiles, 1)
	fmt.Printf("\r\033[2KProcessing (%d/%d): %s", doneFiles, totalFiles, filename) // Clear the line before printing
}
