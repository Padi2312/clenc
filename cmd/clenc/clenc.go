package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Padi2312/clenc/pkg"
	"golang.org/x/term"
)

const (
	saltSize   = 16
	identifier = "ENCRYTPED"
)

var (
	totalFiles, doneFiles int32
	mu                    sync.Mutex // Mutex to ensure thread-safety when updating the progress bar
	workers               int        = 4
	force                 bool       = false
)

var (
	target      string
	password    string
	mode        string
	showVersion bool
)

func parseFlags() {
	flag.StringVar(&target, "target", "", "target file or directory to encrypt/decrypt")
	flag.StringVar(&mode, "mode", "", "operation mode (encrypt/decrypt)")
	flag.IntVar(&workers, "workers", pkg.GetCpuCores(), "amount of workers used for operations")
	flag.BoolVar(&force, "force", false, "force multiple encryption (default false)")
	flag.BoolVar(&showVersion, "version", false, "print the version information")
	flag.Parse()
}

func main() {
	var err error
	parseFlags()
	if showVersion {
		version, err := pkg.GetVersionInfo()
		if err != nil {
			fmt.Println("Error showing version.", err)
		}
		fmt.Println("Clenc Version:", *version)
		os.Exit(0)
	}

	if target == "" || mode == "" {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln("Failed to read password:", err)
	}
	password = string(bytePassword)
	if password == "" {
		log.Fatalln("\nNo password given.")
	}
	fmt.Println("")
	pkg.LogTime("time")
	totalFiles = countFiles(target)

	// Init CryptoClenc
	cryptoClenc := pkg.NewCryptoClenc(
		password,
		saltSize,
		identifier,
	)

	if mode == "decrypt" {
		err = processTarget(target, cryptoClenc.DecryptFile) //decryptFile)
	} else if mode == "encrypt" {
		err = processTarget(target, cryptoClenc.EncryptFile)
	} else {
		flag.Usage()
		log.Fatalln("Use mode 'encrypt' or 'decrypt'")
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("")
	pkg.LogTimeEnd("time")
}

// This function will start worker goroutines and feed them file paths to process.
func processTarget(target string, processFile func(string) error) error {
	fileChan := make(chan string) // Create a channel to send file paths to the workers.

	var wg sync.WaitGroup
	wg.Add(workers) // Add the number of workers to the WaitGroup.
	// Start the worker goroutines.
	for i := 0; i < workers; i++ {
		go func() {
			for filename := range fileChan { // Continuously receive file paths from the channel until it's closed.
				if err := processFile(filename); err != nil {
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

func countFiles(root string) int32 {
	var count int32
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			count++
		}
		return nil
	})
	if err != nil {
		log.Panicln("could not count files in given directory")
		os.Exit(1)
	}
	return count
}

func printProgress(filename string) {
	mu.Lock()
	defer mu.Unlock()
	atomic.AddInt32(&doneFiles, 1)
	fmt.Printf("\r\033[2KProcessing (%d/%d): %s", doneFiles, totalFiles, filename) // Clear the line before printing
}
