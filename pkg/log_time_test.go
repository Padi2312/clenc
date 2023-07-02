package pkg

import (
	"log"
	"os"
	"testing"
	"time"
)

func TestLogTime(t *testing.T) {
	resetGlobalTimers() // Reset globalTimers before each test

	// Test case 1: Timer does not exist, should log the start time
	name := "Timer1"
	LogTime(name)
	if _, exists := getGlobalTimer(name); !exists {
		t.Errorf("Expected timer to be created, but it doesn't exist")
	}

	// Test case 2: Timer already exists, should log an error message and not create a new timer
	LogTime(name)
	expectedLog := "Timer already exists!\n"
	if loggedMsg := captureLogOutput(t, func() {
		LogTime(name)
	}); loggedMsg != expectedLog {
		t.Errorf("Expected log message '%s', but got '%s'", expectedLog, loggedMsg)
	}
}

func TestLogTimeEnd(t *testing.T) {
	resetGlobalTimers() // Reset globalTimers before each test

	// Test case 1: Timer exists, should log the elapsed time and remove the timer
	name := "Timer2"
	LogTime(name)
	_ = getGlobalTimerStartTime(name)
	time.Sleep(time.Microsecond) // Simulate some time delay
	//	LogTimeEnd(name)

	expectedLog := "Elapsed time:"
	if loggedMsg := captureLogOutput(t, func() {
		LogTimeEnd(name)
	}); len(loggedMsg) == 0 || !containsSubstring(loggedMsg, expectedLog) {
		t.Errorf("Expected log message containing '%s', but got '%s'", expectedLog, loggedMsg)
	}
	if _, exists := getGlobalTimer(name); exists {
		t.Errorf("Expected timer to be removed, but it still exists")
	}

	// Test case 2: Timer does not exist, should not log any error or elapsed time
	if loggedMsg := captureLogOutput(t, func() {
		LogTimeEnd("NonExistingTimer")
	}); len(loggedMsg) > 0 {
		t.Errorf("Expected no log message, but got '%s'", loggedMsg)
	}
}

// Helper function to reset globalTimers for testing
func resetGlobalTimers() {
	globalTimers = make(map[string]time.Time)
}

// Helper function to access globalTimers for testing
func getGlobalTimer(name string) (time.Time, bool) {
	timer, exists := globalTimers[name]
	return timer, exists
}

// Helper function to access the start time of a globalTimer for testing
func getGlobalTimerStartTime(name string) time.Time {
	return globalTimers[name]
}

// Helper function to capture the log output during testing
func captureLogOutput(t *testing.T, fn func()) string {
	t.Helper()
	log.SetOutput(os.Stdout) // Set the log output back to os.Stdout

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}

	os.Stdout = w
	log.SetOutput(w)

	fn()

	// Restore os.Stdout and log.SetOutput to their original values
	w.Close()
	os.Stdout = r

	logOutput := make(chan string)
	go func() {
		defer close(logOutput)
		buf := make([]byte, 1024)
		n, _ := r.Read(buf)
		logOutput <- string(buf[:n])
	}()

	return <-logOutput
}

// Helper function to check if a string contains a substring
func containsSubstring(str, substr string) bool {
	return len(str) > 0 && len(substr) > 0 && len(str) >= len(substr) && str[:len(substr)] == substr
}
