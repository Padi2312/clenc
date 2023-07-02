package pkg

import (
	"fmt"
	"time"
)

var globalTimers map[string]time.Time = make(map[string]time.Time)

func LogTime(name string) {
	_, exists := globalTimers[name]
	if exists {
		fmt.Println("Timer already exists!")
		return
	}
	start := time.Now()
	globalTimers[name] = start
}

func LogTimeEnd(name string) {
	_, exists := globalTimers[name]
	if !exists {
		return
	}

	startTime := globalTimers[name]
	delete(globalTimers, name)
	endTime := time.Now()
	elapsed := endTime.Sub(startTime)
	fmt.Println("Elapsed time: " + elapsed.String())
}
