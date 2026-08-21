package utils

import (
	"runtime"
	"sync"
)

// WorkerPool runs jobs concurrently with a fixed number of workers.
// numWorkers <= 0 means use runtime.GOMAXPROCS(0).
func WorkerPool(numWorkers int, jobs []func()) {
	if len(jobs) == 0 {
		return
	}

	if numWorkers <= 0 {
		numWorkers = runtime.GOMAXPROCS(0)
	}
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	ch := make(chan func(), len(jobs))
	for _, job := range jobs {
		ch <- job
	}
	close(ch)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range ch {
				job()
			}
		}()
	}
	wg.Wait()
}
