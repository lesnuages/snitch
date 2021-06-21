package snitch

import (
	"sync"
	"time"
)

// Sample maps an implant name with its MD5 hash
type Sample struct {
	implantName string
	hash        string
}

// NewSample is the Sample constructor
func NewSample(name string, hash string) Sample {
	return Sample{
		implantName: name,
		hash:        hash,
	}
}

// Snitch -- the Snitch struct
type Snitch struct {
	scanners      map[string]Scanner
	samples       chan Sample
	stop          chan bool
	HandleFlagged func(*ScanResult)
}

// Scanner is the abstract representation of a malware scanner
type Scanner interface {
	// Add adds a sample to the scanning list
	Add(Sample)
	// Remove deletes a sample from the list
	Remove(Sample)
	// Samples is the accessor for the sample list
	Samples() []Sample
	// Threshold is the time we need to sleep before each batch of requests
	Threshold() time.Duration
	// MaxRequests represents the maximum number of requests we can make
	// before going to sleep
	MaxRequests() int
	// Scan performs the request to the API
	Scan(Sample) (*ScanResult, error)
	// Mutex is used to lock the sample list during async operations
	Mutex() *sync.Mutex
	// Name of the scanner
	Name() string
}

// ScanResult stores a scan result
type ScanResult struct {
	Sample   Sample
	Provider string
	LastSeen time.Time
}

// ScanLoop --
func ScanLoop(s Scanner, quit chan bool, handleResult func(*ScanResult)) {
	for {
		select {
		case <-quit:
			return
		default:
			// Split samples in equal chunks
			s.Mutex().Lock()
			batches := split(s.Samples(), s.MaxRequests())
			s.Mutex().Unlock()
			for _, sampSlice := range batches {
				for _, samp := range sampSlice {
					r, err := s.Scan(samp)
					if err != nil {
						return
					}
					go handleResult(r)
				}
				// Sleep after scanning a batch
				time.Sleep(s.Threshold())
			}

		}
	}
}

// NewSnitch returns a new Snitch instance
func NewSnitch() *Snitch {
	return &Snitch{
		scanners: make(map[string]Scanner),
		samples:  make(chan Sample),
		stop:     make(chan bool),
	}
}

func WithHandleFlagged(handleFlagged func(*ScanResult)) *Snitch {
	s := NewSnitch()
	s.HandleFlagged = handleFlagged
	return s
}

func (s *Snitch) AddScanner(scanner Scanner) {
	s.scanners[scanner.Name()] = scanner
}

// Start kicks off the regular scans
func (s *Snitch) Start() {
	go s.start()
}

func (s *Snitch) deleteSample(sample Sample) {
	for _, scanner := range s.scanners {
		scanner.Remove(sample)
	}
}

func (s *Snitch) start() {
	// start scanning loops
	for _, scanner := range s.scanners {
		go ScanLoop(scanner, s.stop, func(res *ScanResult) {
			if res != nil {
				// sample is flagged:
				// - delete it from the list to avoid scanning it again
				// - call the HandleFlagged() callback so the API user can be notified
				s.deleteSample(res.Sample)
				if s.HandleFlagged != nil {
					s.HandleFlagged(res)
				}
			}
		})
	}
	for {
		select {
		default:
			for sample := range s.samples {
				for _, scanner := range s.scanners {
					scanner.Add(sample)
				}
			}
		case <-s.stop:
			return
		}
	}

}

// Stop stops the scanning loop
func (s *Snitch) Stop() {
	s.stop <- true
}

// Add adds a hash to the monitored list
func (s *Snitch) Add(name string, hash string) {
	s.samples <- Sample{implantName: name, hash: hash}
}

func split(s []Sample, chunkSize int) [][]Sample {
	var divided [][]Sample
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		divided = append(divided, s[i:end])
	}
	return divided
}
