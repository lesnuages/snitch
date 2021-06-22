package snitch

import (
	"sync"
	"time"

	"github.com/VirusTotal/vt-go"
)

// VTScanner is an implentation of Scanner
// for the Virus Total threat intel platform
type VTScanner struct {
	APIKey    string
	threshold int
	Provider  string
	samples   []Sample
	mutex     sync.Mutex
	stop      chan bool
}

const VTMaxRequests = 4

// NewVTScanner returns a new instance of VTScanner
func NewVTScanner(apiKey string, maxRequests int, name string) *VTScanner {
	return &VTScanner{
		APIKey:    apiKey,
		threshold: maxRequests,
		Provider:  name,
		samples:   []Sample{},
		stop:      make(chan bool),
	}
}

// Add adds a sample to the list
func (s *VTScanner) Add(samp Sample) {
	s.mutex.Lock()
	s.samples = append(s.samples, samp)
	s.mutex.Unlock()
}

func (s *VTScanner) Name() string {
	return s.Provider
}

// Threshold returns the threshold value
// Virus Total free tier limit is 4 requests per minute, but 500 requests/day.
func (s *VTScanner) Threshold() time.Duration {
	return 2 * time.Minute
}

// MaxRequests represents the maximum number of requests that we can make in one minute
func (s *VTScanner) MaxRequests() int {
	return s.threshold
}

// Samples returns the sample list
func (s *VTScanner) Samples() []Sample {
	return s.samples
}

// Scan checks a hash against the Virus Total platform records
func (s *VTScanner) Scan(samp Sample) (*ScanResult, error) {
	client := vt.NewClient(s.APIKey)
	object, err := client.GetObject(vt.URL("files/%s", samp.hash))
	if err != nil {
		return nil, err
	}
	last, err := object.GetTime("last_submission_date")
	if err != nil {
		return nil, err
	}
	return &ScanResult{
		Sample:   samp,
		LastSeen: last,
		Provider: s.Provider,
	}, nil
}

func (s *VTScanner) Start(results chan *ScanResult) {
	for {
		select {
		default:
			s.mutex.Lock()
			batches := split(s.Samples(), s.MaxRequests())
			s.mutex.Unlock()
			for _, sampSlice := range batches {
				for _, samp := range sampSlice {
					r, err := s.Scan(samp)
					if err != nil {
						continue
					}
					results <- r
					s.Remove(samp)
				}
				time.Sleep(s.Threshold())
			}
		case <-s.stop:
			return
		}
	}
}

func (s *VTScanner) Stop() {
	s.stop <- true
}

// Remove deletes a sample from the scanning list
func (s *VTScanner) Remove(sample Sample) {
	var newSamples []Sample
	s.mutex.Lock()
	for _, samp := range s.samples {
		if samp.hash != sample.hash {
			newSamples = append(newSamples, samp)
		}
	}
	s.samples = newSamples
	s.mutex.Unlock()
}
