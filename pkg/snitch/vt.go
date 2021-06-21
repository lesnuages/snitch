package snitch

import (
	"sync"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

// VTScanner is an implentation of Scanner
// for the Virus Total threat intel platform
type VTScanner struct {
	APIKey    string
	threshold int
	Provider  string
	samples   []Sample
	mutex     sync.Mutex
}

// NewVTScanner returns a new instance of VTScanner
func NewVTScanner(apiKey string, threshold int, name string) *VTScanner {
	return &VTScanner{
		APIKey:    apiKey,
		threshold: threshold,
		Provider:  name,
		samples:   []Sample{},
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
// Virus Total free tier limit is 4 requests per minute
func (s *VTScanner) Threshold() time.Duration {
	return time.Duration(60/s.threshold) * time.Second
}

// MaxRequests represents the maximum number of requests that we can make in one minute
func (s *VTScanner) MaxRequests() int {
	return s.threshold
}

// Samples returns the sample list
func (s *VTScanner) Samples() []Sample {
	return s.samples
}

// Mutex --
func (s *VTScanner) Mutex() *sync.Mutex {
	return &s.mutex
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

// Remove deletes a sample from the scanning list
func (s *VTScanner) Remove(sample Sample) {
	var newSamples []Sample
	s.mutex.Lock()
	if len(s.samples)-1 != 0 {
		newSamples = make([]Sample, len(s.samples)-1)
		for i, samp := range s.samples {
			if samp.hash != sample.hash {
				newSamples[i] = s.samples[i]
			}
		}
	}
	s.samples = newSamples
	s.mutex.Unlock()
}
