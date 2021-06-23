package snitch

import (
	"sync"
	"time"

	"github.com/demisto/goxforce"
)

// XForceScanner is an implentation of Scanner
// for the IBM X-Force threat intel platform
type XForceScanner struct {
	APIKey      string
	APIPassword string
	threshold   int
	Provider    string
	samples     []Sample
	mutex       sync.Mutex
	stop        chan bool
}

const XForceMaxRequests = 6

// NewXForceScanner returns a new XForceScanner instance
func NewXForceScanner(apiKey string, password string, maxRequests int, name string) *XForceScanner {
	return &XForceScanner{
		APIKey:      apiKey,
		APIPassword: password,
		samples:     []Sample{},
		Provider:    name,
		threshold:   maxRequests,
		stop:        make(chan bool),
	}
}

func (s *XForceScanner) Name() string {
	return s.Provider
}

// Threshold returns the threshold value
// IBM X-Force API free tier limit is around 6 requests per hour (5000/month ~= 6.97/hour)
func (s *XForceScanner) Threshold() time.Duration {
	return 10 * time.Minute
}

// MaxRequests represents the maximum number of requests that we can make in one minute
func (s *XForceScanner) MaxRequests() int {
	return s.threshold
}

// Samples returns the sample list
func (s *XForceScanner) Samples() []Sample {
	return s.samples
}

// Add adds a sample to the list
func (s *XForceScanner) Add(samp Sample) {
	s.mutex.Lock()
	s.samples = append(s.samples, samp)
	s.mutex.Unlock()
}

// Mutex --
func (s *XForceScanner) Mutex() *sync.Mutex {
	return &s.mutex
}

// Scan runs a scans on a hash
func (s *XForceScanner) Scan(samp Sample) (*ScanResult, error) {
	res := new(ScanResult)
	client, err := goxforce.New(goxforce.SetCredentials(s.APIKey, s.APIPassword))
	if err != nil {
		return nil, err
	}
	details, err := client.MalwareDetails(samp.hash)
	if err != nil {
		return nil, err
	}
	res.Sample = samp
	res.LastSeen = details.Malware.Created
	res.Provider = s.Provider
	return res, nil
}

func (s *XForceScanner) Start(results chan *ScanResult) {
	for {
		select {
		default:
			s.mutex.Lock()
			samps := s.samples
			s.mutex.Unlock()
			for index, sample := range samps {
				if index%s.MaxRequests() == 0 && index > 0 {
					time.Sleep(s.Threshold())
				}
				r, err := s.Scan(sample)
				if err != nil {
					continue
				}
				results <- r
				s.Remove(sample)
			}
		case <-s.stop:
			return
		}
	}
}

func (s *XForceScanner) Stop() {
	s.stop <- true
}

// Remove deletes a sample from the scanning list
func (s *XForceScanner) Remove(sample Sample) {
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
