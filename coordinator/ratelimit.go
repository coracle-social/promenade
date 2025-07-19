package main

import (
	"sync/atomic"
	"time"

	"fiatjaf.com/nostr"
	"github.com/puzpuzpuz/xsync/v3"
)

// ip ratelimiting by failed RPC attempt
const ipFailedMaxBurst = 10
const ipFailedRefill = 2

var ipFailedAttemptNegativeBuckets = xsync.NewMapOf[string, *atomic.Int32]()

// per-client ratelimiting by successful signing attempts
const clientSuccessMaxBurst = 50
const clientSuccessRefill = 3

var clientSuccessfulAttemptNegativeBuckets = xsync.NewMapOf[nostr.PubKey, *atomic.Int32]()

var _ = (func() struct{} {
	go func() {
		for {
			time.Sleep(time.Minute * 3)

			// every 3 minutes an ip gets 2 new attempts
			for key, bucket := range ipFailedAttemptNegativeBuckets.Range {
				newv := bucket.Add(-ipFailedRefill)
				if newv <= 0 {
					// it should not go below zero
					ipFailedAttemptNegativeBuckets.Delete(key)
				}
			}

			// every 3 minutes a client gets 3 new attempts
			for key, bucket := range clientSuccessfulAttemptNegativeBuckets.Range {
				newv := bucket.Add(-clientSuccessRefill)
				if newv <= 0 {
					// it should not go below zero
					clientSuccessfulAttemptNegativeBuckets.Delete(key)
				}
			}
		}
	}()

	return struct{}{}
})()

func useIPFailedAttemptsRateLimit(ip string) {
	nb, _ := ipFailedAttemptNegativeBuckets.LoadOrStore(ip, &atomic.Int32{})
	nb.Add(1) // compute one attempt
}

// this returns true when a request has to be blocked
func justCheckIPFailedAttemptsRateLimit(ip string) bool {
	nb, exists := ipFailedAttemptNegativeBuckets.Load(ip)
	if !exists {
		// nothing registered for this, so it's a go
		return false
	}

	// failed attempts by ip are limited to 10 "burst" attempts
	return nb.Load() >= ipFailedMaxBurst
}

func useClientSuccessAttemptsRateLimit(client nostr.PubKey) {
	nb, _ := clientSuccessfulAttemptNegativeBuckets.LoadOrStore(client, &atomic.Int32{})
	nb.Add(1) // compute one attempt
}

// this returns true when a request has to be blocked
func justCheckClientSuccessAttemptsRateLimit(client nostr.PubKey) bool {
	nb, exists := clientSuccessfulAttemptNegativeBuckets.Load(client)
	if !exists {
		// nothing registered for this, so it's a go
		return false
	}

	// failed attempts by ip are limited to 10 "burst" attempts
	return nb.Load() >= clientSuccessMaxBurst
}
