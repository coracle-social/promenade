package main

import (
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
)

// start ip ratelimiter
var ipNegativeBuckets *xsync.MapOf[string, *atomic.Int32]

const maxTokens = 10

var _ = (func() struct{} {
	ipNegativeBuckets = xsync.NewMapOf[string, *atomic.Int32]()

	go func() {
		for {
			time.Sleep(time.Minute * 3)
			for key, bucket := range ipNegativeBuckets.Range {
				newv := bucket.Add(-2)
				if newv <= 0 {
					ipNegativeBuckets.Delete(key)
				}
			}
		}
	}()

	return struct{}{}
})()

func CheckIPLimited(ip string) bool {
	nb, _ := ipNegativeBuckets.LoadOrStore(ip, &atomic.Int32{})

	if nb.Load() < maxTokens {
		nb.Add(1)
		// rate limit not reached yet
		return false
	}

	// rate limit reached
	return true
}
