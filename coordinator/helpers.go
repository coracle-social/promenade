package main

import "math/rand/v2"

func shuffle[I any](slice []I) {
	for i := 1; i < len(slice); i++ {
		j := rand.IntN(i)
		slice[i], slice[j] = slice[j], slice[i]
	}
}
