package main

import "github.com/nbd-wtf/go-nostr"

func getKeyUserSession(event *nostr.Event) *KeyUserContext {
	p := event.Tags.GetFirst([]string{"p", ""})
	targetPubkey := (*p)[1]
	kuc, _ := userContexts.Load(targetPubkey)
	return kuc
}

func nameWasUsed(name string) bool {
	used := false
	userContexts.Range(func(_ string, value *KeyUserContext) bool {
		if value.name == name {
			used = true
			return false
		}
		return true
	})
	if used {
		return used
	}

	pendingCreation.Range(func(_ string, value *PendingKeyUserContext) bool {
		if value.name == name {
			used = true
			return false
		}
		return true
	})

	return used
}
