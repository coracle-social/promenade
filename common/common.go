package common

const (
	KindAccountRegistration = 26430

	KindConfiguration    = 26432 // coordinator to signer
	KindCommit           = 26433 // signer to coordinator
	KindEventToBeSigned  = 26434 // coordinator to signer
	KindPartialSignature = 26435 // signer to coordinator
)
