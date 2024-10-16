package common

const (
	KindAccountRegistration = 16430

	KindConfiguration    = 26430 // coordinator to signer
	KindCommit           = 26431 // signer to coordinator
	KindEventToBeSigned  = 26432 // coordinator to signer
	KindPartialSignature = 26433 // signer to coordinator
)
