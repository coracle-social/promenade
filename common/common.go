package common

const (
	KindAccountRegistration = 24231

	KindConfiguration    = 24232 // coordinator to signer
	KindCommit           = 24233 // signer to coordinator
	KindEventToBeSigned  = 24234 // coordinator to signer
	KindPartialSignature = 24235 // signer to coordinator
)
