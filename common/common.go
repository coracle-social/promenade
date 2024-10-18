package common

const (
	// event saved on the coordinator
	KindAccountRegistration = 16430

	// user sends a shard encrypted to the signer, gets an ACK back if it's accepted
	KindShard    = 26428
	KindShardACK = 26429

	// signing flow events
	KindConfiguration    = 26430 // coordinator to signer
	KindCommit           = 26431 // signer to coordinator
	KindEventToBeSigned  = 26432 // coordinator to signer
	KindPartialSignature = 26433 // signer to coordinator
)
