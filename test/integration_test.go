package integration_test

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip04"
	"fiatjaf.com/nostr/nip46"
	"fiatjaf.com/promenade/common"
	"fiatjaf.com/promenade/frost"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// testProcess represents a running test process (coordinator or signer)
type testProcess struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr io.ReadCloser
	dbPath string
}

// cleanup kills the process and removes its database directory
func (p *testProcess) cleanup() error {
	if p.cmd.Process != nil {
		// Send SIGTERM first for graceful shutdown
		if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("failed to send SIGTERM: %w", err)
		}

		// Wait a bit for graceful shutdown
		done := make(chan error)
		go func() {
			done <- p.cmd.Wait()
		}()

		select {
		case <-time.After(5 * time.Second):
			// Force kill if it didn't shut down gracefully
			if err := p.cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to kill process: %w", err)
			}
		case err := <-done:
			if err != nil {
				return fmt.Errorf("process exited with error: %w", err)
			}
		}
	}

	// Close stdout/stderr readers
	if p.stdout != nil {
		p.stdout.Close()
	}
	if p.stderr != nil {
		p.stderr.Close()
	}

	// Remove database directory
	if p.dbPath != "" {
		if err := os.RemoveAll(p.dbPath); err != nil {
			return fmt.Errorf("failed to remove db directory: %w", err)
		}
	}

	return nil
}

// startProcess starts a process and returns a testProcess
func startProcess(t *testing.T, name string, args []string, env []string) (*testProcess, error) {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	proc := &testProcess{
		cmd:    cmd,
		stdout: stdout,
		stderr: stderr,
	}

	// Start process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	// Log output
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			t.Logf("[%s stdout] %s", filepath.Base(name), scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			t.Logf("[%s stderr] %s", filepath.Base(name), scanner.Text())
		}
	}()

	return proc, nil
}

// waitForHTTP waits for an HTTP endpoint to become available
func waitForHTTP(t *testing.T, url string, timeout time.Duration) error {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

// Helper function to start a test coordinator
func startTestCoordinator(t *testing.T) (string, nostr.PubKey, func()) {
	t.Helper()

	// Get a random available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	port := fmt.Sprintf("%d", addr.Port)
	coordinatorURL := fmt.Sprintf("ws://127.0.0.1:%s", port)

	// Create temp directory for coordinator DB
	dbPath := t.TempDir()

	// Generate coordinator secret key
	coordinatorSec := nostr.Generate()
	coordinatorPub := nostr.GetPublicKey(coordinatorSec)

	// Start coordinator process
	proc, err := startProcess(t, "go", []string{
		"run", "../coordinator/main.go",
	}, []string{
		fmt.Sprintf("PORT=%s", port),
		"DOMAIN=127.0.0.1",
		fmt.Sprintf("SECRET_KEY=%s", string(coordinatorSec)), // Explicit string conversion
		fmt.Sprintf("DB_PATH=%s", dbPath),
	})
	require.NoError(t, err)
	proc.dbPath = dbPath

	// Wait for coordinator to be ready
	err = waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%s", port), 10*time.Second)
	require.NoError(t, err)

	cleanup := func() {
		if err := proc.cleanup(); err != nil {
			t.Logf("Failed to cleanup coordinator: %v", err)
		}
	}

	return coordinatorURL, coordinatorPub, cleanup
}

// Helper function to start a test signer
func startTestSigner(t *testing.T, coordinatorURL string, signerSec nostr.SecretKey) (nostr.PubKey, func()) {
	t.Helper()

	// Create temp directory for signer DB
	dbPath := t.TempDir()

	// Convert signerSec to string for command-line arg
	secStr := string(signerSec)

	// Start signer process
	proc, err := startProcess(t, "go", []string{
		"run", "../signer/main.go",
		"--sec", secStr,
		"--db", dbPath,
		"--accept-relay", coordinatorURL,
		"--min-pow", "0",
	}, nil)
	require.NoError(t, err)
	proc.dbPath = dbPath

	cleanup := func() {
		if err := proc.cleanup(); err != nil {
			t.Logf("Failed to cleanup signer: %v", err)
		}
	}

	// The signer's public key
	signerPub := nostr.GetPublicKey(signerSec)

	return signerPub, cleanup
}

// Helper function to create an account with the coordinator
func createAccountWithCoordinator(
	t *testing.T,
	userSec nostr.SecretKey,
	coordinatorURL string,
	coordinatorPub nostr.PubKey,
	signerPubkeys []nostr.PubKey,
	threshold int,
) (string, nostr.PubKey) {
	t.Helper()

	// Convert nostr.SecretKey to string for hex decoding
	userSecStr := string(userSec)
	userSkBytes, err := hex.DecodeString(userSecStr)
	require.NoError(t, err)
	btcecUserSk := new(btcec.ModNScalar)
	overflow := btcecUserSk.SetByteSlice(userSkBytes)
	require.False(t, overflow, "user secret key overflow")

	// Generate key shards using FROST
	shards, actualAggPubkey, _ := frost.TrustedKeyDeal(btcecUserSk, threshold, len(signerPubkeys))

	// Convert actualAggPubkey (btcec.JacobianPoint) to nostr.PubKey
	aggPubkeyHex := hex.EncodeToString(actualAggPubkey.X.Bytes()[:])
	nostrAggPubkey := nostr.PubKey(aggPubkeyHex)

	// Convert potentially negated btcecUserSk back to hex for signing Nostr events
	skBytesArray := btcecUserSk.Bytes()
	finalAggSecHex := hex.EncodeToString(skBytesArray[:])
	finalAggSec := nostr.SecretKey(finalAggSecHex)

	// Generate handler key pair for NIP-46
	handlerSec := nostr.Generate()
	handlerPub := nostr.GetPublicKey(handlerSec)

	// Create AccountRegistration
	ar := common.AccountRegistration{
		PubKey:        nostrAggPubkey,
		HandlerSecret: handlerSec,
		Threshold:     threshold,
		Signers:       make([]common.Signer, len(signerPubkeys)),
	}

	// Add signers to AccountRegistration
	for i, signerPub := range signerPubkeys {
		ar.Signers[i] = common.Signer{
			PeerPubKey: signerPub,
			Shard:      shards[i].PublicKeyShard,
		}
	}

	// Create and sign AccountRegistration event
	regEvt := ar.Encode()
	regEvt.Sign(finalAggSec)

	// Create a pool for publishing events
	pool := nostr.NewPool(nostr.PoolOptions{})

	// Publish AccountRegistration event
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relay, err := pool.EnsureRelay(coordinatorURL)
	require.NoError(t, err)
	status := relay.Publish(ctx, regEvt)
	require.True(t, int(status) == 1 || int(status) == 3, "registration event not sent/stored") // 1=Sent, 3=Stored

	// Send encrypted shards to signers
	for i, signerPub := range signerPubkeys {
		// Encrypt shard
		plaintextShardHex := shards[i].Hex()
		sharedSecret, err := nip04.ComputeSharedSecret(string(signerPub), string(finalAggSec))
		require.NoError(t, err)
		encryptedContent, err := nip04.Encrypt(plaintextShardHex, sharedSecret)
		require.NoError(t, err)

		// Create and sign shard event
		shardEvt := nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      common.KindShard,
			Content:   encryptedContent,
			Tags: nostr.Tags{
				{"p", signerPub.Hex()},
				{"coordinator", coordinatorURL},
			},
			PubKey: nostrAggPubkey.Hex(),
		}
		shardEvt.Sign(finalAggSec)

		// Publish shard event
		status := relay.Publish(ctx, shardEvt)
		require.True(t, int(status) == 1 || int(status) == 3, "shard event not sent/stored") // 1=Sent, 3=Stored
	}

	// Give some time for setup to complete
	time.Sleep(2 * time.Second)

	// Construct bunker URL
	relayNoScheme := strings.TrimPrefix(strings.TrimPrefix(coordinatorURL, "ws://"), "wss://")
	bunkerURL := fmt.Sprintf("bunker://%s?relay=%s", handlerPub.Hex(), relayNoScheme)

	return bunkerURL, nostrAggPubkey
}

// Helper function to sign an event using NIP-46
func signEventWithNIP46(t *testing.T, bunkerURL string, eventToSign *nostr.Event) error {
	t.Helper()

	// Parse bunker URL to get handler pubkey and relay
	parts := strings.SplitN(strings.TrimPrefix(bunkerURL, "bunker://"), "?", 2)
	require.Len(t, parts, 2, "invalid bunker URL format")
	handlerPubHex := parts[0]
	handlerPub, err := nostr.PubKeyFromHex(handlerPubHex)
	require.NoError(t, err)

	params := strings.Split(parts[1], "&")
	var relayURL string
	for _, param := range params {
		if strings.HasPrefix(param, "relay=") {
			relayURL = "ws://" + strings.TrimPrefix(param, "relay=")
			break
		}
	}
	require.NotEmpty(t, relayURL, "relay not found in bunker URL")

	// Create NIP-46 client
	clientSec := nostr.Generate()
	clientSecStr := string(clientSec)

	// Create a new ResponseRouter (nip46.NewSigner is undefined)
	nip46Signer := &nip46.ResponseRouter{} // Placeholder, actual initialization TBD
	_ = nip46Signer                        // Silence unused var warning

	// Connect to handler
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// TODO: Implement NIP-46 signing once library issues are resolved
	_ = clientSecStr // Silence unused var warning
	_ = handlerPub   // Silence unused var warning
	_ = relayURL     // Silence unused var warning

	return fmt.Errorf("NIP-46 signing not implemented due to library issues")
}

func TestPromenadeFullIntegration(t *testing.T) {
	// Set reasonable timeout for the entire test
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_ = ctx // TODO: Use ctx in helper functions

	// Start coordinator
	coordinatorURL, coordinatorPub, cleanupCoordinator := startTestCoordinator(t)
	defer cleanupCoordinator()

	// Start 4 signers
	signerSecrets := make([]nostr.SecretKey, 4)
	signerPubkeys := make([]nostr.PubKey, 4)
	cleanupSigners := make([]func(), 4)

	for i := range signerSecrets {
		signerSecrets[i] = nostr.Generate()
		var cleanup func()
		signerPubkeys[i], cleanup = startTestSigner(t, coordinatorURL, signerSecrets[i])
		cleanupSigners[i] = cleanup
		defer cleanupSigners[i]()
	}

	// Create user account
	userSec := nostr.Generate()
	threshold := 3 // 3-of-4 signing threshold

	bunkerURL, aggPubkey := createAccountWithCoordinator(t, userSec, coordinatorURL, coordinatorPub, signerPubkeys, threshold)
	require.NotEmpty(t, bunkerURL)
	require.NotEmpty(t, aggPubkey)

	// Create and sign a test event
	eventToSign := &nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "Hello from Promenade integration test!",
		Tags:      nostr.Tags{},
	}

	err := signEventWithNIP46(t, bunkerURL, eventToSign)
	require.NoError(t, err)
	require.NotEmpty(t, eventToSign.Sig)
	require.Equal(t, aggPubkey, eventToSign.PubKey)

	// Verify the signature
	require.True(t, eventToSign.Verify())
}
