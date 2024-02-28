package main

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strings"

	_ "github.com/a-h/templ"
	"github.com/fiatjaf/khatru"
	"github.com/kelseyhightower/envconfig"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip05"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
)

type Settings struct {
	Port    string `envconfig:"PORT" default:"6363"`
	Domain  string `envconfig:"DOMAIN" default:"localhost"`
	SchemeS string

	PrivateKey string `envconfig:"PRIVATE_KEY" required:"true"`
	PublicKey  string

	RegisteredSigners []string `envconfig:"REGISTERED_SIGNERS"`
}

//go:embed static/*
var static embed.FS

//go:embed index.html
var index []byte

var (
	s     Settings
	rw    nostr.RelayStore
	log   = zerolog.New(os.Stderr).Output(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	relay = khatru.NewRelay()
)

func main() {
	err := envconfig.Process("", &s)
	if err != nil {
		log.Fatal().Err(err).Msg("couldn't process envconfig")
		return
	}
	s.PublicKey, _ = nostr.GetPublicKey(s.PrivateKey)
	if strings.Count(s.Domain, ".") < 3 && s.Domain != "localhost" {
		s.SchemeS = "s"
	}

	relay.Info.Name = "promenade relay"
	relay.Info.Description = "a relay that acts as nip-46 provider for musig2-based keys"
	relay.Info.PubKey = s.PublicKey

	relay.RejectFilter = append(relay.RejectFilter,
		veryPrivateFiltering,
	)
	relay.RejectEvent = append(relay.RejectEvent,
		preliminaryElimination,
	)
	relay.OnEphemeralEvent = append(relay.OnEphemeralEvent,
		handleNIP46Request,
		handlePartialPublicKey,
		handlePartialSharedKey,
		handleNonce,
		handlePartialSig,
	)
	relay.OnConnect = append(relay.OnConnect,
		func(ctx context.Context) {
			khatru.RequestAuth(ctx)
		},
	)
	mux := relay.Router()

	// routes
	mux.Handle("/static/", http.FileServer(http.FS(static)))
	mux.HandleFunc("/.well-known/nostr.json", func(w http.ResponseWriter, r *http.Request) {
		resp := nip05.WellKnownResponse{
			Names: make(map[string]string),
			NIP46: make(map[string][]string),
		}
		userContexts.Range(func(pubkey string, kuc *KeyUserContext) bool {
			resp.Names[pubkey] = kuc.name
			resp.NIP46[pubkey] = []string{"http" + s.SchemeS + "://" + s.Domain}
			return true
		})
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "text/html")
		w.Write(index)
	})

	// start
	log.Print("listening at http://0.0.0.0:" + s.Port)
	server := &http.Server{
		Addr:    "0.0.0.0:" + s.Port,
		Handler: cors.AllowAll().Handler(relay),
	}
	go func() {
		server.ListenAndServe()
		if err := server.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("")
		}
	}()

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)
	<-sc
	server.Close()
}
