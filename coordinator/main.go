package main

import (
	"context"
	"embed"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/badger"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/khatru/policies"
	"fiatjaf.com/promenade/common"
	_ "github.com/a-h/templ"
	"github.com/kelseyhightower/envconfig"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
)

type Settings struct {
	Port    string `envconfig:"PORT" default:"6363"`
	Domain  string `envconfig:"DOMAIN" default:"localhost"`
	SchemeS string

	SecretKeyHex string `envconfig:"SECRET_KEY" required:"true"`
	SecretKey    nostr.SecretKey

	EventstorePath string `envconfig:"DB_PATH" default:"/tmp/promenade-eventstore"`
}

//go:embed static/*
var static embed.FS

//go:embed index.html
var index []byte

var (
	s     Settings
	db    eventstore.Store
	log   = zerolog.New(os.Stderr).Output(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	relay = khatru.NewRelay()
)

func main() {
	err := envconfig.Process("", &s)
	if err != nil {
		log.Fatal().Err(err).Msg("couldn't process envconfig")
		return
	}
	s.SecretKey, err = nostr.SecretKeyFromHex(s.SecretKeyHex)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid SECRET_KEY")
		return
	}

	if strings.Count(s.Domain, ".") < 3 && s.Domain != "localhost" {
		s.SchemeS = "s"
	}

	// nip46 dynamic signer setup
	nip46Signer.Init()

	// database
	db = &badger.BadgerBackend{Path: s.EventstorePath}
	if err := db.Init(); err != nil {
		log.Fatal().Err(err).Str("path", s.EventstorePath).Msg("failed to initialize events db")
		return
	}

	// relay setup
	relay.Info.Name = "promenade relay"
	relay.Info.Description = "a relay that acts as nip-46 provider for multisignature conglomerates"
	relay.Info.PubKey = s.SecretKey.Public()

	relay.UseEventstore(db, 400)

	relay.RejectConnection = policies.ConnectionRateLimiter(1, time.Minute*5, 100)
	relay.OnEvent = policies.SeqEvent(
		policies.EventIPRateLimiter(2, time.Minute*3, 10),
		filterOutEverythingExceptWhatWeWant)
	relay.OnRequest = policies.SeqRequest(
		policies.FilterIPRateLimiter(20, time.Minute, 100),
		handleRequest,
	)
	relay.OnEphemeralEvent = func(ctx context.Context, event nostr.Event) {
		if event.Kind == nostr.KindNostrConnect {
			handleNIP46Request(ctx, event)
		} else if slices.Contains([]nostr.Kind{common.KindCommit, common.KindPartialSignature}, event.Kind) {
			handleSignerStuff(ctx, event)
		}
	}
	relay.OnEventSaved = handleCreate
	mux := relay.Router()

	// routes
	mux.Handle("/static/", http.FileServer(http.FS(static)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		component := dashboard()
		component.Render(r.Context(), w)
	})

	// start
	log.Print("listening at http://0.0.0.0:" + s.Port)
	server := &http.Server{
		Addr:    "0.0.0.0:" + s.Port,
		Handler: cors.AllowAll().Handler(relay),
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("")
		}
	}()

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)
	<-sc
	server.Close()
}
