package main

import (
	"embed"
	"net/http"
	"os"
	"os/signal"
	"strings"

	_ "github.com/a-h/templ"
	"github.com/fiatjaf/eventstore"
	"github.com/fiatjaf/eventstore/badger"
	"github.com/fiatjaf/khatru"
	"github.com/kelseyhightower/envconfig"
	"github.com/nbd-wtf/go-nostr"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
)

type Settings struct {
	Port    string `envconfig:"PORT" default:"6363"`
	Domain  string `envconfig:"DOMAIN" default:"localhost"`
	SchemeS string

	PrivateKey string `envconfig:"SECRET_KEY" required:"true"`
	PublicKey  string

	EventstorePath string `envconfig:"DB_PATH" default:"/tmp/promenade-eventstore"`
}

//go:embed static/*
var static embed.FS

//go:embed index.html
var index []byte

var (
	s        Settings
	rw       nostr.RelayStore
	log      = zerolog.New(os.Stderr).Output(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	relay    = khatru.NewRelay()
	eventsdb eventstore.RelayWrapper
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

	db := &badger.BadgerBackend{Path: s.EventstorePath}
	if err := db.Init(); err != nil {
		log.Fatal().Err(err).Str("path", s.EventstorePath).Msg("failed to initialize events db")
		return
	}
	eventsdb = eventstore.RelayWrapper{Store: db}

	relay.Info.Name = "promenade relay"
	relay.Info.Description = "a relay that acts as nip-46 provider for multisignature conglomerates"
	relay.Info.PubKey = s.PublicKey

	relay.StoreEvent = append(relay.StoreEvent, db.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, db.QueryEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, db.DeleteEvent)

	relay.RejectEvent = append(relay.RejectEvent,
		filterOutEverythingExceptWhatWeWant,
	)
	relay.RejectFilter = append(relay.RejectFilter,
		veryPrivateFiltering,
		keepTrackOfWhoIsListening,
	)
	relay.OnEphemeralEvent = append(relay.OnEphemeralEvent,
		handleNIP46Request,
		handleSignerStuff,
	)
	relay.OnEventSaved = append(relay.OnEventSaved,
		handleCreate,
	)
	mux := relay.Router()

	// routes
	mux.Handle("/static/", http.FileServer(http.FS(static)))
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
		if err := server.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("")
		}
	}()

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)
	<-sc
	server.Close()
}
