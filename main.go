package main

import (
	"context"
	"embed"
	"net/http"
	"os"
	"os/signal"
	"slices"

	_ "github.com/a-h/templ"
	"github.com/fiatjaf/khatru"
	"github.com/kelseyhightower/envconfig"
	"github.com/nbd-wtf/go-nostr"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
)

type Settings struct {
	Port string `envconfig:"PORT" default:"6363"`

	PrivateKey string `envconfig:"PRIVATE_KEY" required:"true"`
}

//go:embed static/*
var static embed.FS

//go:embed index.html
var index []byte

var (
	s   Settings
	rw  nostr.RelayStore
	log = zerolog.New(os.Stderr).Output(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
)

func main() {
	err := envconfig.Process("", &s)
	if err != nil {
		log.Fatal().Err(err).Msg("couldn't process envconfig")
		return
	}

	// initialize relay and relay store
	relay := khatru.NewRelay()
	relay.RejectEvent = append(relay.RejectEvent,
		func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
			if slices.Contains([]int{nostr.KindNostrConnect, 24233}, event.Kind) {
				return false, ""
			}
			return true, "unsupported event"
		})
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
