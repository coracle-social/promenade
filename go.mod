module git.fiatjaf.com/multi-nip46

go 1.21.6

require (
	github.com/a-h/templ v0.2.543
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.2
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/fiatjaf/khatru v0.3.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/mailru/easyjson v0.7.7
	github.com/mitchellh/go-homedir v1.1.0
	github.com/nbd-wtf/go-nostr v0.28.6
	github.com/puzpuzpuz/xsync/v3 v3.0.2
	github.com/rs/cors v1.10.1
	github.com/rs/zerolog v1.32.0
	github.com/urfave/cli/v3 v3.0.0-alpha7
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/fasthttp/websocket v1.5.7 // indirect
	github.com/fiatjaf/eventstore v0.3.8 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.3.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.17.3 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/savsgio/gotils v0.0.0-20230208104028-c358bd845dee // indirect
	github.com/sebest/xff v0.0.0-20210106013422-671bd2870b3a // indirect
	github.com/tidwall/gjson v1.17.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d // indirect
	golang.org/x/net v0.18.0 // indirect
	golang.org/x/sys v0.14.0 // indirect
)

replace github.com/nbd-wtf/go-nostr => ../go-nostr
