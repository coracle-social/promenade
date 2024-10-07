dev:
    fd 'go|html|md|templ|base.css' | entr -r bash -c 'just build && godotenv ./promenade'

tailwind:
    tailwindcss -i ./base.css -o ./static/bundle.css

templ:
    templ generate

build:
    just templ
    just tailwind
    CC=musl-gcc go build -ldflags="-s -w -linkmode external -extldflags '-static' -X main.compileTimeTs=$(date '+%s') -s -w" -o ./promenade

deploy target: build
    ssh root@{{target}} 'systemctl stop promenade'
    scp promenade {{target}}:promenade/promenade
    ssh root@{{target}} 'systemctl start promenade'
