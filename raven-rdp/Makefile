MODULE   := github.com/salarrbl/raven-rdp
BINARY   := raven-rdp
VERSION  := 0.1.0
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE     := $(shell date -u +%Y-%m-%d 2>/dev/null || echo unknown)
LDFLAGS  := -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Commit=$(COMMIT) \
  -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: all build test race lint clean

all: build

## build: compile the raven-rdp binary into dist/
build:
	@mkdir -p dist
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/raven-rdp

## test: run the full test suite
test:
	go test ./...

## race: run the full test suite with the race detector
race:
	go test -race ./...

## lint: gofmt check and go vet
lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt: files need formatting (run: gofmt -w .)"; exit 1; }
	go vet ./...

## clean: remove build artifacts
clean:
	rm -rf dist
