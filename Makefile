BINARY   = k8scan
CMD      = ./cmd/k8scan
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: all build test lint tidy clean

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

run:
	go run $(CMD) scan

test:
	go test ./... -race -count=1

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/

docker:
	docker build -t k8scan:$(VERSION) .

release:
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 $(CMD)
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64 $(CMD)
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-amd64 $(CMD)
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64 $(CMD)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-windows-amd64.exe $(CMD)
