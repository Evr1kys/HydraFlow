BINARY_NAME=hydraflow
AGENT_BINARY=hydraflow-agent
SUB_BINARY=hydraflow-sub
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build build-agent build-sub build-all test lint vet fmt clean install

all: build-all

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/hydraflow/

build-agent:
	go build $(LDFLAGS) -o bin/$(AGENT_BINARY) ./cmd/hydraflow-agent/

build-sub:
	go build -o bin/$(SUB_BINARY) ./tools/sub-server.go

build-all: build build-agent build-sub

test:
	go test -v -race -count=1 ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin/

install: build-all
	cp bin/$(BINARY_NAME) /usr/local/bin/
	cp bin/$(AGENT_BINARY) /usr/local/bin/
	cp bin/$(SUB_BINARY) /usr/local/bin/
