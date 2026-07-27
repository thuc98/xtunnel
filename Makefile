BINARY := xtunnel
MAIN := ./cmd/xtunnel
DIST_DIR := dist

.PHONY: build build-linux-amd64 build-macos-arm64 build-all clean test

build:
	go build -o $(BINARY) $(MAIN)

build-linux-amd64:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(DIST_DIR)/$(BINARY)-linux-amd64 $(MAIN)

build-macos-arm64:
	mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(DIST_DIR)/$(BINARY)-darwin-arm64 $(MAIN)

build-all: build build-linux-amd64 build-macos-arm64

test:
	go test ./...

clean:
	rm -rf $(DIST_DIR) $(BINARY)
