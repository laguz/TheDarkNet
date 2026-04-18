.PHONY: all deps build install run-mgmt run-hyperd run-agent xcode test clean

all: deps build

deps:
	go mod tidy
	cd hyperd && npm install

build:
	mkdir -p bin
	go build -o bin/thedarknet-mgmt ./cmd/mgmt
	go build -o bin/thedarknet-agent ./cmd/agent

install: build
	mkdir -p ~/Library/Application\ Support/TheDarkNet
	sudo cp bin/thedarknet-agent /usr/local/bin/thedarknet-agent

run-mgmt: build
	./bin/thedarknet-mgmt

run-hyperd:
	node ./hyperd/index.js

run-agent: build
	sudo ./bin/thedarknet-agent

test:
	go test ./pkg/proto/...

xcode:
	open apple/TheDarkNet.xcodeproj

clean:
	rm -rf bin
	rm -f thedarknet.db
	rm -rf ~/Library/Application\ Support/TheDarkNet/hyperd-data
	rm -f ~/Library/Application\ Support/TheDarkNet/hyperd.sock
