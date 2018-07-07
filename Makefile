.PHONY: all
all: build

.PHONY: build
build:
	@go build . -o bin/hdwallet

.PHONY: test
test:
	@go test -v .

.PHONY: deps/cp
deps/cp:
	@cp -r "${GOPATH}/src/github.com/ethereum/go-ethereum/crypto/secp256k1/libsecp256k1" "vendor/github.com/ethereum/go-ethereum/crypto/secp256k1/"

.PHONY: example
example:
	@go run -v example/example.go
