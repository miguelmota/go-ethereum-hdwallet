.PHONY: all
all: build

.PHONY: install
install:
	@go get -u github.com/miguelmota/go-ethereum-hdwallet

.PHONY: build
build:
	@go build -o ./bin/geth-hdwallet ./cmd/geth-hdwallet

.PHONY: format
format:
	@go fmt ./...
	@go vet .

.PHONY: test
test:
	@go test -v .

.PHONY: ensure
ensure:
	@dep ensure

.PHONY: deps
deps:
	@go mod tidy
	@go mod download
	@go mod vendor

.PHONY: deps-fix
deps-fix:
	@cp -r "${GOPATH}/src/github.com/ethereum/go-ethereum/crypto/secp256k1/libsecp256k1" "vendor/github.com/ethereum/go-ethereum/crypto/secp256k1/"

.PHONY: run-example-1
run-example-1:
	@go run example/derive.go

.PHONY: run-example-2
run-example-2:
	@go run example/sign.go

.PHONY: run-example-3
run-example-3:
	@go run example/seed.go

.PHONY: run-example-4
run-example-4:
	@go run example/keys.go

.PHONY: run-cli-example-1
run-cli-example-1:
	@./bin/geth-hdwallet -mnemonic "tag volcano eight thank tide danger coast health above argue embrace heavy" -path "m/44'/60'/0'/0/0"

.PHONY: release
release:
	@rm -rf dist
	@goreleaser
