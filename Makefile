VERSION := $(shell cat VERSION | tr -d '[:space:]')
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint vet vuln sec clean

build:
	go build $(LDFLAGS) -o triton .

test:
	go test ./... -race -count=1

cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

lint: vet
	@which staticcheck > /dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
	staticcheck ./...

vet:
	go vet ./...

vuln:
	@which govulncheck > /dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

sec:
	@which gosec > /dev/null 2>&1 || go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec ./...

clean:
	rm -f triton triton.exe coverage.out
