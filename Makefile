VERSION := $(shell cat VERSION | tr -d '[:space:]')
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint vet clean

build:
	go build $(LDFLAGS) -o triton .

test:
	go test ./... -v -count=1

cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

lint: vet
	@which staticcheck > /dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

vet:
	go vet ./...

clean:
	rm -f triton triton.exe coverage.out
