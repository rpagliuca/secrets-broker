GOVULNCHECK = golang.org/x/vuln/cmd/govulncheck@v1.10.0

.PHONY: build check fmt vet test vuln

build:
	CGO_ENABLED=0 go build -trimpath -o secrets-broker ./cmd/secrets-broker

check: fmt vet test vuln

fmt:
	gofmt -l . | (! grep .)

vet:
	go vet ./...

test:
	go test -count=1 -race ./...

vuln:
	go run $(GOVULNCHECK) ./...
