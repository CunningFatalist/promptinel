FROM golang:1.26.4-bookworm

ARG GOLANGCI_LINT_VERSION=v2.10.1
ARG GOVULNCHECK_VERSION=v1.1.4
ARG GORELEASER_VERSION=v2.10.2

WORKDIR /app

COPY . .

RUN go mod download

RUN GOBIN=$(go env GOPATH)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}
RUN GOBIN=$(go env GOPATH)/bin go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}
RUN GOBIN=$(go env GOPATH)/bin go install github.com/goreleaser/goreleaser/v2@${GORELEASER_VERSION}

ENTRYPOINT [ "tail", "-f", "/dev/null" ]
