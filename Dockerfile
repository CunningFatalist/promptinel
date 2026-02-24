FROM golang:1.25.7-bookworm

WORKDIR /app

COPY . .

RUN go mod download

RUN GOBIN=$(go env GOPATH)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1

ENTRYPOINT [ "tail", "-f", "/dev/null" ]
