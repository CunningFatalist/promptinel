FROM golang:1.25.7-bookworm

WORKDIR /app

COPY . .

RUN go mod download

RUN curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.10.1

ENTRYPOINT [ "tail", "-f", "/dev/null" ]