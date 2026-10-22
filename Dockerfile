FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY vendor/ vendor/
COPY go.mod go.sum ./
COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -o /xtunnel ./cmd/xtunnel

FROM alpine:3.20

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /xtunnel /usr/local/bin/xtunnel

ENTRYPOINT ["xtunnel"]
