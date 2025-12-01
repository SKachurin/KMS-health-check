FROM golang:1.23-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go test ./...

RUN go build -o /kms-healthcheck .

## Runtime
FROM alpine:3.20
# TLS trust for HTTPS calls (AWS KMS)
RUN apk add --no-cache ca-certificates

# RUN adduser -D -H app && chown app:app /usr/local/bin
COPY --from=builder /kms-healthcheck /usr/local/bin/kms-healthcheck
# USER app

ENTRYPOINT ["/usr/local/bin/kms-healthcheck"]
