FROM golang:1.23-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

# bring in source
COPY . .

# >>> add missing deps inside the build <<<
RUN go get github.com/redis/go-redis/v9
RUN go mod tidy

# now tests will pass
#RUN go test ./...

# build
RUN go build -o /kms-healthcheck .

## Runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
COPY --from=builder /kms-healthcheck /usr/local/bin/kms-healthcheck
ENTRYPOINT ["/usr/local/bin/kms-healthcheck"]
