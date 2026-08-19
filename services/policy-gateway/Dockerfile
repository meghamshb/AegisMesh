# syntax=docker/dockerfile:1.7

FROM golang:1.22-alpine AS builder

ARG TARGETARCH
WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget \
    && addgroup -S gateway \
    && adduser -S gateway -G gateway

WORKDIR /app
COPY --from=builder /out/gateway /app/gateway

USER gateway
EXPOSE 8080
ENTRYPOINT ["/app/gateway"]
