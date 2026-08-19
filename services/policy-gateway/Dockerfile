# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS ui-builder

WORKDIR /src/services/approval-ui
COPY services/approval-ui/package.json services/approval-ui/package-lock.json ./
RUN npm ci
COPY services/approval-ui/ ./
RUN npm run build

FROM golang:1.22-alpine AS builder

ARG TARGETARCH
WORKDIR /src/services/policy-gateway
RUN apk add --no-cache ca-certificates git

COPY services/policy-gateway/go.mod services/policy-gateway/go.sum ./
RUN go mod download

COPY services/policy-gateway/ ./
COPY --from=ui-builder /src/services/policy-gateway/internal/ui/dist ./internal/ui/dist

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
