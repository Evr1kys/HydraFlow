FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" -o /bin/hydraflow ./cmd/hydraflow/
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" -o /bin/hydraflow-agent ./cmd/hydraflow-agent/
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /bin/hydraflow-sub ./tools/sub-server.go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl

COPY --from=builder /bin/hydraflow /usr/local/bin/hydraflow
COPY --from=builder /bin/hydraflow-agent /usr/local/bin/hydraflow-agent
COPY --from=builder /bin/hydraflow-sub /usr/local/bin/hydraflow-sub

RUN mkdir -p /etc/hydraflow /var/lib/hydraflow-agent /var/log/hydraflow

VOLUME /etc/hydraflow /var/lib/hydraflow-agent
EXPOSE 443 2053 8388 8443 10086

ENTRYPOINT ["hydraflow"]
CMD ["serve"]
