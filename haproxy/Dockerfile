FROM golang:1.27-alpine AS watchdog-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /watchdog ./cmd/panel

FROM haproxy:3.2-alpine
USER root
RUN apk add --no-cache bash
COPY --from=watchdog-build /watchdog /usr/local/bin/fluxgate-watchdog
COPY haproxy/watch.sh /usr/local/bin/watch-haproxy
RUN chmod +x /usr/local/bin/watch-haproxy
STOPSIGNAL SIGTERM
CMD ["/usr/local/bin/watch-haproxy"]
