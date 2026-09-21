FROM golang:1.24-alpine AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -o /panel ./cmd/panel

FROM node:22-alpine AS web-build
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM haproxy:3.2-alpine
USER root
RUN apk add --no-cache ca-certificates
COPY --from=go-build /panel /usr/local/bin/panel
COPY --from=web-build /src/web/dist /opt/panel/web
ENV PANEL_DATA=/data PANEL_WEB=/opt/panel/web
VOLUME /data
CMD ["/usr/local/bin/panel"]
