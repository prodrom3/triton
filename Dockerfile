# Build stage
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /triton .

# Runtime stage: small image with CA certificates (TLS) and traceroute.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates traceroute
COPY --from=build /triton /usr/local/bin/triton
# GeoLite2 databases are not bundled; mount them and point --db at the path,
# e.g. docker run -v $PWD/GeoLite2-City.mmdb:/data/city.mmdb triton --db /data/city.mmdb 8.8.8.8
ENTRYPOINT ["triton"]
