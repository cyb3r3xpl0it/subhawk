FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o subhawk .

# Runtime image — chromium for screenshots
FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    chromium \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ttf-freefont

# Chromium env for chromedp
ENV CHROME_BIN=/usr/bin/chromium-browser \
    CHROME_PATH=/usr/lib/chromium/ \
    CHROMIUM_FLAGS="--disable-software-rasterizer --disable-dev-shm-usage"

COPY --from=builder /build/subhawk /usr/local/bin/subhawk
COPY --from=builder /build/wordlists /wordlists

WORKDIR /data

ENTRYPOINT ["subhawk"]
CMD ["--help"]
