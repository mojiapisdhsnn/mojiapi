# Step 1: Build the Go binary
FROM golang:1.24-alpine AS builder

WORKDIR /app
# Copy the Go file into the container
COPY main.go .

# Initialize a module and build (CGO disabled for a static binary)
RUN go mod init nullapi \
    && go get github.com/gorilla/websocket \
    && go mod tidy \
    && CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/nullapi main.go

# Step 2: Prepare the final lightweight runtime image
FROM alpine:latest

# Install minimal certificates for outgoing connections if needed
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy the compiled Go binary from the builder stage
COPY --from=builder /app/nullapi /app/nullapi
RUN chmod +x /app/nullapi

# Create persistent data directory
RUN mkdir -p /data

# Expose only the web panel / WS port
EXPOSE 8000

CMD ["/app/nullapi"]

