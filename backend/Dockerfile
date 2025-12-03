# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o netshoot-server ./cmd/server/

# Runtime stage - use the netshoot image as base to have all tools available
FROM nicolaka/netshoot:latest

WORKDIR /app

# Copy the Go binary
COPY --from=builder /app/netshoot-server /usr/local/bin/netshoot-server

# Expose port
EXPOSE 8080

# Set environment variables
ENV PORT=8080

# Run the server
CMD ["netshoot-server"]
