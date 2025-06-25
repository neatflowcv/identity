# Build stage
FROM golang:1.24.3-alpine AS builder

# Set working directory
WORKDIR /app

# Install git (required for some Go modules)
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application using Makefile approach
RUN CGO_ENABLED=0 GOOS=linux go build -o identity ./cmd/identity

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS calls
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/identity .

# Change ownership to non-root user
RUN chown appuser:appgroup identity

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Command to run
CMD ["./identity"] 