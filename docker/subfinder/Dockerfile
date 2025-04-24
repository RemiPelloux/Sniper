FROM golang:1.20-alpine as builder

# Install git
RUN apk add --no-cache git

# Download and build subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Create a lightweight runtime container
FROM alpine:3.18

# Copy the binary from the builder stage
COPY --from=builder /go/bin/subfinder /usr/local/bin/

# Create config directory
RUN mkdir -p /root/.config/subfinder

# Set entrypoint to run subfinder
ENTRYPOINT ["subfinder"]

# Default command shows help
CMD ["-h"] 