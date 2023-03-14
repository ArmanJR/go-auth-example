# Start with a base Golang image
FROM golang:1.17-alpine3.14 AS builder

# Set the working directory
WORKDIR /app

# Copy the source code to the container
COPY . .

# Install bash
#RUN apk update && apk add bash

# Build the binary
RUN go mod download && \
    export GOPROXY=direct && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# Start with a minimal Alpine image
FROM alpine:3.14

# Copy the binary from the builder image
COPY --from=builder /app/app /app/app

# Expose the port that the app listens on
EXPOSE 8000

# Set the command to start the app
CMD ["/app/app"]
